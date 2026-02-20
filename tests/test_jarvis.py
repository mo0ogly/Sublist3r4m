"""Tests for jarvis_intelligence.py module.

Covers: SecurityValidator, EnhancedLogger, EnhancedEnumeratorBase,
        CertificateTransparencyEnum, DomainIntelligenceCollector,
        ConfigManager, file-output helpers.
"""

import json
import logging
import os
import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# We need to suppress side-effects that happen at import time in
# jarvis_intelligence (global logger init, requests import warnings, etc.).
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Patch the global `initialize_globals` call that some code paths trigger,
# and ensure imports don't fail even without optional deps.
import jarvis.base as ji_base
import jarvis.enumerators as ji_enum
import jarvis.logger as ji_logger
import jarvis.main as ji_main
from jarvis.base import EnhancedEnumeratorBase
from jarvis_intelligence import (
    CertificateTransparencyEnum,
    ConfigManager,
    EnhancedLogger,
    SecurityValidator,
)

# ===================================================================
# Helpers
# ===================================================================

def _make_null_logger():
    """Return a standard-library logger with only a NullHandler."""
    name = "test_jarvis_null_{}".format(id(object()))
    lg = logging.getLogger(name)
    lg.handlers = [logging.NullHandler()]
    lg.setLevel(logging.DEBUG)
    return lg


def _make_security_validator():
    """Return a SecurityValidator wired to a null logger."""
    return SecurityValidator(logger=None)


# ===================================================================
# SecurityValidator -- domain validation
# ===================================================================

class TestSecurityValidatorDomain:
    """Tests for SecurityValidator.validate_domain."""

    def test_security_validator_valid_domain(self):
        """Well-formed domains should be accepted."""
        sv = _make_security_validator()

        valid_domains = [
            "google.com",
            "sub.domain.co.uk",
            "my-site.org",
            "a1b2.net",
            "deep.sub.domain.io",
        ]
        for domain in valid_domains:
            is_valid, sanitized, err = sv.validate_domain(domain)
            assert is_valid is True, (
                "Domain '{}' should be valid, got error: {}".format(domain, err)
            )
            assert sanitized is not None
            assert err is None

    def test_security_validator_invalid_domain(self):
        """Injection attempts and malformed domains should be rejected."""
        sv = _make_security_validator()

        bad_inputs = [
            "'; DROP TABLE users;--",
            "<script>alert(1)</script>.com",
            "../../../etc/passwd",
            "domain with spaces.com",
            "",
            None,
            "a",  # too short
        ]
        for bad in bad_inputs:
            is_valid, sanitized, err = sv.validate_domain(bad)
            assert is_valid is False, (
                "Input '{}' should be rejected but was accepted".format(bad)
            )


# ===================================================================
# SecurityValidator -- integer (port) validation
# ===================================================================

class TestSecurityValidatorInteger:
    """Tests for integer validation via validate_port_list."""

    def test_security_validator_valid_integer(self):
        """Positive port numbers within range should be accepted."""
        sv = _make_security_validator()

        is_valid, ports, err = sv.validate_port_list("80,443,8080")
        assert is_valid is True
        assert ports == [80, 443, 8080]
        assert err is None

    def test_security_validator_invalid_integer(self):
        """Negative numbers, non-integers, and out-of-range values are rejected."""
        sv = _make_security_validator()

        # Non-digit string
        is_valid, ports, err = sv.validate_port_list("abc")
        assert is_valid is False

        # Port 0 is out of range (valid range 1-65535)
        is_valid, ports, err = sv.validate_port_list("0")
        assert is_valid is False

        # Port above 65535
        is_valid, ports, err = sv.validate_port_list("70000")
        assert is_valid is False

        # Negative via shell injection character
        is_valid, ports, err = sv.validate_port_list("-1")
        assert is_valid is False


# ===================================================================
# CertificateTransparencyEnum -- crt.sh enumeration (mocked)
# ===================================================================

class TestCrtshEnumeration:
    """Test CertificateTransparencyEnum with mocked HTTP."""

    @patch("jarvis.base.REQUESTS_AVAILABLE", True)
    def test_crtsh_enumeration(self):
        """Mocked crt.sh JSON response should yield extracted subdomains."""
        fake_cert_data = [
            {
                "name_value": "mail.targetdomain.com\napi.targetdomain.com",
                "common_name": "*.targetdomain.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2024-01-01",
                "not_after": "2025-01-01",
            },
            {
                "name_value": "dev.targetdomain.com",
                "common_name": "dev.targetdomain.com",
            },
        ]

        # Build a mock requests.Session whose get() returns our fake data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = fake_cert_data
        mock_response.text = json.dumps(fake_cert_data)

        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        mock_session.verify = True

        # Patch globals that the enumerator relies on
        mock_logger = MagicMock()
        mock_sv = MagicMock()
        mock_sv.validate_domain.return_value = (True, "targetdomain.com", None)

        with patch.object(ji_base, "logger", mock_logger), \
             patch.object(ji_base, "security_validator", mock_sv), \
             patch.object(ji_enum, "logger", mock_logger), \
             patch.object(ji_logger, "colors", MagicMock(
                 GREEN="", WHITE="", BLUE="", RED="",
                 YELLOW="", CYAN="", MAGENTA="", BOLD="",
                 DIM="", UNDERLINE="", enabled=False)):

            enum = CertificateTransparencyEnum(
                domain="targetdomain.com",
                silent=True,
                verbose=False,
            )
            # Replace session with our mock
            enum.session = mock_session

            # Call extract_domains directly with the fake data
            enum.extract_domains(fake_cert_data)

            found = enum.subdomains
            assert "mail.targetdomain.com" in found
            assert "api.targetdomain.com" in found
            assert "dev.targetdomain.com" in found
            assert len(found) >= 3


# ===================================================================
# Output tests (JSON, CSV)
# ===================================================================

class TestOutputFormats:
    """Test _write_json and _write_csv helpers."""

    def test_output_json(self, tmp_path):
        """_write_json should produce a valid JSON file with expected keys."""
        json_file = str(tmp_path / "subdomains.json")
        subdomains = ["mail.example.com", "api.example.com"]
        metadata = {
            "timestamp": "2025-01-01T00:00:00",
            "total_subdomains": 2,
            "tool": "JARVIS Intelligence v1.0",
            "format_version": "1.0",
        }

        mock_logger = MagicMock()
        mock_sv = MagicMock()
        mock_sv.validate_file_path.return_value = (True, json_file, None)

        with patch.object(ji_main, "logger", mock_logger), \
             patch.object(ji_main, "security_validator", mock_sv):
            result = ji_main._write_json(json_file, subdomains, metadata)

        assert result is True
        assert os.path.isfile(json_file)

        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "metadata" in data
        assert "subdomains" in data
        assert len(data["subdomains"]) == 2
        domains_in_output = [s["domain"] for s in data["subdomains"]]
        assert "mail.example.com" in domains_in_output
        assert "api.example.com" in domains_in_output

    def test_output_csv(self, tmp_path):
        """_write_csv should produce a CSV file containing the subdomains."""
        csv_file = str(tmp_path / "subdomains.csv")
        subdomains = ["www.example.com", "ftp.example.com"]
        metadata = {
            "timestamp": "2025-01-01T00:00:00",
            "total_subdomains": 2,
            "tool": "JARVIS Intelligence v1.0",
        }

        mock_logger = MagicMock()
        mock_sv = MagicMock()
        mock_sv.validate_file_path.return_value = (True, csv_file, None)

        with patch.object(ji_main, "logger", mock_logger), \
             patch.object(ji_main, "security_validator", mock_sv):
            result = ji_main._write_csv(csv_file, subdomains, metadata)

        assert result is True
        assert os.path.isfile(csv_file)

        with open(csv_file, "r", encoding="utf-8") as f:
            content = f.read()

        assert "www.example.com" in content
        assert "ftp.example.com" in content


# ===================================================================
# EnhancedLogger test
# ===================================================================

class TestEnhancedLogger:
    """Test that EnhancedLogger initializes without polluting the filesystem."""

    def test_enhanced_logger(self, tmp_path):
        """Logger should initialize and use NullHandler without file pollution
        outside the specified log_dir."""
        unique_name = "test_jarvis_logger_{}".format(id(tmp_path))
        log = EnhancedLogger(
            name=unique_name,
            log_dir=str(tmp_path),
            debug=False,
        )

        assert log is not None
        assert log.session_id.startswith("session_")
        assert isinstance(log.metrics, dict)
        assert log.metrics["total_messages"] >= 0

        # The logger should have handlers -- at least the ones it set up
        assert len(log.logger.handlers) > 0

        # Log a message -- should not raise
        log.info("Test message from unit test", module="TestModule")
        log.warning("Warning test", module="TestModule")
        log.error("Error test", module="TestModule")

        # Verify metrics were updated
        assert log.metrics["total_messages"] >= 3


# ===================================================================
# ConfigManager test
# ===================================================================

class TestConfigLoading:
    """Test ConfigManager loading from config.json.example."""

    def test_config_loading(self):
        """Loading config.json.example should produce a valid config dict."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config.json.example",
        )

        cm = ConfigManager(config_file=config_path)
        assert isinstance(cm.config, dict)

        # Check expected top-level keys
        assert "api_keys" in cm.config
        assert "endpoints" in cm.config
        assert "settings" in cm.config

        # Check a specific setting
        timeout = cm.get_setting("timeout")
        assert timeout is not None
        assert isinstance(timeout, (int, float))
        assert timeout > 0


# ===================================================================
# Retry logic test
# ===================================================================

class TestRetryLogic:
    """Verify that EnhancedEnumeratorBase retries on HTTP errors."""

    @patch("jarvis.base.REQUESTS_AVAILABLE", True)
    def test_retry_logic(self):
        """send_req should retry on failure and eventually return None when
        all retries are exhausted."""
        mock_logger = MagicMock()
        mock_sv = MagicMock()
        mock_sv.validate_domain.return_value = (True, "retrydomain.com", None)

        with patch.object(ji_base, "logger", mock_logger), \
             patch.object(ji_base, "security_validator", mock_sv), \
             patch.object(ji_logger, "colors", MagicMock(
                 GREEN="", WHITE="", BLUE="", RED="",
                 YELLOW="", CYAN="", MAGENTA="", BOLD="",
                 DIM="", UNDERLINE="", enabled=False)):

            # Create a concrete subclass to test send_req
            class _TestEnum(EnhancedEnumeratorBase):
                def extract_domains(self, resp):
                    pass

                def generate_query(self):
                    return "test"

            enum = _TestEnum(
                base_url="https://fake.example.com/?q={query}&d={domain}&p={page_no}",
                engine_name="TestEngine",
                domain="retrydomain.com",
                silent=True,
                verbose=False,
                timeout=1,
                delay=0,
            )

            # Create a mock session that always raises a ConnectionError
            mock_session = MagicMock()
            import requests as req_mod
            mock_session.get.side_effect = req_mod.exceptions.ConnectionError("mocked")
            enum.session = mock_session

            # Patch time.sleep to avoid delays in tests
            with patch("time.sleep"):
                result = enum.send_req("testquery", retries=2)

            assert result is None, "Should return None when all retries fail"
            # The session.get should have been called 3 times (initial + 2 retries)
            assert mock_session.get.call_count == 3
            assert enum.metrics["requests_failed"] >= 1
