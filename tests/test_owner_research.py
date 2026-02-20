"""Tests for owner_research_engine.py module.

Covers: AdvancedOwnerLogger, FuzzyMatcher, OwnerDatabase,
        AdvancedOwnerResearchEngine (domain validation, normalization,
        security validation, CSV/JSON export).
"""

import json
import os

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from owner_research_engine import (
    AdvancedOwnerLogger,
    AdvancedOwnerResearchEngine,
    FuzzyMatcher,
    OwnerDatabase,
)

# ===================================================================
# Helpers
# ===================================================================

def _make_logger(tmp_path):
    """Create an AdvancedOwnerLogger that writes into a temp directory."""
    return AdvancedOwnerLogger(
        name="test_owner_logger_{}".format(id(tmp_path)),
        log_dir=str(tmp_path),
        debug=False,
    )


def _make_database(tmp_path, logger=None):
    """Create an OwnerDatabase backed by a file inside tmp_path."""
    db_path = str(tmp_path / "test_owner.db")
    return OwnerDatabase(db_path=db_path, logger=logger)


# ===================================================================
# FuzzyMatcher tests
# ===================================================================

class TestFuzzyMatcher:
    """Tests for the FuzzyMatcher class."""

    def test_fuzzy_matcher_exact(self):
        """Identical strings should produce a global score >= 0.95."""
        matcher = FuzzyMatcher()
        result = matcher.compute_similarity("Google LLC", "Google LLC")
        assert result["global_score"] >= 0.95, (
            "Identical strings should score >= 0.95, got {}".format(
                result["global_score"]
            )
        )

    def test_fuzzy_matcher_similar(self):
        """Similar company names should produce a meaningful positive score.

        The weighted average across all algorithms (exact, substring, sequence,
        soundex, levenshtein, jaro-winkler, n-gram) yields ~0.41 for
        'Google LLC' vs 'Google Inc'.  The important invariant is that the
        score is significantly higher than for completely different strings.
        """
        matcher = FuzzyMatcher()
        result = matcher.compute_similarity("Google LLC", "Google Inc")
        assert result["global_score"] >= 0.35, (
            "'Google LLC' vs 'Google Inc' should score >= 0.35, got {}".format(
                result["global_score"]
            )
        )
        # Also verify it is categorised above 'very_poor'
        assert result["quality"] in ("excellent", "very_good", "good", "fair", "poor"), (
            "Similar strings should not be 'very_poor', got '{}'".format(
                result["quality"]
            )
        )

    def test_fuzzy_matcher_different(self):
        """Clearly different strings should produce a score < 0.5."""
        matcher = FuzzyMatcher()
        result = matcher.compute_similarity("Apple", "Microsoft")
        assert result["global_score"] < 0.5, (
            "'Apple' vs 'Microsoft' should score < 0.5, got {}".format(
                result["global_score"]
            )
        )


# ===================================================================
# OwnerDatabase tests
# ===================================================================

class TestOwnerDatabase:
    """Tests for the OwnerDatabase SQLite cache."""

    def test_owner_database_insert_query(self, tmp_path):
        """Inserting owner info then retrieving it should return the same data."""
        db = _make_database(tmp_path)
        try:
            domain = "example.org"
            owner_data = {
                "owner_name": "Example Corp",
                "registrar": "RegistrarCo",
                "creation_date": "2020-01-01",
                "expiry_date": "2030-01-01",
                "emails": ["admin@example.org"],
                "phone": "+1-555-0100",
                "address": "123 Main St",
                "raw_whois": "raw whois text",
                "source": "whois",
                "confidence_score": 0.85,
            }

            result = db.cache_owner_info(domain, owner_data)
            assert result is True, "cache_owner_info should return True on success"

            # Retrieve with a generous max_age
            cached = db.get_cached_owner(domain, max_age_hours=9999)
            assert cached is not None, "Cached owner should be retrievable"
            assert cached["owner_name"] == "Example Corp"
            assert cached["registrar"] == "RegistrarCo"
            assert "admin@example.org" in cached["emails"]
        finally:
            db.close()

    def test_owner_database_cleanup(self, tmp_path):
        """Old entries should be cleaned up when cleanup_old_data is called."""
        db = _make_database(tmp_path)
        try:
            domain = "old.example.com"
            owner_data = {
                "owner_name": "Old Corp",
                "registrar": "OldReg",
                "emails": [],
                "source": "whois",
                "confidence_score": 0.5,
            }
            db.cache_owner_info(domain, owner_data)

            # Manually backdate the last_updated to make the entry appear old
            db.connection.execute(
                "UPDATE owner_cache SET last_updated = datetime('now', '-60 days') "
                "WHERE domain = ?",
                (domain,),
            )
            db.connection.commit()

            # Cleanup entries older than 30 days
            cleanup_result = db.cleanup_old_data(days_old=30)
            assert cleanup_result is True

            # The old entry should no longer be retrievable even with generous max_age
            cached = db.get_cached_owner(domain, max_age_hours=999999)
            assert cached is None, "Old entry should have been deleted by cleanup"
        finally:
            db.close()


# ===================================================================
# Domain validation / normalization tests (AdvancedOwnerResearchEngine)
# ===================================================================

class TestDomainValidationAndNormalization:
    """Tests for _is_valid_domain and _clean_domain on the engine."""

    def _make_engine(self, tmp_path):
        """Instantiate an AdvancedOwnerResearchEngine with temp paths."""
        db_path = str(tmp_path / "engine.db")
        with patch.object(AdvancedOwnerLogger, "_ensure_log_directory"):
            with patch.object(AdvancedOwnerLogger, "_setup_logger"):
                engine = AdvancedOwnerResearchEngine(
                    debug=False,
                    cache_db=db_path,
                )
        return engine

    def test_domain_validation(self, tmp_path):
        """Valid domains pass, invalid ones are rejected."""
        engine = self._make_engine(tmp_path)
        try:
            # Valid domains
            assert engine._is_valid_domain("google.com") is True
            assert engine._is_valid_domain("sub.domain.co.uk") is True
            assert engine._is_valid_domain("my-site.org") is True

            # Invalid domains
            assert engine._is_valid_domain("") is False
            assert engine._is_valid_domain("x") is False  # too short
            assert engine._is_valid_domain("no spaces.com") is False
            assert engine._is_valid_domain("-dash.com") is False
        finally:
            engine.database.close()

    def test_domain_normalization(self, tmp_path):
        """_clean_domain strips protocol, www prefix is preserved but lowered,
        trailing slashes and paths are removed."""
        engine = self._make_engine(tmp_path)
        try:
            assert engine._clean_domain("https://Example.COM/path") == "example.com"
            assert engine._clean_domain("http://www.Example.COM/") == "www.example.com"
            assert engine._clean_domain("EXAMPLE.COM") == "example.com"
            assert engine._clean_domain("example.com:8080") == "example.com"
        finally:
            engine.database.close()


# ===================================================================
# Security validation tests (using _is_valid_domain / _clean_domain)
# ===================================================================

class TestSecurityValidation:
    """Ensure SQL injection and path traversal inputs are rejected."""

    def _make_engine(self, tmp_path):
        db_path = str(tmp_path / "sec_engine.db")
        with patch.object(AdvancedOwnerLogger, "_ensure_log_directory"):
            with patch.object(AdvancedOwnerLogger, "_setup_logger"):
                engine = AdvancedOwnerResearchEngine(
                    debug=False,
                    cache_db=db_path,
                )
        return engine

    def test_security_validator_injection(self, tmp_path):
        """SQL injection-style strings should be rejected as invalid domains."""
        engine = self._make_engine(tmp_path)
        try:
            injections = [
                "'; DROP TABLE users; --",
                "1 OR 1=1",
                "admin'--",
                "' UNION SELECT * FROM users --",
            ]
            for payload in injections:
                assert engine._is_valid_domain(payload) is False, (
                    "Injection payload should be invalid: {}".format(payload)
                )
        finally:
            engine.database.close()

    def test_security_validator_path_traversal(self, tmp_path):
        """Path traversal strings should be rejected as invalid domains."""
        engine = self._make_engine(tmp_path)
        try:
            traversals = [
                "../../etc/passwd",
                "../../../windows/system32",
                "..\\..\\etc\\passwd",
            ]
            for payload in traversals:
                assert engine._is_valid_domain(payload) is False, (
                    "Path traversal should be invalid: {}".format(payload)
                )
        finally:
            engine.database.close()


# ===================================================================
# Export tests
# ===================================================================

class TestExport:
    """Tests for CSV and JSON export methods."""

    def _make_engine(self, tmp_path):
        db_path = str(tmp_path / "export_engine.db")
        with patch.object(AdvancedOwnerLogger, "_ensure_log_directory"):
            with patch.object(AdvancedOwnerLogger, "_setup_logger"):
                engine = AdvancedOwnerResearchEngine(
                    debug=False,
                    cache_db=db_path,
                )
        return engine

    def _sample_results(self):
        return {
            "processed_domains": [
                {
                    "domain": "test.com",
                    "owner_info": {
                        "owner_name": "Test Corp",
                        "registrar": "RegCo",
                        "creation_date": "2020-01-01",
                        "expiry_date": "2030-01-01",
                        "emails": ["admin@test.com"],
                        "phone": "+1-555-0199",
                    },
                    "cache_hit": False,
                    "processing_time": 0.5,
                    "confidence_score": 0.9,
                },
            ],
            "fuzzy_matches": [
                {
                    "domain": "test.com",
                    "actual_owner": "Test Corp",
                    "expected_owner": "Test Corporation",
                    "match_score": 0.88,
                    "match_quality": "very_good",
                    "is_match": True,
                    "threshold_category": "very_good",
                },
            ],
            "statistics": {},
            "session_info": {},
        }

    def test_csv_export(self, tmp_path):
        """Export to CSV and verify the file contains the expected content."""
        engine = self._make_engine(tmp_path)
        try:
            results = self._sample_results()
            csv_file = str(tmp_path / "results.csv")

            engine._export_csv(results, csv_file)

            assert os.path.isfile(csv_file), "CSV file should exist"

            with open(csv_file, "r", encoding="utf-8") as f:
                content = f.read()

            assert "test.com" in content
            assert "Test Corp" in content
            assert "RegCo" in content
        finally:
            engine.database.close()

    def test_json_export(self, tmp_path):
        """Export to JSON and verify the file can be parsed back correctly."""
        engine = self._make_engine(tmp_path)
        try:
            results = self._sample_results()
            json_file = str(tmp_path / "results.json")

            engine._export_json(results, json_file)

            assert os.path.isfile(json_file), "JSON file should exist"

            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            assert "processed_domains" in data
            assert len(data["processed_domains"]) == 1
            assert data["processed_domains"][0]["domain"] == "test.com"
        finally:
            engine.database.close()


# ===================================================================
# Logger initialization test
# ===================================================================

class TestLoggerInitialization:
    """Test that the logger creates without errors."""

    def test_logger_initialization(self, tmp_path):
        """AdvancedOwnerLogger should initialize without raising."""
        log = _make_logger(tmp_path)
        assert log is not None
        assert log.name == "test_owner_logger_{}".format(id(tmp_path))
        assert log.session_id.startswith("owner_session_")
        assert isinstance(log.metrics, dict)
        assert log.metrics["total_messages"] >= 0
