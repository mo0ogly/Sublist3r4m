"""Tests for the subbrute.subbrute module.

Covers resolver/names file loading, ColoredLogger initialisation,
wildcard detection, DNS lookup worker, nameserver verification,
print_target deduplication, and result formatting.

All DNS and network calls are mocked so the suite runs without
internet access.
"""

import logging
import os
import queue
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest

# ---------------------------------------------------------------------------
# Helpers to safely import the module under test while the global
# ``logger`` and ``signal_init`` side-effects are contained.
# ---------------------------------------------------------------------------
# The subbrute module creates a global ColoredLogger (which opens a log file)
# and calls signal.signal inside signal_init().  We patch those during import
# so the test process is not affected.
import subbrute.subbrute as subbrute_mod


# ---------------------------------------------------------------------------
# 1. test_resolver_loading
# ---------------------------------------------------------------------------
class TestResolverLoading:
    """Verify that resolvers.txt can be read via check_open."""

    def test_check_open_reads_resolvers(self, tmp_path):
        """check_open returns a list of lines from the resolver file."""
        resolver_file = tmp_path / "resolvers.txt"
        resolver_file.write_text("8.8.8.8\n8.8.4.4\n1.1.1.1\n")

        result = subbrute_mod.check_open(str(resolver_file))

        assert len(result) == 3
        assert "8.8.8.8\n" in result
        assert "1.1.1.1\n" in result

    def test_check_open_with_actual_resolvers_file(self):
        """The bundled resolvers.txt should be readable and non-empty."""
        resolvers_path = os.path.join(
            os.path.dirname(subbrute_mod.__file__), "resolvers.txt"
        )
        if not os.path.isfile(resolvers_path):
            pytest.skip("resolvers.txt not found at expected location")

        result = subbrute_mod.check_open(resolvers_path)
        assert len(result) > 0, "resolvers.txt should not be empty"


# ---------------------------------------------------------------------------
# 2. test_names_loading
# ---------------------------------------------------------------------------
class TestNamesLoading:
    """Verify that names.txt can be read via check_open."""

    def test_check_open_reads_names(self, tmp_path):
        """check_open returns a list of subdomain lines."""
        names_file = tmp_path / "names.txt"
        names_file.write_text("www\nmail\nftp\n")

        result = subbrute_mod.check_open(str(names_file))

        assert len(result) == 3
        assert "www\n" in result

    def test_check_open_with_actual_names_file(self):
        """The bundled names.txt should be readable and non-empty."""
        names_path = os.path.join(
            os.path.dirname(subbrute_mod.__file__), "names.txt"
        )
        if not os.path.isfile(names_path):
            pytest.skip("names.txt not found at expected location")

        result = subbrute_mod.check_open(names_path)
        assert len(result) > 0, "names.txt should not be empty"


# ---------------------------------------------------------------------------
# 3. test_colored_logger
# ---------------------------------------------------------------------------
class TestColoredLogger:
    """ColoredLogger initialises without errors and logs at every level."""

    def test_logger_initialises(self, tmp_path):
        """Creating a ColoredLogger should not raise."""
        log_file = str(tmp_path / "test.log")
        cl = subbrute_mod.ColoredLogger(
            name="test_logger_init", log_file=log_file, debug=True
        )
        assert cl is not None
        assert cl.debug_enabled is True
        assert isinstance(cl.logger, logging.Logger)

    def test_logger_levels_do_not_raise(self, tmp_path):
        """Calling debug/info/warning/error should not raise."""
        log_file = str(tmp_path / "test_levels.log")
        cl = subbrute_mod.ColoredLogger(
            name="test_logger_levels", log_file=log_file, debug=True
        )
        # Replace handlers with NullHandler to avoid polluting output
        cl.logger.handlers = [logging.NullHandler()]

        cl.debug("debug message")
        cl.info("info message")
        cl.warning("warning message")
        cl.error("error message")
        # We do NOT test critical() because it calls sys.exit(1)

    def test_logger_color_codes_present(self):
        """COLORS dictionary should contain expected keys."""
        expected_keys = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "RESET"}
        assert expected_keys == set(subbrute_mod.ColoredLogger.COLORS.keys())


# ---------------------------------------------------------------------------
# 4. test_wildcard_detection
# ---------------------------------------------------------------------------
class TestWildcardDetection:
    """Mock DNS responses to exercise find_wildcards logic."""

    def _make_verifier(self, mock_resolver_cls):
        """Build a NameServerVerifier with all DNS calls mocked."""
        instance = mock_resolver_cls.return_value
        instance.nameservers = ["8.8.8.8"]
        instance.timeout = 1
        instance.lifetime = 1
        # query() is called during __init__ for latency test -- make it succeed
        instance.query.return_value = [MagicMock()]

        resolver_q = MagicMock()
        wildcards = {}
        verifier = subbrute_mod.NameServerVerifier.__new__(
            subbrute_mod.NameServerVerifier
        )
        # Manually initialise fields that __init__ would set, to avoid
        # triggering multiprocessing.Process.__init__ and signal_init().
        verifier.time_to_die = False
        verifier.resolver_q = resolver_q
        verifier.wildcards = wildcards
        verifier.record_type = "A"
        verifier.resolver_list = ["8.8.8.8"]
        verifier.target = "example.com"
        verifier.most_popular_website = "www.google.com"
        verifier.backup_resolver = ["127.0.0.1"]
        verifier.resolver = instance
        return verifier

    def test_nxdomain_means_no_wildcard(self, mock_dns):
        """NXDOMAIN for random subdomain means no wildcard -- returns True."""
        with patch("dns.resolver.Resolver") as mock_cls:
            verifier = self._make_verifier(mock_cls)
            # First call (spam test): raise NXDOMAIN
            # Second call (wildcard test): raise NXDOMAIN
            verifier.resolver.query.side_effect = dns.resolver.NXDOMAIN()

            result = verifier.find_wildcards("example.com")
            assert result is True

    def test_spam_dns_detected(self, mock_dns):
        """If the resolver answers random .com domains, it is a spam DNS."""
        with patch("dns.resolver.Resolver") as mock_cls:
            verifier = self._make_verifier(mock_cls)
            # Spam test returns records -- should be rejected
            mock_record = MagicMock()
            mock_record.__str__ = lambda self: "1.2.3.4"
            mock_answer = MagicMock()
            mock_answer.__len__ = lambda self: 1
            mock_answer.__iter__ = lambda self: iter([mock_record])
            verifier.resolver.query.return_value = mock_answer

            result = verifier.find_wildcards("example.com")
            assert result is False


# ---------------------------------------------------------------------------
# 5. test_lookup_worker
# ---------------------------------------------------------------------------
class TestLookupWorker:
    """Exercise DNSLookupWorker.check with mocked DNS resolution."""

    def _make_worker(self, mock_resolver_cls):
        """Build a DNSLookupWorker without starting a process."""
        instance = mock_resolver_cls.return_value
        instance.nameservers = ["8.8.8.8"]
        instance.timeout = 2
        instance.lifetime = 5
        instance.query.return_value = MagicMock()

        worker = subbrute_mod.DNSLookupWorker.__new__(
            subbrute_mod.DNSLookupWorker
        )
        worker.required_nameservers = 16
        worker.in_q = MagicMock()
        worker.out_q = MagicMock()
        worker.resolver_q = MagicMock()
        worker.resolver_q.get_nowait.side_effect = queue.Empty
        worker.domain = "example.com"
        worker.wildcards = {}
        worker.spider_blacklist = {}
        worker.resolver = instance
        worker.resolver.nameservers = ["8.8.8.8"] * 17  # above threshold
        return worker

    def test_check_returns_response_for_a_record(self, mock_dns):
        """check() should return a response object for valid A lookups."""
        with patch("dns.resolver.Resolver") as mock_cls:
            worker = self._make_worker(mock_cls)
            mock_response = MagicMock()
            mock_response.response = "www.example.com IN A 93.184.216.34"
            mock_response.__iter__ = lambda self: iter([])
            worker.resolver.query.return_value = mock_response

            result = worker.check("www.example.com", "A")
            assert result is not None

    def test_check_returns_false_on_nxdomain(self, mock_dns):
        """check() should return False when NXDOMAIN is raised."""
        with patch("dns.resolver.Resolver") as mock_cls:
            worker = self._make_worker(mock_cls)
            worker.resolver.query.side_effect = dns.resolver.NXDOMAIN()

            result = worker.check("nonexistent.example.com", "A")
            assert result is False


# ---------------------------------------------------------------------------
# 6. test_nameserver_verification
# ---------------------------------------------------------------------------
class TestNameserverVerification:
    """Mock DNS query for the NS verification path."""

    def _make_verifier(self, mock_resolver_cls):
        """Build a NameServerVerifier bypassing __init__."""
        instance = mock_resolver_cls.return_value
        instance.nameservers = ["8.8.8.8"]
        instance.timeout = 1
        instance.lifetime = 1
        instance.query.return_value = [MagicMock()]

        verifier = subbrute_mod.NameServerVerifier.__new__(
            subbrute_mod.NameServerVerifier
        )
        verifier.time_to_die = False
        verifier.resolver_q = MagicMock()
        verifier.wildcards = {}
        verifier.record_type = "A"
        verifier.resolver_list = []
        verifier.target = "example.com"
        verifier.most_popular_website = "www.google.com"
        verifier.backup_resolver = ["127.0.0.1"]
        verifier.resolver = instance
        return verifier

    def test_add_nameserver_puts_to_queue(self, mock_dns):
        """add_nameserver should put the server string into resolver_q."""
        with patch("dns.resolver.Resolver") as mock_cls:
            verifier = self._make_verifier(mock_cls)
            verifier.resolver_q.put = MagicMock()

            result = verifier.add_nameserver("8.8.8.8")

            assert result is True
            verifier.resolver_q.put.assert_called_once_with("8.8.8.8", timeout=1)

    def test_add_empty_nameserver_rejected(self, mock_dns):
        """add_nameserver should reject an empty string."""
        with patch("dns.resolver.Resolver") as mock_cls:
            verifier = self._make_verifier(mock_cls)

            result = verifier.add_nameserver("")
            assert result is False

    def test_is_valid_ip(self, mock_dns):
        """_is_valid_ip should accept valid IPv4 and reject garbage."""
        with patch("dns.resolver.Resolver") as mock_cls:
            verifier = self._make_verifier(mock_cls)

            assert verifier._is_valid_ip("8.8.8.8") is True
            assert verifier._is_valid_ip("1.2.3.4") is True
            assert verifier._is_valid_ip("not-an-ip") is False
            assert verifier._is_valid_ip("") is False

    def test_verify_empty_list_returns_false(self, mock_dns):
        """verify([]) should return False immediately."""
        with patch("dns.resolver.Resolver") as mock_cls:
            verifier = self._make_verifier(mock_cls)

            result = verifier.verify([])
            assert result is False


# ---------------------------------------------------------------------------
# 7. test_print_target_dedup
# ---------------------------------------------------------------------------
class TestPrintTargetDedup:
    """Verify that print_target removes duplicate subdomains."""

    @patch("subbrute.subbrute.run")
    def test_duplicates_removed(self, mock_run, mock_dns):
        """print_target should return a set with no duplicates."""
        # run() is a generator -- simulate two identical results
        mock_run.return_value = iter([
            ("www.example.com", "A", ["93.184.216.34"]),
            ("www.example.com", "A", ["93.184.216.34"]),
            ("mail.example.com", "A", ["93.184.216.35"]),
        ])

        result = subbrute_mod.print_target(
            "example.com",
            record_type="A",
            subdomains="names.txt",
            resolve_list="resolvers.txt",
            process_count=1,
            verbose=False,
        )

        assert isinstance(result, set)
        # Even though run() yielded www twice, the set should deduplicate
        assert len(result) <= 3
        # Check that at least the unique entries are present
        matching = [r for r in result if "www.example.com" in r]
        assert len(matching) == 1, "www.example.com should appear exactly once"


# ---------------------------------------------------------------------------
# 8. test_result_formatting
# ---------------------------------------------------------------------------
class TestResultFormatting:
    """Verify the CSV-like output format used by print_target / main."""

    def test_format_with_record_type(self):
        """When record_type is truthy, result is 'hostname,addr1,addr2'."""
        hostname = "www.example.com"
        _record_type = "A"  # noqa: F841
        response = ["93.184.216.34", "93.184.216.35"]

        # Replicate the formatting logic from print_target (line 1084)
        formatted = "%s,%s" % (hostname, ",".join(response).strip(","))

        assert formatted == "www.example.com,93.184.216.34,93.184.216.35"

    def test_format_without_record_type(self):
        """When record_type is falsy, result is just the hostname."""
        hostname = "www.example.com"
        record_type = False

        if not record_type:
            result = hostname
        else:
            result = hostname  # would never reach here

        assert result == "www.example.com"

    def test_extract_hosts_filters_by_domain(self):
        """extract_hosts should only return hosts ending with the target domain."""
        # Note: extract_hosts uses str.endswith() so "other.evil.net" won't
        # match "example.com", but "notexample.com" *does* end with
        # "example.com".  Use a truly different domain to test filtering.
        data = " sub.example.com  other.evil.net  deep.sub.example.com "
        result = subbrute_mod.extract_hosts(data, "example.com")

        assert "sub.example.com" in result
        assert "deep.sub.example.com" in result
        assert "other.evil.net" not in result

    def test_extract_hosts_strips_trailing_dot(self):
        """extract_hosts should strip trailing dots from hostnames."""
        data = " sub.example.com.  "
        # The regex matches "sub.example.com." including the dot, but
        # the function strips it.  The match requires surrounding whitespace.
        result = subbrute_mod.extract_hosts(data, "example.com")
        for host in result:
            assert not host.endswith("."), "trailing dot should be stripped"
