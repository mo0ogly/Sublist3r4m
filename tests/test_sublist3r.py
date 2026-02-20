"""Comprehensive tests for sublist3r.py.

Every network call (DNS, HTTP, socket) is mocked so the suite runs fully
offline.  The autouse fixtures in conftest.py provide DNS mocking, logger
isolation, and a network-blocking safety net.
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure the project root is importable
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import sublist3r  # noqa: E402

# ========================================================================
# 1. Subdomain result sorting and deduplication
# ========================================================================

class TestSubdomainSorting:
    """Tests for subdomain_sorting_key and sort order."""

    def test_sorting_key_plain_domain(self):
        """Plain domain parts are reversed for sorting."""
        key = sublist3r.subdomain_sorting_key("a.example.com")
        # reversed parts: ['com', 'example', 'a'], not www -> (parts, 0)
        assert key == (["com", "example", "a"], 0)

    def test_sorting_key_www_moves_to_top(self):
        """www prefix should sort before other same-level subdomains."""
        key = sublist3r.subdomain_sorting_key("www.example.com")
        # www is stripped, weight=1
        assert key == (["com", "example"], 1)

    def test_sorted_order_matches_docstring_example(self):
        """The sorted order should match the example given in the docstring."""
        unsorted = [
            "b.example.com",
            "www.a.example.com",
            "a.example.net",
            "www.example.net",
            "example.net",
            "example.com",
            "b.a.example.com",
            "a.example.com",
            "www.example.com",
        ]
        expected = [
            "example.com",
            "www.example.com",
            "a.example.com",
            "www.a.example.com",
            "b.a.example.com",
            "b.example.com",
            "example.net",
            "www.example.net",
            "a.example.net",
        ]
        result = sorted(unsorted, key=sublist3r.subdomain_sorting_key)
        assert result == expected

    def test_deduplication_via_set(self, sample_domains):
        """Duplicates are removed when subdomains go through a set, as in main()."""
        duped = sample_domains + sample_domains[:3]
        deduped = sorted(set(duped), key=sublist3r.subdomain_sorting_key)
        assert len(deduped) == len(set(sample_domains))
        # Every original domain should still be present
        for d in sample_domains:
            assert d in deduped


# ========================================================================
# 2. Port scanning (mock socket)
# ========================================================================

class TestPortScan:
    """Tests for the portscan class with mocked socket operations."""

    @patch("sublist3r.socket.socket")
    def test_open_port_detected(self, mock_socket_cls, capsys):
        """An open port (connect_ex returns 0) should be printed."""
        sock_instance = MagicMock()
        sock_instance.connect_ex.return_value = 0
        mock_socket_cls.return_value = sock_instance

        scanner = sublist3r.portscan(["sub.example.com"], ["80"])
        scanner.run()
        # Threads are started inside run(); wait a moment for them to finish
        import time
        time.sleep(0.5)
        captured = capsys.readouterr().out
        assert "sub.example.com" in captured
        assert "80" in captured

    @patch("sublist3r.socket.socket")
    def test_closed_port_not_reported(self, mock_socket_cls, capsys):
        """A closed port (connect_ex returns non-zero) should produce no output."""
        sock_instance = MagicMock()
        sock_instance.connect_ex.return_value = 1  # closed
        mock_socket_cls.return_value = sock_instance

        scanner = sublist3r.portscan(["sub.example.com"], ["443"])
        scanner.run()
        import time
        time.sleep(0.5)
        captured = capsys.readouterr().out
        # No "Found open ports" line should appear
        assert "Found open ports" not in captured

    @patch("sublist3r.socket.socket")
    def test_multiple_ports_some_open(self, mock_socket_cls, capsys):
        """When scanning multiple ports, only open ones are reported."""
        sock_instance = MagicMock()
        # First call: port 80 open, second call: port 443 closed
        sock_instance.connect_ex.side_effect = [0, 1]
        mock_socket_cls.return_value = sock_instance

        scanner = sublist3r.portscan(["host.example.com"], ["80", "443"])
        scanner.run()
        import time
        time.sleep(0.5)
        captured = capsys.readouterr().out
        assert "80" in captured
        assert "443" not in captured


# ========================================================================
# 3. Search-engine classes: Google, Bing, Yahoo
# ========================================================================

class TestGoogleEnum:
    """GoogleEnum.extract_domains with a mocked HTTP response."""

    @patch("requests.Session")
    def test_extract_domains_from_cite_tags(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()
        html = (
            '<cite class="bc">http://mail.example.com/path</cite>'
            '<cite class="bc">http://api.example.com/other</cite>'
            '<cite class="bc">http://www.example.com/nope</cite>'
        )
        enum = sublist3r.GoogleEnum.__new__(sublist3r.GoogleEnum)
        # Manually initialise just enough state (bypass __init__ which
        # tries to start a multiprocessing.Process and make HTTP calls)
        enum.domain = "example.com"
        enum.subdomains = []
        enum.verbose = False
        enum.silent = True
        enum.engine_name = "Google"

        links = enum.extract_domains(html)
        assert "mail.example.com" in enum.subdomains
        assert "api.example.com" in enum.subdomains
        # www.example.com == self.domain-ish but with www; the code skips
        # items where subdomain == self.domain.  www.example.com != example.com
        # so it IS added.
        assert "www.example.com" in enum.subdomains
        # The raw links list should have 3 entries
        assert len(links) == 3

    @patch("requests.Session")
    def test_check_response_errors_blocked(self, mock_session_cls):
        """Google blocking message returns False."""
        enum = sublist3r.GoogleEnum.__new__(sublist3r.GoogleEnum)
        enum.domain = "example.com"
        enum.subdomains = []
        enum.verbose = False
        enum.silent = True
        enum.engine_name = "Google"

        assert enum.check_response_errors("Our systems have detected unusual traffic") is False
        assert enum.check_response_errors("Normal HTML page") is True


class TestBingEnum:
    """BingEnum.extract_domains with mocked HTML."""

    @patch("requests.Session")
    def test_extract_domains_from_bing_html(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()
        html = (
            '<li class="b_algo"><h2><a href="http://test.example.com/page"'
            ' target>title</a></h2></li>'
            '<li class="b_algo"><h2><a href="http://dev.example.com/x"'
            ' target>title2</a></h2></li>'
        )
        enum = sublist3r.BingEnum.__new__(sublist3r.BingEnum)
        enum.domain = "example.com"
        enum.subdomains = []
        enum.verbose = False
        enum.silent = True
        enum.engine_name = "Bing"

        links = enum.extract_domains(html)
        assert "test.example.com" in enum.subdomains
        assert "dev.example.com" in enum.subdomains
        assert len(links) == 2


class TestYahooEnum:
    """YahooEnum.extract_domains with mocked HTML."""

    @patch("requests.Session")
    def test_extract_domains_from_yahoo_html(self, mock_session_cls):
        mock_session_cls.return_value = MagicMock()
        html = (
            '<span class="txt"><span class=" cite fw-xl fz-15px">'
            'mail.example.com/inbox</span></span>'
            '<span class="txt"><span class=" cite fw-xl fz-15px">'
            'other.differentsite.org/page</span></span>'
        )
        enum = sublist3r.YahooEnum.__new__(sublist3r.YahooEnum)
        enum.domain = "example.com"
        enum.subdomains = []
        enum.verbose = False
        enum.silent = True
        enum.engine_name = "Yahoo"

        enum.extract_domains(html)
        assert "mail.example.com" in enum.subdomains
        # other.differentsite.org does not end with example.com -> skipped
        assert "other.differentsite.org" not in enum.subdomains


# ========================================================================
# 4. File output
# ========================================================================

class TestWriteFile:
    """write_file should create a file with one subdomain per line."""

    def test_write_file_creates_correct_content(self, tmp_output_dir):
        filepath = tmp_output_dir / "results.txt"
        subdomains = ["a.example.com", "b.example.com", "c.example.com"]
        sublist3r.write_file(str(filepath), subdomains)

        content = filepath.read_text()
        lines = content.strip().splitlines()
        assert lines == subdomains

    def test_write_file_empty_list(self, tmp_output_dir):
        filepath = tmp_output_dir / "empty.txt"
        sublist3r.write_file(str(filepath), [])
        assert filepath.read_text() == ""


# ========================================================================
# 5. CLI argument parsing
# ========================================================================

class TestParseArgs:
    """parse_args (argparse) behaviour."""

    def test_minimal_args(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["sublist3r.py", "-d", "example.com"])
        args = sublist3r.parse_args()
        assert args.domain == "example.com"
        assert args.threads == 30
        assert args.output is None
        assert args.ports is None
        assert args.engines is None
        assert args.bruteforce is False
        assert args.no_color is False

    def test_all_flags(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", [
            "sublist3r.py",
            "-d", "test.org",
            "-b",
            "-p", "80,443",
            "-v",
            "-t", "10",
            "-e", "google,bing",
            "-o", "/tmp/out.txt",
            "-n",
        ])
        args = sublist3r.parse_args()
        assert args.domain == "test.org"
        assert args.bruteforce is None  # nargs='?' with no value -> None
        assert args.ports == "80,443"
        assert args.verbose is None
        assert args.threads == 10
        assert args.engines == "google,bing"
        assert args.output == "/tmp/out.txt"
        assert args.no_color is True

    def test_missing_domain_exits(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["sublist3r.py"])
        with pytest.raises(SystemExit):
            sublist3r.parse_args()


# ========================================================================
# 6. The main() function with mocked engines
# ========================================================================

class TestMain:
    """main() with all engines mocked out."""

    @patch("sublist3r.multiprocessing.Manager")
    def test_main_returns_sorted_subdomains(self, mock_manager):
        """main() should return a sorted, deduplicated list of subdomains."""
        # The Manager().list() is used as the shared queue
        shared_list = ["b.example.com", "a.example.com", "a.example.com"]
        mock_manager.return_value.list.return_value = shared_list

        with patch("sublist3r.GoogleEnum") as MockGoogle, \
             patch("sublist3r.YahooEnum") as MockYahoo, \
             patch("sublist3r.BingEnum") as MockBing, \
             patch("sublist3r.AskEnum") as MockAsk, \
             patch("sublist3r.BaiduEnum") as MockBaidu, \
             patch("sublist3r.NetcraftEnum") as MockNetcraft, \
             patch("sublist3r.DNSdumpster") as MockDNS, \
             patch("sublist3r.Virustotal") as MockVT, \
             patch("sublist3r.ThreatCrowd") as MockTC, \
             patch("sublist3r.CrtSearch") as MockCrt, \
             patch("sublist3r.PassiveDNS") as MockPassive:

            # Each engine mock needs start() and join()
            for m in [MockGoogle, MockYahoo, MockBing, MockAsk, MockBaidu,
                      MockNetcraft, MockDNS, MockVT, MockTC, MockCrt, MockPassive]:
                inst = MagicMock()
                inst.start = MagicMock()
                inst.join = MagicMock()
                m.return_value = inst

            result = sublist3r.main(
                domain="example.com",
                threads=2,
                savefile=None,
                ports=None,
                silent=True,
                verbose=False,
                enable_bruteforce=False,
                engines=None,
            )

        assert isinstance(result, list)
        # Deduplication should have removed one duplicate
        assert result == sorted(set(shared_list), key=sublist3r.subdomain_sorting_key)

    @patch("sublist3r.multiprocessing.Manager")
    def test_main_invalid_domain_returns_empty(self, mock_manager):
        """An invalid domain string should yield an empty list."""
        result = sublist3r.main(
            domain="not a valid domain!!!",
            threads=2,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None,
        )
        assert result == []

    @patch("sublist3r.multiprocessing.Manager")
    def test_main_with_specific_engines(self, mock_manager):
        """Passing engines='google' should only instantiate GoogleEnum."""
        shared_list = ["mail.example.com"]
        mock_manager.return_value.list.return_value = shared_list

        with patch("sublist3r.GoogleEnum") as MockGoogle:
            inst = MagicMock()
            MockGoogle.return_value = inst
            result = sublist3r.main(
                domain="example.com",
                threads=2,
                savefile=None,
                ports=None,
                silent=True,
                verbose=False,
                enable_bruteforce=False,
                engines="google",
            )
            MockGoogle.assert_called_once()
        assert "mail.example.com" in result

    @patch("sublist3r.write_file")
    @patch("sublist3r.multiprocessing.Manager")
    def test_main_saves_to_file_when_requested(self, mock_manager, mock_write):
        """When savefile is provided, write_file should be invoked."""
        shared_list = ["a.example.com"]
        mock_manager.return_value.list.return_value = shared_list

        with patch("sublist3r.GoogleEnum") as MockGoogle:
            MockGoogle.return_value = MagicMock()

            sublist3r.main(
                domain="example.com",
                threads=2,
                savefile="/tmp/test_out.txt",
                ports=None,
                silent=True,
                verbose=False,
                enable_bruteforce=False,
                engines="google",
            )
        mock_write.assert_called_once()
        assert mock_write.call_args[0][0] == "/tmp/test_out.txt"


# ========================================================================
# 7. enumratorBase and enumratorBaseThreaded - extract_domains / helpers
# ========================================================================

class TestEnumratorBase:
    """Direct tests on the base enumerator class."""

    @patch("requests.Session")
    def test_get_response_none_returns_zero(self, mock_session):
        """get_response(None) should return 0."""
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        assert base.get_response(None) == 0

    @patch("requests.Session")
    def test_get_response_with_text(self, mock_session):
        """get_response should return .text when available."""
        mock_resp = MagicMock()
        mock_resp.text = "<html>hello</html>"
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        assert base.get_response(mock_resp) == "<html>hello</html>"

    @patch("requests.Session")
    def test_check_max_subdomains(self, mock_session):
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        base.MAX_DOMAINS = 10
        assert base.check_max_subdomains(10) is True
        assert base.check_max_subdomains(9) is False
        base.MAX_DOMAINS = 0  # unlimited
        assert base.check_max_subdomains(999) is False

    @patch("requests.Session")
    def test_check_max_pages(self, mock_session):
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        base.MAX_PAGES = 5
        assert base.check_max_pages(5) is True
        assert base.check_max_pages(4) is False
        base.MAX_PAGES = 0
        assert base.check_max_pages(999) is False

    @patch("requests.Session")
    def test_get_page_default_increments_by_ten(self, mock_session):
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        assert base.get_page(0) == 10
        assert base.get_page(10) == 20

    @patch("requests.Session")
    def test_send_req_handles_exception(self, mock_session):
        """When session.get raises, send_req should return 0 (via get_response(None))."""
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        session = MagicMock()
        session.get.side_effect = ConnectionError("no network")
        base.session = session
        base.headers = {}
        base.timeout = 1
        base.base_url = "http://example.com/?q={query}&p={page_no}"
        result = base.send_req("test query", page_no=1)
        assert result == 0

    @patch("requests.Session")
    def test_base_extract_domains_returns_none(self, mock_session):
        """The base class extract_domains is a no-op (returns None)."""
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        assert base.extract_domains("anything") is None

    @patch("requests.Session")
    def test_check_response_errors_default_true(self, mock_session):
        """The default check_response_errors returns True (no errors)."""
        base = sublist3r.enumratorBase.__new__(sublist3r.enumratorBase)
        assert base.check_response_errors("anything") is True


# ========================================================================
# 8. Invalid domain handling
# ========================================================================

class TestInvalidDomain:
    """main() should reject obviously invalid domain strings."""

    @patch("sublist3r.multiprocessing.Manager")
    def test_domain_with_spaces(self, mock_mgr):
        result = sublist3r.main(
            domain="has spaces .com",
            threads=1, savefile=None, ports=None,
            silent=True, verbose=False,
            enable_bruteforce=False, engines=None,
        )
        assert result == []

    @patch("sublist3r.multiprocessing.Manager")
    def test_empty_domain(self, mock_mgr):
        result = sublist3r.main(
            domain="",
            threads=1, savefile=None, ports=None,
            silent=True, verbose=False,
            enable_bruteforce=False, engines=None,
        )
        assert result == []

    @patch("sublist3r.multiprocessing.Manager")
    def test_domain_with_special_chars(self, mock_mgr):
        result = sublist3r.main(
            domain="ex@mple!.com",
            threads=1, savefile=None, ports=None,
            silent=True, verbose=False,
            enable_bruteforce=False, engines=None,
        )
        assert result == []


# ========================================================================
# Additional edge-case tests
# ========================================================================

class TestGenerateQuery:
    """Verify query generation for engines with and without existing subdomains."""

    @patch("requests.Session")
    def test_google_generate_query_no_subs(self, mock_session):
        enum = sublist3r.GoogleEnum.__new__(sublist3r.GoogleEnum)
        enum.domain = "example.com"
        enum.subdomains = []
        enum.MAX_DOMAINS = 11
        query = enum.generate_query()
        assert "site:example.com" in query
        assert "-www.example.com" in query

    @patch("requests.Session")
    def test_google_generate_query_with_subs(self, mock_session):
        enum = sublist3r.GoogleEnum.__new__(sublist3r.GoogleEnum)
        enum.domain = "example.com"
        enum.subdomains = ["mail.example.com", "api.example.com"]
        enum.MAX_DOMAINS = 11
        query = enum.generate_query()
        assert "-mail.example.com" in query
        assert "-api.example.com" in query

    @patch("requests.Session")
    def test_bing_generate_query_no_subs(self, mock_session):
        enum = sublist3r.BingEnum.__new__(sublist3r.BingEnum)
        enum.domain = "example.com"
        enum.subdomains = []
        enum.MAX_DOMAINS = 30
        query = enum.generate_query()
        assert "domain:example.com" in query

    @patch("requests.Session")
    def test_yahoo_generate_query_no_subs(self, mock_session):
        enum = sublist3r.YahooEnum.__new__(sublist3r.YahooEnum)
        enum.domain = "example.com"
        enum.subdomains = []
        query = enum.generate_query()
        assert "site:example.com" in query


class TestNoColor:
    """no_color() should blank out all color globals."""

    def test_no_color_clears_globals(self):
        # Save originals
        originals = (sublist3r.G, sublist3r.Y, sublist3r.B, sublist3r.R, sublist3r.W)
        sublist3r.no_color()
        assert sublist3r.G == ""
        assert sublist3r.Y == ""
        assert sublist3r.B == ""
        assert sublist3r.R == ""
        assert sublist3r.W == ""
        # Restore
        sublist3r.G, sublist3r.Y, sublist3r.B, sublist3r.R, sublist3r.W = originals
