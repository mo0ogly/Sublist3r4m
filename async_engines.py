#!/usr/bin/env python
# coding: utf-8
# Async alternative to Sublist3r's threaded search engine enumeration.
# Uses aiohttp + asyncio.gather() for concurrent HTTP requests.

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
import urllib.parse as urlparse

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

# Reuse shared utilities from the original module
from sublist3r import (
    B,
    G,
    R,
    W,
    Y,
    banner,
    no_color,
    subdomain_sorting_key,
    write_file,
)


def _check_aiohttp() -> None:
    """Exit with a helpful message when aiohttp is not installed."""
    if aiohttp is None:
        print(
            R + "[!] Error: aiohttp is required for async mode." + W + "\n"
            "Install it with:  pip install sublist3r4m[async]"
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Async base class
# ---------------------------------------------------------------------------

class AsyncEnumeratorBase:
    """Base class for async search-engine subdomain enumerators.

    Subclasses must implement:
        - generate_query()
        - extract_domains(resp_text)

    And may optionally override:
        - check_response_errors(resp_text) -> bool
        - should_sleep() -> coroutine
        - get_page(num) -> int
        - enumerate() for engines with non-standard pagination
    """

    MAX_DOMAINS: int = 0
    MAX_PAGES: int = 0

    def __init__(
        self,
        base_url: str,
        engine_name: str,
        domain: str,
        *,
        silent: bool = False,
        verbose: bool = True,
        rate_limit: float = 1.0,
    ) -> None:
        self.domain = urlparse.urlparse(domain).netloc
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.rate_limit = rate_limit  # seconds between requests
        self.subdomains: list[str] = []
        self.timeout = 25
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36"
                " (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "Accept-Encoding": "gzip",
        }
        self._last_request_time: float = 0.0
        self.print_banner()

    # -- helpers -------------------------------------------------------------

    def print_(self, text: object) -> None:
        if not self.silent:
            print(text)

    def print_banner(self) -> None:
        self.print_(G + "[-] Searching now in %s.." % self.engine_name + W)

    # -- rate-limiting -------------------------------------------------------

    async def _rate_limit_wait(self) -> None:
        """Enforce per-engine rate limiting between HTTP requests."""
        if self.rate_limit <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.monotonic()

    # -- HTTP ----------------------------------------------------------------

    async def send_req(
        self,
        session: aiohttp.ClientSession,
        query: str,
        page_no: int = 1,
    ) -> str | int:
        url = self.base_url.format(query=query, page_no=page_no)
        return await self._get(session, url)

    async def _get(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> str | int:
        await self._rate_limit_wait()
        try:
            async with session.get(
                url,
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as resp:
                return await resp.text()
        except Exception:
            return 0

    # -- pagination helpers --------------------------------------------------

    def check_max_subdomains(self, count: int) -> bool:
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num: int) -> bool:
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    def get_page(self, num: int) -> int:
        return num + 10

    # -- override points -----------------------------------------------------

    def extract_domains(self, resp: str) -> list[str]:  # noqa: ARG002
        return []

    def check_response_errors(self, resp: str | int) -> bool:  # noqa: ARG002
        return True

    async def should_sleep(self) -> None:
        return

    def generate_query(self) -> str:
        return ""

    # -- main loop -----------------------------------------------------------

    async def enumerate(self, session: aiohttp.ClientSession) -> list[str]:
        """Run the pagination loop, returning discovered subdomains."""
        page_no = 0
        prev_links: list[str] = []
        retries = 0

        while True:
            query = self.generate_query()
            count = query.count(self.domain)

            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):
                return self.subdomains

            resp = await self.send_req(session, query, page_no)

            if not self.check_response_errors(resp):
                return self.subdomains

            links = self.extract_domains(resp)

            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            await self.should_sleep()

        return self.subdomains  # pragma: no cover


# ---------------------------------------------------------------------------
# Concrete engine implementations
# ---------------------------------------------------------------------------

class AsyncGoogleEnum(AsyncEnumeratorBase):
    """Google search engine enumerator (async)."""

    MAX_DOMAINS = 11
    MAX_PAGES = 200

    def __init__(self, domain: str, *, silent: bool = False, verbose: bool = True, rate_limit: float = 1.0) -> None:
        base_url = (
            "https://google.com/search?q={query}&btnG=Search"
            "&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        )
        super().__init__(base_url, "Google", domain, silent=silent, verbose=verbose, rate_limit=rate_limit)

    def extract_domains(self, resp: str | int) -> list[str]:
        if not isinstance(resp, str):
            return []
        links_list: list[str] = []
        link_regx = re.compile(r"<cite.*?>(.*?)<\/cite>")
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub("<span.*>", "", link)
                if not link.startswith("http"):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp: str | int) -> bool:
        if isinstance(resp, str) and "Our systems have detected unusual traffic" in resp:
            self.print_(R + "[!] Error: Google probably now is blocking our requests" + W)
            self.print_(R + "[~] Finished now the Google Enumeration ..." + W)
            return False
        return True

    async def should_sleep(self) -> None:
        await asyncio.sleep(5)

    def generate_query(self) -> str:
        if self.subdomains:
            fmt = "site:{domain} -www.{domain} -{found}"
            found = " -".join(self.subdomains[: self.MAX_DOMAINS - 2])
            return fmt.format(domain=self.domain, found=found)
        return "site:{domain} -www.{domain}".format(domain=self.domain)


class AsyncBingEnum(AsyncEnumeratorBase):
    """Bing search engine enumerator (async)."""

    MAX_DOMAINS = 30
    MAX_PAGES = 0

    def __init__(self, domain: str, *, silent: bool = False, verbose: bool = True, rate_limit: float = 1.0) -> None:
        base_url = "https://www.bing.com/search?q={query}&go=Submit&first={page_no}"
        super().__init__(base_url, "Bing", domain, silent=silent, verbose=verbose, rate_limit=rate_limit)

    def extract_domains(self, resp: str | int) -> list[str]:
        if not isinstance(resp, str):
            return []
        links_list: list[str] = []
        link_regx = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regx2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r"<(\/)?strong>|<span.*?>|<|>", "", link)
                if not link.startswith("http"):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def generate_query(self) -> str:
        if self.subdomains:
            fmt = "domain:{domain} -www.{domain} -{found}"
            found = " -".join(self.subdomains[: self.MAX_DOMAINS])
            return fmt.format(domain=self.domain, found=found)
        return "domain:{domain} -www.{domain}".format(domain=self.domain)


class AsyncYahooEnum(AsyncEnumeratorBase):
    """Yahoo search engine enumerator (async)."""

    MAX_DOMAINS = 10
    MAX_PAGES = 0

    def __init__(self, domain: str, *, silent: bool = False, verbose: bool = True, rate_limit: float = 1.0) -> None:
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        super().__init__(base_url, "Yahoo", domain, silent=silent, verbose=verbose, rate_limit=rate_limit)

    def extract_domains(self, resp: str | int) -> list[str]:
        if not isinstance(resp, str):
            return []
        link_regx2 = re.compile('<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile('<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list: list[str] = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub(r"<(\/)?b>", "", link)
                if not link.startswith("http"):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def get_page(self, num: int) -> int:
        return num + 10

    def generate_query(self) -> str:
        if self.subdomains:
            fmt = "site:{domain} -domain:www.{domain} -domain:{found}"
            found = " -domain:".join(self.subdomains[:77])
            return fmt.format(domain=self.domain, found=found)
        return "site:{domain}".format(domain=self.domain)


class AsyncVirusTotal(AsyncEnumeratorBase):
    """VirusTotal enumerator (async)."""

    def __init__(self, domain: str, *, silent: bool = False, verbose: bool = True, rate_limit: float = 1.0) -> None:
        base_url = "https://www.virustotal.com/ui/domains/{domain}/subdomains"
        super().__init__(base_url, "Virustotal", domain, silent=silent, verbose=verbose, rate_limit=rate_limit)
        self.url: str = self.base_url.format(domain=self.domain)

    async def enumerate(self, session: aiohttp.ClientSession) -> list[str]:
        while self.url:
            resp = await self._get(session, self.url)
            if not isinstance(resp, str):
                break
            data = json.loads(resp)
            if "error" in data:
                self.print_(R + "[!] Error: Virustotal probably now is blocking our requests" + W)
                break
            if "links" in data and "next" in data["links"]:
                self.url = data["links"]["next"]
            else:
                self.url = ""
            self._extract_from_json(data)
        return self.subdomains

    def _extract_from_json(self, data: dict) -> None:
        try:
            for item in data["data"]:
                if item["type"] == "domain":
                    subdomain = item["id"]
                    if not subdomain.endswith(self.domain):
                        continue
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass

    # Unused stubs to satisfy the base-class interface
    def extract_domains(self, resp: str | int) -> list[str]:
        return []

    def generate_query(self) -> str:
        return ""


class AsyncCrtSearch(AsyncEnumeratorBase):
    """SSL Certificate Transparency log enumerator via crt.sh (async)."""

    def __init__(self, domain: str, *, silent: bool = False, verbose: bool = True, rate_limit: float = 1.0) -> None:
        base_url = "https://crt.sh/?q=%25.{domain}"
        super().__init__(base_url, "SSL Certificates", domain, silent=silent, verbose=verbose, rate_limit=rate_limit)

    async def enumerate(self, session: aiohttp.ClientSession) -> list[str]:
        url = self.base_url.format(domain=self.domain)
        resp = await self._get(session, url)
        if isinstance(resp, str) and resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp: str | int) -> list[str]:
        if not isinstance(resp, str):
            return []
        link_regx = re.compile("<TD>(.*?)</TD>")
        links_list: list[str] = []
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = link.strip()
                subdomains: list[str] = []
                if "<BR>" in link:
                    subdomains = link.split("<BR>")
                else:
                    subdomains.append(link)
                for subdomain in subdomains:
                    if not subdomain.endswith(self.domain) or "*" in subdomain:
                        continue
                    if "@" in subdomain:
                        subdomain = subdomain[subdomain.find("@") + 1 :]
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def generate_query(self) -> str:
        return ""


class AsyncThreatCrowd(AsyncEnumeratorBase):
    """ThreatCrowd enumerator (async)."""

    def __init__(self, domain: str, *, silent: bool = False, verbose: bool = True, rate_limit: float = 1.0) -> None:
        base_url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        super().__init__(base_url, "ThreatCrowd", domain, silent=silent, verbose=verbose, rate_limit=rate_limit)

    async def enumerate(self, session: aiohttp.ClientSession) -> list[str]:
        url = self.base_url.format(domain=self.domain)
        resp = await self._get(session, url)
        if isinstance(resp, str) and resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp: str | int) -> list[str]:
        if not isinstance(resp, str):
            return []
        found: list[str] = []
        try:
            links = json.loads(resp)["subdomains"]
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
                    found.append(subdomain)
        except Exception:
            pass
        return found

    def generate_query(self) -> str:
        return ""


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

SUPPORTED_ENGINES: dict[str, type[AsyncEnumeratorBase]] = {
    "google": AsyncGoogleEnum,
    "bing": AsyncBingEnum,
    "yahoo": AsyncYahooEnum,
    "virustotal": AsyncVirusTotal,
    "ssl": AsyncCrtSearch,
    "threatcrowd": AsyncThreatCrowd,
}


async def async_main(
    domain: str,
    savefile: str | None = None,
    engines: str | None = None,
    silent: bool = False,
    verbose: bool = True,
    rate_limit: float = 1.0,
    max_connections: int = 30,
) -> list[str]:
    """Run all chosen async engines concurrently via asyncio.gather().

    Args:
        domain: Target domain to enumerate subdomains for.
        savefile: Optional path to save results.
        engines: Comma-separated engine names, or None for all.
        silent: Suppress console output.
        verbose: Print subdomains in real time.
        rate_limit: Minimum seconds between HTTP requests per engine.
        max_connections: Maximum simultaneous TCP connections.

    Returns:
        Sorted list of unique discovered subdomains.
    """
    _check_aiohttp()

    # Validate domain
    domain_check = re.compile(r"^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        if not silent:
            print(R + "Error: Please enter a valid domain" + W)
        return []

    if not domain.startswith("http://") or not domain.startswith("https://"):
        domain = "http://" + domain

    parsed_domain = urlparse.urlparse(domain)

    if not silent:
        print(B + "[-] Enumerating subdomains now for %s" % parsed_domain.netloc + W)
    if verbose and not silent:
        print(Y + "[-] verbosity is enabled, will show the subdomains results in realtime" + W)

    # Select engines
    if engines is None:
        chosen = list(SUPPORTED_ENGINES.values())
    else:
        chosen = []
        for name in engines.split(","):
            name = name.strip().lower()
            if name in SUPPORTED_ENGINES:
                chosen.append(SUPPORTED_ENGINES[name])

    if not chosen:
        if not silent:
            print(R + "[!] No valid engines selected." + W)
        return []

    # Instantiate engines
    instances = [
        cls(domain, silent=silent, verbose=verbose, rate_limit=rate_limit)
        for cls in chosen
    ]

    # Run all engines concurrently under a single shared session
    connector = aiohttp.TCPConnector(limit=max_connections)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        results = await asyncio.gather(
            *(engine.enumerate(session) for engine in instances),
            return_exceptions=True,
        )

    # Collect and deduplicate
    all_subdomains: set[str] = set()
    for result in results:
        if isinstance(result, BaseException):
            if not silent:
                print(R + "[!] Engine error: %s" % result + W)
            continue
        all_subdomains.update(result)

    subdomains = sorted(all_subdomains, key=subdomain_sorting_key)

    if savefile:
        write_file(savefile, subdomains)

    if not silent:
        print(Y + "[-] Total Unique Subdomains Found: %s" % len(subdomains) + W)
        for subdomain in subdomains:
            print(G + subdomain + W)

    return subdomains


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Async subdomain enumerator (alternative to Sublist3r's threaded mode)",
        epilog="Example: python async_engines.py -d google.com",
    )
    parser.add_argument("-d", "--domain", required=True, help="Domain to enumerate subdomains for")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument(
        "-e", "--engines",
        help="Comma-separated list of engines (google,bing,yahoo,virustotal,ssl,threatcrowd)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", default=True, help="Show subdomains in real time")
    parser.add_argument("-n", "--no-color", action="store_true", default=False, help="Disable coloured output")
    parser.add_argument(
        "--rate-limit", type=float, default=1.0,
        help="Seconds between requests per engine (default: 1.0)",
    )
    parser.add_argument(
        "--max-connections", type=int, default=30,
        help="Max simultaneous TCP connections (default: 30)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    _check_aiohttp()
    args = _parse_args()
    if args.no_color:
        no_color()
    banner()
    asyncio.run(
        async_main(
            domain=args.domain,
            savefile=args.output,
            engines=args.engines,
            silent=False,
            verbose=args.verbose,
            rate_limit=args.rate_limit,
            max_connections=args.max_connections,
        )
    )
