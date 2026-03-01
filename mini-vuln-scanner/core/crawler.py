"""
core/crawler.py — Depth-limited BFS web crawler.

Prints clear progress to the terminal so you can see exactly what it is doing.
No HTTP server is started. All output goes to stdout via print / logging.
"""

import logging
import time
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qsl
from urllib.robotparser import RobotFileParser
from typing import Optional

import requests
from bs4 import BeautifulSoup

from core.session import SessionManager
from core.utils import normalize_url, same_domain, is_valid_url

try:
    from colorama import Fore, Style
except ImportError:
    class Fore:   # type: ignore[no-redef]
        GREEN = YELLOW = RED = CYAN = WHITE = ""
    class Style:  # type: ignore[no-redef]
        BRIGHT = RESET_ALL = ""


class Crawler:
    """
    BFS web crawler — discovers pages and forms within a single domain.

    Results:
        visited_urls         set[str]       — normalised pages fetched
        collected_forms      list[dict]     — <form> descriptors
        collected_get_params dict[str,list] — URL → list of GET param names
    """

    def __init__(
        self,
        start_url: str,
        max_depth: int,
        delay: float,
        session_mgr: SessionManager,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.start_url  = normalize_url(start_url)
        self.max_depth  = max_depth
        self.delay      = delay
        self.session_mgr = session_mgr
        self._log       = logger or logging.getLogger("scanner")

        self.visited_urls: set[str]             = set()
        self.collected_forms: list[dict]        = []
        self.collected_get_params: dict[str, list[str]] = {}

        self._robots = self._load_robots()

    # ── robots.txt ─────────────────────────────────────────────────────────

    def _load_robots(self) -> RobotFileParser:
        parsed    = urlparse(self.start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        rp = RobotFileParser()
        rp.set_url(robots_url)
        try:
            rp.read()
            self._log.debug(f"robots.txt loaded from {robots_url}")
        except Exception as exc:
            self._log.debug(f"Could not read robots.txt ({exc}); proceeding.")
        return rp

    def _is_allowed(self, url: str) -> bool:
        return self._robots.can_fetch("*", url)

    # ── BFS crawl ──────────────────────────────────────────────────────────

    def crawl(self) -> None:
        """Execute BFS crawl from start_url, printing progress as we go."""
        queue: deque[tuple[str, int]] = deque([(self.start_url, 0)])
        queued: set[str] = {self.start_url}

        while queue:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            if not self._is_allowed(url):
                print(f"  {Fore.YELLOW}[CRAWL] Skipped (robots.txt): {url}{Style.RESET_ALL}")
                continue

            print(f"  {Fore.CYAN}[CRAWL] Visiting [depth={depth}]: {url}{Style.RESET_ALL}")

            # ── Fetch ───────────────────────────────────────────────────
            try:
                resp = self.session_mgr.get(url)
            except requests.exceptions.Timeout:
                print(f"  {Fore.YELLOW}[CRAWL] Timeout → {url} (skipping){Style.RESET_ALL}")
                continue
            except requests.exceptions.SSLError as exc:
                print(f"  {Fore.YELLOW}[CRAWL] SSL error → {url}: {exc} (skipping){Style.RESET_ALL}")
                continue
            except requests.exceptions.ConnectionError as exc:
                print(f"  {Fore.YELLOW}[CRAWL] Connection error → {url}: {exc} (skipping){Style.RESET_ALL}")
                continue
            except requests.RequestException as exc:
                print(f"  {Fore.YELLOW}[CRAWL] Request error → {url}: {exc} (skipping){Style.RESET_ALL}")
                continue

            if resp.status_code == 403:
                print(f"  {Fore.YELLOW}[CRAWL] 403 Forbidden → {url} (skipping){Style.RESET_ALL}")
                continue
            if resp.status_code == 404:
                print(f"  {Fore.YELLOW}[CRAWL] 404 Not Found → {url} (skipping){Style.RESET_ALL}")
                continue

            self.visited_urls.add(url)
            time.sleep(self.delay)

            # Only parse HTML
            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type:
                print(f"  {Fore.WHITE}[CRAWL] Skipping non-HTML content ({content_type[:40]}){Style.RESET_ALL}")
                continue

            # ── Parse ───────────────────────────────────────────────────
            try:
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception as exc:
                print(f"  {Fore.YELLOW}[CRAWL] Parse error on {url}: {exc}{Style.RESET_ALL}")
                continue

            self._collect_get_params(url)

            forms = list(soup.find_all("form"))
            self._extract_forms(url, soup)
            print(
                f"  {Fore.GREEN}[CRAWL] ✓ {url} → "
                f"{len(forms)} form(s), "
                f"{len(self.collected_get_params.get(url, []))} GET param(s)"
                f"{Style.RESET_ALL}"
            )

            if depth >= self.max_depth:
                continue

            # ── Enqueue new links ───────────────────────────────────────
            new_links = self._extract_links(url, soup)
            added = 0
            for link in new_links:
                norm = normalize_url(link)
                if norm not in queued and norm not in self.visited_urls:
                    queued.add(norm)
                    queue.append((norm, depth + 1))
                    added += 1
            if added:
                print(f"  {Fore.CYAN}[CRAWL] Enqueued {added} new link(s) from {url}{Style.RESET_ALL}")

    # ── Link extraction ────────────────────────────────────────────────────

    def _extract_links(self, current_url: str, soup: BeautifulSoup) -> list[str]:
        links: list[str] = []
        for tag in soup.find_all("a", href=True):
            href: str = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(current_url, href)
            if not is_valid_url(absolute):
                continue
            if not same_domain(self.start_url, absolute):
                continue
            links.append(absolute)
        return links

    # ── Form extraction ────────────────────────────────────────────────────

    def _extract_forms(self, page_url: str, soup: BeautifulSoup) -> None:
        for form in soup.find_all("form"):
            action: str = form.get("action", "") or ""
            absolute_action = urljoin(page_url, action) if action else page_url
            method: str = form.get("method", "GET").strip().upper()

            inputs: list[dict] = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                inputs.append({
                    "name":  name,
                    "type":  inp.get("type", "text").lower(),
                    "value": inp.get("value", ""),
                })

            self.collected_forms.append({
                "source_url": page_url,
                "action":     absolute_action,
                "method":     method,
                "inputs":     inputs,
            })

    # ── GET param collection ───────────────────────────────────────────────

    def _collect_get_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = [name for name, _ in parse_qsl(parsed.query)]
        if params:
            self.collected_get_params[url] = params
