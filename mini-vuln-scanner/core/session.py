"""
core/session.py — requests Session with User-Agent rotation and retry logic.

Provides a SessionManager that wraps a requests.Session with:
  - Rotating User-Agent headers (from a built-in list of real browser strings)
  - Configurable custom UA override
  - Retry with exponential backoff for transient errors
  - Graceful handling of 403, 429, SSL errors, and timeouts
"""

import logging
import random
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ─── Built-in User-Agent pool ────────────────────────────────────────────────
_USER_AGENTS: list[str] = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
    # Firefox / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    # Edge / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # Chrome / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.3 Safari/605.1.15",
    # Firefox / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    # Chrome / Linux
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
    # Firefox / Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    # Opera / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0",
    # Brave / Windows (presents as Chrome)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36",
]

# Number of seconds to back off on 429 Too Many Requests
_BACK_OFF_SLEEP = 5.0
# Default request timeout (seconds)
_DEFAULT_TIMEOUT = 8


class SessionManager:
    """
    Manages an HTTP session with rotating User-Agents and automatic retries.

    Usage::

        mgr = SessionManager()
        response = mgr.get("https://example.com")
        response = mgr.post("https://example.com/form", data={"q": "test"})
    """

    def __init__(self, custom_ua: Optional[str] = None) -> None:
        """
        Initialise the session manager.

        Args:
            custom_ua: If provided, always use this User-Agent string instead
                       of rotating through the built-in list.
        """
        self._custom_ua: Optional[str] = custom_ua
        self._session: requests.Session = self._build_session()

    # ── Private helpers ──────────────────────────────────────────────────────

    def _pick_ua(self) -> str:
        """Return the next User-Agent string (custom or random)."""
        if self._custom_ua:
            return self._custom_ua
        return random.choice(_USER_AGENTS)

    @staticmethod
    def _build_session() -> requests.Session:
        """
        Create a requests.Session configured with retry / backoff adapters.

        Retries up to 3 times on connection/read errors and 500-level responses,
        with exponential backoff (0.5 s, 1 s, 2 s).
        """
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    def _headers(self) -> dict[str, str]:
        """Build request headers with a rotated User-Agent."""
        return {
            "User-Agent": self._pick_ua(),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    # ── Public request methods ───────────────────────────────────────────────

    def get(
        self,
        url: str,
        params: Optional[dict] = None,
        allow_redirects: bool = True,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> requests.Response:
        """
        Perform a GET request.

        Args:
            url:              Target URL.
            params:           Optional query-string parameters dict.
            allow_redirects:  Follow HTTP redirects (default True).
            timeout:          Socket timeout in seconds.

        Returns:
            requests.Response object.

        Raises:
            requests.RequestException on unrecoverable errors.
        """
        try:
            resp = self._session.get(
                url,
                params=params,
                headers=self._headers(),
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=True,
            )
            self._handle_rate_limit(resp)
            return resp
        except requests.exceptions.SSLError as exc:
            logger.warning(f"SSL error for {url}: {exc}")
            raise
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout reaching {url}")
            raise
        except requests.exceptions.ConnectionError as exc:
            logger.warning(f"Connection error for {url}: {exc}")
            raise

    def post(
        self,
        url: str,
        data: Optional[dict] = None,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> requests.Response:
        """
        Perform a POST request (form-encoded body).

        Args:
            url:     Target URL.
            data:    Form field dict to send as application/x-www-form-urlencoded.
            timeout: Socket timeout in seconds.

        Returns:
            requests.Response object.
        """
        try:
            resp = self._session.post(
                url,
                data=data or {},
                headers=self._headers(),
                timeout=timeout,
                allow_redirects=True,
                verify=True,
            )
            self._handle_rate_limit(resp)
            return resp
        except requests.exceptions.SSLError as exc:
            logger.warning(f"SSL error for {url}: {exc}")
            raise
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout reaching {url}")
            raise
        except requests.exceptions.ConnectionError as exc:
            logger.warning(f"Connection error for {url}: {exc}")
            raise

    @staticmethod
    def _handle_rate_limit(resp: requests.Response) -> None:
        """If we receive a 429, sleep for a bit before returning."""
        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", _BACK_OFF_SLEEP))
            logger.warning(
                f"Rate-limited (429). Sleeping {retry_after}s before continuing."
            )
            time.sleep(retry_after)
