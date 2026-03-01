"""
core/utils.py — Shared utility helpers for the web vulnerability scanner.

Includes:
  - URL normalisation (remove fragments, sort query params, trailing slash)
  - Colored console output helpers (via colorama)
  - Logging setup
"""

import logging
import sys
from urllib.parse import (
    ParseResultBytes,
    urldefrag,
    urlparse,
    urlunparse,
    urlencode,
    parse_qsl,
)

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)


# ─── Logging ─────────────────────────────────────────────────────────────────

class _ColorFormatter(logging.Formatter):
    """Custom formatter that adds ANSI colors based on log level."""

    _LEVEL_COLORS: dict[int, str] = {
        logging.DEBUG:   Fore.WHITE,
        logging.INFO:    Fore.CYAN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR:   Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self._LEVEL_COLORS.get(record.levelno, "")
        levelname = f"{color}[{record.levelname}]{Style.RESET_ALL}"
        record.levelname = levelname
        return super().format(record)


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return the root scanner logger with colored console output.

    Args:
        level: logging level (e.g. logging.DEBUG or logging.INFO).

    Returns:
        Configured Logger instance.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        _ColorFormatter(
            fmt="%(levelname)s %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    log = logging.getLogger("scanner")
    log.setLevel(level)
    # Avoid duplicate handlers if called multiple times
    if not log.handlers:
        log.addHandler(handler)
    return log


# ─── URL Normalisation ────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """
    Normalize a URL by:
      - Stripping URL fragments (#anchor)
      - Removing trailing slashes from the path
      - Sorting query parameters alphabetically
      - Lowercasing the scheme and host

    Args:
        url: Raw URL string.

    Returns:
        Normalized URL string.

    Example::

        normalize_url("https://Example.COM/path/?z=1&a=2#frag")
        # → "https://example.com/path?a=2&z=1"
    """
    url, _ = urldefrag(url)  # strip fragment
    parsed = urlparse(url)

    # Lowercase scheme + netloc
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Remove trailing slash from path (but keep "/" alone)
    path = parsed.path.rstrip("/") or "/"

    # Sort query parameters
    query_pairs = sorted(parse_qsl(parsed.query))
    query = urlencode(query_pairs)

    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def same_domain(base_url: str, candidate_url: str) -> bool:
    """
    Return True if *candidate_url* belongs to the same domain (netloc) as *base_url*.

    Args:
        base_url:      The scanner's start/root URL.
        candidate_url: A URL discovered during crawling.

    Returns:
        True if both share the same netloc (ignoring port differences handled
        by the server).
    """
    base_host = urlparse(base_url).netloc.lower()
    cand_host = urlparse(candidate_url).netloc.lower()
    # Accept exact match OR subdomain
    return cand_host == base_host or cand_host.endswith("." + base_host)


def is_valid_url(url: str) -> bool:
    """
    Return True if the string is a plausible HTTP(S) URL.

    Args:
        url: String to check.

    Returns:
        True if url starts with http:// or https:// and has a non-empty netloc.
    """
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def extract_base_url(url: str) -> str:
    """
    Return the scheme + netloc portion of a URL (i.e. the origin).

    Example::

        extract_base_url("https://example.com/path?q=1")
        # → "https://example.com"
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


# ─── Console color helpers ────────────────────────────────────────────────────

def color_severity(severity: str) -> str:
    """
    Wrap a severity string in the appropriate ANSI color code.

    Args:
        severity: One of "high", "medium", "warn", "info".

    Returns:
        Colored string ready for console output.
    """
    severity = severity.lower()
    mapping: dict[str, str] = {
        "high":   Fore.RED + Style.BRIGHT,
        "medium": Fore.YELLOW + Style.BRIGHT,
        "warn":   Fore.YELLOW,
        "info":   Fore.CYAN,
    }
    color = mapping.get(severity, Fore.WHITE)
    return f"{color}{severity.upper()}{Style.RESET_ALL}"


def truncate(text: str, max_len: int = 120) -> str:
    """
    Truncate *text* to *max_len* characters, appending '…' if cut.

    Args:
        text:    Input string.
        max_len: Maximum allowed length.

    Returns:
        Possibly-truncated string.
    """
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"
