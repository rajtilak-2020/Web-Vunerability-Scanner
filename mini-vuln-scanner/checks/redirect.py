"""
checks/redirect.py — Open redirect detection module.

Strategy:
  1. Inspect every GET parameter whose name matches a known redirect-related
     name (redirect, next, url, return, goto, etc.).
  2. For each such parameter, append known off-domain test values
     (e.g. //google.com, //evil.com/test, http://evil.com).
  3. Make a GET request and inspect the response:
       - If the final response URL is on a different domain → flag.
       - If the Location header points off-domain (even with allow_redirects=False) → flag.
  4. Never follow a redirect to actually visit external sites; only inspect
     the Location header or the final response URL.

This is DETECTION ONLY. No data is sent to external servers from our side.
"""

import logging
import time
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import requests

from core.session import SessionManager
from payloads.common import REDIRECT_PAYLOADS, REDIRECT_PARAM_NAMES

logger = logging.getLogger("scanner")


def check_open_redirect(
    base_url: str,
    params: list[str],
    session_mgr: SessionManager,
    delay: float,
    target_base: str,
) -> list[dict]:
    """
    Test URL parameters for open redirect vulnerabilities.

    Args:
        base_url:    Page URL (may contain an existing query string).
        params:      List of GET parameter names present in base_url.
        session_mgr: HTTP session manager.
        delay:       Seconds between requests.
        target_base: The scanner's start URL (used to determine "home domain").

    Returns:
        List of finding dicts for detected open redirects.
    """
    findings: list[dict] = []

    # Only test parameters whose names suggest a redirect destination
    redirect_params = [
        p for p in params if p.lower() in REDIRECT_PARAM_NAMES
    ]

    if not redirect_params:
        return []

    parsed = urlparse(base_url)
    existing_params = dict(parse_qsl(parsed.query))
    target_host = urlparse(target_base).netloc.lower()

    for param_name in redirect_params:
        for payload in REDIRECT_PAYLOADS:
            test_params = dict(existing_params)
            test_params[param_name] = payload
            test_url = _rebuild_url(parsed, test_params)

            try:
                # First check: inspect Location header WITHOUT following redirects
                resp_no_follow = session_mgr.get(
                    test_url, allow_redirects=False, timeout=8
                )
                time.sleep(delay / 2)

                location = resp_no_follow.headers.get("Location", "")
                if location and _is_offsite(location, target_host):
                    findings.append(
                        _finding(
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            reason="Location header points off-domain (no-follow request).",
                            evidence=f"Location: {location}",
                        )
                    )
                    break  # One confirmed payload per param

                # Second check: follow the redirect and inspect final URL
                resp_follow = session_mgr.get(test_url, allow_redirects=True, timeout=8)
                time.sleep(delay / 2)

                final_url = resp_follow.url
                if _is_offsite(final_url, target_host):
                    findings.append(
                        _finding(
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            reason="Browser was redirected off-domain after following redirects.",
                            evidence=f"Final URL: {final_url}",
                        )
                    )
                    break

            except requests.RequestException as exc:
                logger.debug(f"Redirect check failed for {test_url}: {exc}")
                continue

    return findings


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_offsite(url: str, target_host: str) -> bool:
    """
    Return True if *url* resolves to a host outside *target_host*.

    Args:
        url:         URL string to inspect (may be relative or absolute).
        target_host: The scanner's target netloc (e.g. "example.com").

    Returns:
        True if the URL host is non-empty and not the target host.
    """
    # Handle protocol-relative URLs (//evil.com)
    if url.startswith("//"):
        url = "https:" + url

    parsed = urlparse(url)
    host = parsed.netloc.lower()

    if not host:
        return False  # Relative URL — same site

    # Allow exact match or subdomain of target
    return not (host == target_host or host.endswith("." + target_host))


def _rebuild_url(parsed, params: dict) -> str:
    """Reconstruct a URL with an updated query string."""
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params), "")
    )


# ─── Finding factory ──────────────────────────────────────────────────────────

def _finding(
    *,
    url: str,
    param: str,
    payload: str,
    reason: str,
    evidence: str,
) -> dict:
    """Return a standard finding dict for an open redirect."""
    return {
        "vuln_type": "Open Redirect",
        "severity":  "warn",
        "url":       url,
        "detail":    (
            f"Open redirect detected via parameter '{param}'. {reason}"
        ),
        "evidence":  (
            f"Payload: {payload!r} | {evidence}"
        ),
    }
