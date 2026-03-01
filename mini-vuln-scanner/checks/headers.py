"""
checks/headers.py — Passive security-header analysis module.

Examines HTTP response headers for the presence and correctness of:
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security (HSTS)
  - Referrer-Policy
  - Permissions-Policy / Feature-Policy

Each finding dict returned follows the standard schema:
    {
        "vuln_type":  str,   # e.g. "Missing Security Header"
        "severity":   str,   # "high" | "warn" | "info"
        "url":        str,
        "detail":     str,   # human-readable description
        "evidence":   str,   # raw header value or "Header absent"
    }
"""

import re
from typing import Optional

import requests


# Minimum HSTS max-age considered acceptable (1 year)
_HSTS_MIN_MAX_AGE: int = 31_536_000


def check_security_headers(url: str, response: requests.Response) -> list[dict]:
    """
    Analyse the HTTP response headers for the given URL.

    Args:
        url:      The URL that was requested.
        response: The requests.Response object from the GET request.

    Returns:
        A list of finding dicts; may be empty if all headers are present and correct.
    """
    findings: list[dict] = []
    headers = response.headers  # case-insensitive mapping

    findings.extend(_check_csp(url, headers))
    findings.extend(_check_x_frame_options(url, headers))
    findings.extend(_check_x_content_type_options(url, headers))
    findings.extend(_check_hsts(url, headers, response.url))
    findings.extend(_check_referrer_policy(url, headers))
    findings.extend(_check_permissions_policy(url, headers))
    findings.extend(_check_server_leakage(url, headers))

    return findings


# ─── Individual header checks ─────────────────────────────────────────────────

def _check_csp(url: str, headers) -> list[dict]:
    """Check for Content-Security-Policy."""
    findings = []
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        findings.append(
            _finding(
                vuln_type="Missing Header: Content-Security-Policy",
                severity="high",
                url=url,
                detail=(
                    "Content-Security-Policy (CSP) header is absent. "
                    "Without CSP, the browser cannot restrict script sources, "
                    "significantly increasing XSS risk."
                ),
                evidence="Header absent",
            )
        )
    else:
        # Warn about unsafe-inline / unsafe-eval
        if "unsafe-inline" in csp.lower():
            findings.append(
                _finding(
                    vuln_type="Weak CSP: unsafe-inline",
                    severity="warn",
                    url=url,
                    detail=(
                        "CSP includes 'unsafe-inline', which permits inline "
                        "scripts/styles and partially undermines XSS protection."
                    ),
                    evidence=csp[:300],
                )
            )
        if "unsafe-eval" in csp.lower():
            findings.append(
                _finding(
                    vuln_type="Weak CSP: unsafe-eval",
                    severity="warn",
                    url=url,
                    detail=(
                        "CSP includes 'unsafe-eval', which allows eval() and "
                        "related constructs — a common XSS bypass."
                    ),
                    evidence=csp[:300],
                )
            )
    return findings


def _check_x_frame_options(url: str, headers) -> list[dict]:
    """Check for X-Frame-Options."""
    xfo = headers.get("X-Frame-Options", "").upper()
    if not xfo:
        return [
            _finding(
                vuln_type="Missing Header: X-Frame-Options",
                severity="warn",
                url=url,
                detail=(
                    "X-Frame-Options header is absent. "
                    "The page may be embeddable in an iframe, enabling clickjacking attacks."
                ),
                evidence="Header absent",
            )
        ]
    if xfo not in ("DENY", "SAMEORIGIN"):
        return [
            _finding(
                vuln_type="Weak Header: X-Frame-Options",
                severity="warn",
                url=url,
                detail=(
                    f"X-Frame-Options is set to '{xfo}', which is non-standard. "
                    "Recommended values are DENY or SAMEORIGIN."
                ),
                evidence=xfo,
            )
        ]
    return []


def _check_x_content_type_options(url: str, headers) -> list[dict]:
    """Check for X-Content-Type-Options: nosniff."""
    xcto = headers.get("X-Content-Type-Options", "").lower()
    if "nosniff" not in xcto:
        return [
            _finding(
                vuln_type="Missing/Weak Header: X-Content-Type-Options",
                severity="warn",
                url=url,
                detail=(
                    "X-Content-Type-Options: nosniff is absent or incorrect. "
                    "This allows browsers to MIME-sniff responses, potentially "
                    "executing non-script files as scripts."
                ),
                evidence=xcto or "Header absent",
            )
        ]
    return []


def _check_hsts(url: str, headers, effective_url: str) -> list[dict]:
    """Check for Strict-Transport-Security (only meaningful for HTTPS)."""
    if not effective_url.startswith("https://"):
        return []

    hsts = headers.get("Strict-Transport-Security", "")
    if not hsts:
        return [
            _finding(
                vuln_type="Missing Header: Strict-Transport-Security",
                severity="warn",
                url=url,
                detail=(
                    "HSTS header is absent on an HTTPS response. "
                    "Without HSTS, browsers may fall back to HTTP, "
                    "enabling downgrade/MITM attacks."
                ),
                evidence="Header absent",
            )
        ]

    findings = []

    # Check max-age
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < _HSTS_MIN_MAX_AGE:
            findings.append(
                _finding(
                    vuln_type="Weak HSTS max-age",
                    severity="warn",
                    url=url,
                    detail=(
                        f"HSTS max-age is {max_age}, which is below the recommended "
                        f"minimum of {_HSTS_MIN_MAX_AGE} seconds (1 year). "
                        "Short max-age values reduce protection."
                    ),
                    evidence=hsts,
                )
            )
    else:
        findings.append(
            _finding(
                vuln_type="Invalid HSTS: missing max-age",
                severity="warn",
                url=url,
                detail="HSTS header is present but missing required max-age directive.",
                evidence=hsts,
            )
        )

    # Suggest includeSubDomains
    if "includesubdomains" not in hsts.lower():
        findings.append(
            _finding(
                vuln_type="HSTS missing includeSubDomains",
                severity="info",
                url=url,
                detail=(
                    "HSTS header does not include 'includeSubDomains'. "
                    "Subdomains remain unprotected from downgrade attacks."
                ),
                evidence=hsts,
            )
        )

    return findings


def _check_referrer_policy(url: str, headers) -> list[dict]:
    """Check for Referrer-Policy."""
    rp = headers.get("Referrer-Policy", "")
    if not rp:
        return [
            _finding(
                vuln_type="Missing Header: Referrer-Policy",
                severity="info",
                url=url,
                detail=(
                    "Referrer-Policy header is absent. "
                    "Browsers may send the full URL as a Referer to third parties, "
                    "potentially leaking sensitive URL parameters."
                ),
                evidence="Header absent",
            )
        ]
    return []


def _check_permissions_policy(url: str, headers) -> list[dict]:
    """Check for Permissions-Policy (formerly Feature-Policy)."""
    pp = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")
    if not pp:
        return [
            _finding(
                vuln_type="Missing Header: Permissions-Policy",
                severity="info",
                url=url,
                detail=(
                    "Permissions-Policy (formerly Feature-Policy) header is absent. "
                    "Consider declaring which browser features the page requires."
                ),
                evidence="Header absent",
            )
        ]
    return []


def _check_server_leakage(url: str, headers) -> list[dict]:
    """Warn if Server or X-Powered-By headers reveal technology details."""
    findings = []
    server = headers.get("Server", "")
    xpb = headers.get("X-Powered-By", "")

    if server and any(
        kw in server.lower()
        for kw in ("apache", "nginx", "iis", "lighttpd", "jetty", "gunicorn")
    ):
        findings.append(
            _finding(
                vuln_type="Server Version Disclosure",
                severity="info",
                url=url,
                detail=(
                    f"The 'Server' header exposes technology/version details: '{server}'. "
                    "This helps attackers fingerprint the stack."
                ),
                evidence=server,
            )
        )

    if xpb:
        findings.append(
            _finding(
                vuln_type="Technology Disclosure via X-Powered-By",
                severity="info",
                url=url,
                detail=(
                    f"X-Powered-By header reveals server-side technology: '{xpb}'. "
                    "Consider removing this header."
                ),
                evidence=xpb,
            )
        )

    return findings


# ─── Helper ───────────────────────────────────────────────────────────────────

def _finding(
    *,
    vuln_type: str,
    severity: str,
    url: str,
    detail: str,
    evidence: str,
) -> dict:
    """Construct a standard finding dict."""
    return {
        "vuln_type": vuln_type,
        "severity":  severity,
        "url":       url,
        "detail":    detail,
        "evidence":  evidence,
    }
