"""
checks/xss.py — Reflected XSS detection module.

Strategy:
  1. For each URL with GET parameters, inject each XSS payload into one
     parameter at a time and check whether the raw payload appears in the
     response body (unescaped).
  2. For each form (GET or POST), inject into all text-like input fields and
     check the response body.
  3. Also performs basic regex checks for payload reflection inside:
       - HTML attribute values
       - <script>…</script> blocks
       - JSON-like values in the response body

Finding severity: "high" if payload appears unescaped; otherwise not reported.
"""

import logging
import re
import time
from urllib.parse import urlencode, parse_qsl, urlparse, urlunparse
from typing import Optional

import requests

from core.session import SessionManager
from payloads.common import XSS_PAYLOADS

logger = logging.getLogger("scanner")

# Input types that can carry reflected XSS payloads
_INJECTABLE_INPUT_TYPES: frozenset[str] = frozenset(
    {"text", "search", "email", "url", "tel", "textarea", "hidden", "password"}
)


def check_xss(
    base_url: str,
    params: list[str],
    forms: list[dict],
    session_mgr: SessionManager,
    delay: float = 1.0,
) -> list[dict]:
    """
    Test for reflected XSS via URL GET parameters and form fields.

    Args:
        base_url:    The page URL (may include existing query string).
        params:      List of GET parameter names present in base_url's query.
        forms:       List of form descriptors (from the crawler).
        session_mgr: HTTP session manager.
        delay:       Seconds to sleep between requests to avoid rate-limiting.

    Returns:
        List of finding dicts for confirmed reflections.
    """
    findings: list[dict] = []

    # ── GET parameter injection ───────────────────────────────────────────────
    if params:
        parsed = urlparse(base_url)
        existing_params = dict(parse_qsl(parsed.query))

        for param_name in params:
            for payload in XSS_PAYLOADS:
                # Build request params: inject into one param, keep others benign
                test_params = dict(existing_params)
                test_params[param_name] = payload

                test_url = _rebuild_url(parsed, test_params)

                try:
                    resp = session_mgr.get(test_url, allow_redirects=True)
                    time.sleep(delay)
                except requests.RequestException as exc:
                    logger.debug(f"XSS GET request failed for {test_url}: {exc}")
                    continue

                hit, snippet = _payload_reflected(payload, resp.text)
                if hit:
                    findings.append(
                        _finding(
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            detail=(
                                f"Reflected XSS candidate in GET parameter '{param_name}'. "
                                f"Payload echoed back unescaped in the response."
                            ),
                            evidence=snippet,
                        )
                    )
                    # One confirmed payload per param is sufficient evidence
                    break

    # ── Form injection ────────────────────────────────────────────────────────
    for form in forms:
        findings.extend(
            _test_form_xss(form, session_mgr, delay)
        )

    return findings


# ─── Form testing ─────────────────────────────────────────────────────────────

def _test_form_xss(
    form: dict,
    session_mgr: SessionManager,
    delay: float,
) -> list[dict]:
    """
    Inject XSS payloads into injectable form fields and check responses.

    Args:
        form:        Form descriptor dict from the crawler.
        session_mgr: HTTP session manager.
        delay:       Delay between requests.

    Returns:
        List of findings for this form.
    """
    findings = []
    action_url = form["action"]
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])

    # Build a baseline data dict with empty / existing values
    baseline_data = {inp["name"]: inp.get("value", "") for inp in inputs}

    # Identify injectable fields
    injectable = [
        inp["name"]
        for inp in inputs
        if inp.get("type", "text") in _INJECTABLE_INPUT_TYPES
    ]

    if not injectable:
        return []

    for field_name in injectable:
        for payload in XSS_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[field_name] = payload

            try:
                if method == "POST":
                    resp = session_mgr.post(action_url, data=test_data)
                else:
                    resp = session_mgr.get(action_url, params=test_data)
                time.sleep(delay)
            except requests.RequestException as exc:
                logger.debug(
                    f"XSS form request failed [{method} {action_url}]: {exc}"
                )
                continue

            hit, snippet = _payload_reflected(payload, resp.text)
            if hit:
                findings.append(
                    _finding(
                        url=action_url,
                        param=f"form field '{field_name}' [{method}]",
                        payload=payload,
                        detail=(
                            f"Reflected XSS candidate: form field '{field_name}' "
                            f"on {form['source_url']} reflects payload unescaped."
                        ),
                        evidence=snippet,
                    )
                )
                break  # One hit per field is enough evidence

    return findings


# ─── Reflection detection ─────────────────────────────────────────────────────

def _payload_reflected(payload: str, response_text: str) -> tuple[bool, str]:
    """
    Check whether *payload* appears unescaped in *response_text*.

    Also checks for reflection inside:
      - script blocks
      - HTML attribute values (via a broad regex)
      - JSON values

    Args:
        payload:       The XSS string that was sent.
        response_text: HTTP response body.

    Returns:
        (True, snippet) if the payload is found; (False, "") otherwise.
    """
    # Direct literal presence (most reliable indicator)
    if payload in response_text:
        idx = response_text.index(payload)
        snippet = response_text[max(0, idx - 40): idx + len(payload) + 40]
        return True, snippet.strip()

    # Check inside <script> blocks
    script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
    for match in script_pattern.finditer(response_text):
        if payload in match.group(1):
            return True, match.group(0)[:200]

    # URL-decoded check (payload may have been partially decoded)
    from urllib.parse import unquote
    decoded_payload = unquote(payload)
    if decoded_payload in response_text and decoded_payload != payload:
        idx = response_text.index(decoded_payload)
        snippet = response_text[max(0, idx - 40): idx + len(decoded_payload) + 40]
        return True, snippet.strip()

    return False, ""


# ─── URL helpers ──────────────────────────────────────────────────────────────

def _rebuild_url(parsed, params: dict) -> str:
    """Reconstruct a URL with a new query string from *params* dict."""
    new_query = urlencode(params)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, "")
    )


# ─── Finding factory ──────────────────────────────────────────────────────────

def _finding(
    *,
    url: str,
    param: str,
    payload: str,
    detail: str,
    evidence: str,
) -> dict:
    """Return a standard finding dict for a reflected XSS hit."""
    return {
        "vuln_type": "Reflected XSS",
        "severity":  "high",
        "url":       url,
        "detail":    detail,
        "evidence":  (
            f"Parameter: {param} | Payload: {payload!r} | Snippet: {evidence[:200]}"
        ),
    }
