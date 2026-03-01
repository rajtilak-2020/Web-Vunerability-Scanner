"""
checks/sqli.py — Conservative error-based SQL injection detection.

Strategy (non-destructive):
  1. For each URL GET parameter, send payloads one at a time.
  2. Compare the response to the baseline:
       - SQL error keyword present in body → flag
       - HTTP 500 when baseline was 200 → flag
       - Large content-length difference (>3x) → flag as "anomaly"
  3. For forms (GET and POST), inject into text-like fields similarly.

What this module does NOT do:
  - Blind / time-based injection
  - UNION-based data extraction
  - Stacked queries
  - Any attempt to modify or extract data
"""

import logging
import time
from urllib.parse import urlencode, parse_qsl, urlparse, urlunparse

import requests

from core.session import SessionManager
from payloads.common import SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES

logger = logging.getLogger("scanner")

# Input types considered injectable in forms
_INJECTABLE_INPUT_TYPES: frozenset[str] = frozenset(
    {"text", "search", "email", "url", "tel", "number", "hidden", "textarea"}
)

# Minimum body size ratio to flag as anomalous (baseline vs. payload response)
_CONTENT_DIFF_RATIO: float = 3.0


def check_sqli(
    base_url: str,
    params: list[str],
    forms: list[dict],
    session_mgr: SessionManager,
    delay: float = 1.0,
) -> list[dict]:
    """
    Detect potential error-based SQL injection points.

    Args:
        base_url:    Page URL (may include existing query string).
        params:      GET parameter names present in base_url.
        forms:       Form descriptors from the crawler.
        session_mgr: HTTP session manager.
        delay:       Seconds between requests.

    Returns:
        List of finding dicts for detected anomalies.
    """
    findings: list[dict] = []

    # ── GET parameter testing ────────────────────────────────────────────────
    if params:
        parsed = urlparse(base_url)
        existing_params = dict(parse_qsl(parsed.query))

        for param_name in params:
            # Fetch baseline response with the original param value
            baseline_status, baseline_len = _baseline(
                parsed, existing_params, session_mgr
            )
            time.sleep(delay)

            for payload in SQLI_PAYLOADS:
                test_params = dict(existing_params)
                test_params[param_name] = payload
                test_url = _rebuild_url(parsed, test_params)

                try:
                    resp = session_mgr.get(test_url)
                    time.sleep(delay)
                except requests.RequestException as exc:
                    logger.debug(f"SQLi GET request failed {test_url}: {exc}")
                    continue

                finding = _analyse(
                    url=test_url,
                    param=param_name,
                    payload=payload,
                    resp=resp,
                    baseline_status=baseline_status,
                    baseline_len=baseline_len,
                )
                if finding:
                    findings.append(finding)
                    break  # One confirmed payload per param is enough

    # ── Form testing ──────────────────────────────────────────────────────────
    for form in forms:
        findings.extend(_test_form_sqli(form, session_mgr, delay))

    return findings


# ─── Form testing ─────────────────────────────────────────────────────────────

def _test_form_sqli(
    form: dict,
    session_mgr: SessionManager,
    delay: float,
) -> list[dict]:
    """Test each injectable form field for SQLi error signatures."""
    findings = []
    action_url = form["action"]
    method = form.get("method", "GET").upper()
    inputs = form.get("inputs", [])

    baseline_data = {inp["name"]: inp.get("value", "") for inp in inputs}
    injectable = [
        inp["name"]
        for inp in inputs
        if inp.get("type", "text") in _INJECTABLE_INPUT_TYPES
    ]

    if not injectable:
        return []

    # Baseline request
    try:
        if method == "POST":
            b_resp = session_mgr.post(action_url, data=baseline_data)
        else:
            b_resp = session_mgr.get(action_url, params=baseline_data)
        baseline_status = b_resp.status_code
        baseline_len = len(b_resp.text)
        time.sleep(delay)
    except requests.RequestException:
        return []

    for field_name in injectable:
        for payload in SQLI_PAYLOADS:
            test_data = dict(baseline_data)
            test_data[field_name] = payload

            try:
                if method == "POST":
                    resp = session_mgr.post(action_url, data=test_data)
                else:
                    resp = session_mgr.get(action_url, params=test_data)
                time.sleep(delay)
            except requests.RequestException as exc:
                logger.debug(f"SQLi form request failed: {exc}")
                continue

            finding = _analyse(
                url=action_url,
                param=f"form field '{field_name}' [{method}]",
                payload=payload,
                resp=resp,
                baseline_status=baseline_status,
                baseline_len=baseline_len,
            )
            if finding:
                findings.append(finding)
                break

    return findings


# ─── Response analysis ────────────────────────────────────────────────────────

def _analyse(
    url: str,
    param: str,
    payload: str,
    resp: requests.Response,
    baseline_status: int,
    baseline_len: int,
) -> dict | None:
    """
    Determine whether a SQLi response signals a vulnerability.

    Checks (in priority order):
      1. SQL error keyword in response body
      2. HTTP 500 (server error) when baseline was success (200)
      3. Anomalous content-length change (>3×)

    Returns a finding dict or None.
    """
    body_lower = resp.text.lower()

    # 1. SQL error signature
    for sig in SQLI_ERROR_SIGNATURES:
        if sig in body_lower:
            snippet = _extract_snippet(resp.text, sig)
            return _finding(
                url=url,
                param=param,
                payload=payload,
                reason=f"SQL error keyword detected: '{sig}'",
                evidence=snippet,
                severity="high",
            )

    # 2. HTTP 500 when baseline was 200
    if baseline_status == 200 and resp.status_code == 500:
        return _finding(
            url=url,
            param=param,
            payload=payload,
            reason=(
                "Server returned HTTP 500 (server error) with SQLi payload "
                "while baseline returned HTTP 200."
            ),
            evidence=f"Status: {resp.status_code}",
            severity="warn",
        )

    # 3. Large content-length difference
    if baseline_len > 0:
        ratio = max(len(resp.text), baseline_len) / min(len(resp.text), baseline_len)
        if ratio >= _CONTENT_DIFF_RATIO:
            return _finding(
                url=url,
                param=param,
                payload=payload,
                reason=(
                    f"Anomalous content-length change with SQLi payload "
                    f"(baseline: {baseline_len}B, payload: {len(resp.text)}B, "
                    f"ratio: {ratio:.1f}×)."
                ),
                evidence=f"Length delta: {abs(len(resp.text) - baseline_len)}B",
                severity="info",
            )

    return None


def _extract_snippet(text: str, keyword: str) -> str:
    """Return up to 160 chars centred on *keyword* in *text*."""
    lower = text.lower()
    idx = lower.find(keyword)
    if idx == -1:
        return ""
    start = max(0, idx - 60)
    end = min(len(text), idx + len(keyword) + 100)
    return text[start:end].strip()


# ─── URL helpers ──────────────────────────────────────────────────────────────

def _rebuild_url(parsed, params: dict) -> str:
    """Reconstruct a URL with a new query string."""
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params), "")
    )


def _baseline(parsed, existing_params: dict, session_mgr: SessionManager) -> tuple[int, int]:
    """Fetch the baseline (unmodified) response and return (status, body_len)."""
    baseline_url = _rebuild_url(parsed, existing_params)
    try:
        resp = session_mgr.get(baseline_url)
        return resp.status_code, len(resp.text)
    except requests.RequestException:
        return 200, 0  # Assume success if baseline fails


# ─── Finding factory ──────────────────────────────────────────────────────────

def _finding(
    *,
    url: str,
    param: str,
    payload: str,
    reason: str,
    evidence: str,
    severity: str,
) -> dict:
    """Return a standard finding dict for an SQLi signal."""
    return {
        "vuln_type": "Potential SQL Injection (error-based)",
        "severity":  severity,
        "url":       url,
        "detail":    (
            f"SQLi signal in parameter '{param}'. {reason}"
        ),
        "evidence":  (
            f"Payload: {payload!r} | {evidence[:300]}"
        ),
    }
