"""
checks/csrf.py — CSRF token absence heuristic for POST forms.

Methodology (passive / heuristic):
  For every POST form discovered by the crawler:
    1. Look for a hidden input whose name contains a known CSRF token pattern
       (e.g. csrf, token, nonce, xsrf, authenticity, etc.)
    2. If found, check that the value looks sufficiently random:
         - Length > 15 characters
         - Contains a mix of letters, digits, or symbols
    3. If NO likely token field is found, flag the form as
       "Potentially Vulnerable to CSRF" (severity: warn).
    4. If a token field is found but the value looks weak/static, issue an
       informational note.

Severity:
  - "warn"  → no token found at all
  - "info"  → token present but value looks weak (short or non-random)
"""

import re
import string

from payloads.common import CSRF_TOKEN_PATTERNS

# Minimum token value length to be considered non-trivial
_MIN_TOKEN_LENGTH: int = 15

# A "random-looking" value should contain characters from at least 2 of:
#   uppercase letters, lowercase letters, digits, special chars
_CHARSET_GROUPS: list[frozenset[str]] = [
    frozenset(string.ascii_uppercase),
    frozenset(string.ascii_lowercase),
    frozenset(string.digits),
    frozenset(string.punctuation),
]


def check_csrf(page_url: str, post_forms: list[dict]) -> list[dict]:
    """
    Run CSRF heuristic checks on a list of POST forms from a single page.

    Args:
        page_url:   URL of the page that contains the forms.
        post_forms: List of form descriptor dicts (from the crawler),
                    pre-filtered to method == POST.

    Returns:
        List of finding dicts; may be empty if all forms appear protected.
    """
    findings: list[dict] = []

    for form in post_forms:
        result = _check_form_csrf(page_url, form)
        if result:
            findings.append(result)

    return findings


# ─── Per-form check ───────────────────────────────────────────────────────────

def _check_form_csrf(page_url: str, form: dict) -> dict | None:
    """
    Inspect a single POST form for a likely CSRF protection token.

    Args:
        page_url: URL of the page containing the form.
        form:     Form descriptor from the crawler.

    Returns:
        A finding dict if the form appears unprotected, else None.
    """
    action_url = form.get("action", page_url)
    inputs = form.get("inputs", [])

    # Identify candidate token fields (hidden inputs with matching names)
    token_candidates = [
        inp
        for inp in inputs
        if inp.get("type", "").lower() in ("hidden", "text", "")
        and _name_looks_like_csrf_token(inp.get("name", ""))
    ]

    # No token field found at all → likely vulnerable
    if not token_candidates:
        input_names = [inp.get("name", "?") for inp in inputs]
        return {
            "vuln_type": "Potential CSRF Vulnerability",
            "severity":  "warn",
            "url":       page_url,
            "detail":    (
                f"POST form (action: '{action_url}') has no detectable CSRF token "
                f"field. Without a secret token validated server-side, authenticated "
                f"users may be tricked into submitting unintended requests."
            ),
            "evidence":  (
                f"Form inputs found: {input_names}"
                if input_names
                else "No form inputs found at all."
            ),
        }

    # Token field found — validate its value
    for candidate in token_candidates:
        value: str = candidate.get("value", "")
        if _value_looks_random(value):
            # Looks properly protected — no finding
            return None

    # Token field present but value is weak / empty / static
    return {
        "vuln_type": "Weak CSRF Token",
        "severity":  "info",
        "url":       page_url,
        "detail":    (
            f"POST form (action: '{action_url}') has a field that resembles a "
            f"CSRF token (name: '{token_candidates[0]['name']}') but the value "
            f"looks weak, empty, or static. Verify it is truly random and "
            f"validated server-side."
        ),
        "evidence":  (
            f"Field name: '{token_candidates[0]['name']}', "
            f"value: '{token_candidates[0].get('value', '')}'"
        ),
    }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _name_looks_like_csrf_token(name: str) -> bool:
    """
    Return True if the input's *name* attribute contains a CSRF-related keyword.

    Args:
        name: The input field name.

    Returns:
        True if a CSRF_TOKEN_PATTERN matches (case-insensitive).
    """
    name_lower = name.lower()
    return any(pattern in name_lower for pattern in CSRF_TOKEN_PATTERNS)


def _value_looks_random(value: str) -> bool:
    """
    Heuristically determine whether *value* looks like a random token.

    Criteria:
      - Length > _MIN_TOKEN_LENGTH
      - Characters span at least 2 different charset groups

    Args:
        value: The field's current value string.

    Returns:
        True if the value appears sufficiently random.
    """
    if len(value) <= _MIN_TOKEN_LENGTH:
        return False

    groups_present = sum(
        1 for group in _CHARSET_GROUPS if any(ch in group for ch in value)
    )
    return groups_present >= 2
