"""
payloads/common.py — Safe, educational test payloads for vulnerability scanning.

All payloads in this file are SAFE and NON-DESTRUCTIVE:
  - They do NOT extract or exfiltrate data
  - They do NOT execute server-side code
  - They are designed ONLY to trigger detectable client-side or error responses
  - They MUST NOT be used against systems without explicit written permission

DISCLAIMER: These payloads are included solely for educational purposes and for
authorized security testing.  Misuse is a criminal offense in most jurisdictions.
"""

from typing import Final


# ─── Reflected XSS Payloads ──────────────────────────────────────────────────
# Each payload, if reflected UNESCAPED in an HTML response, indicates a potential
# reflected Cross-Site Scripting vulnerability.
# None of these actually execute in the scanner's context; they are sent as
# strings and we merely check whether the server echoes them back verbatim.

XSS_PAYLOADS: Final[list[str]] = [
    # Classic script injection via attribute break-out
    '"><script>alert(1)</script>',
    # img tag with onerror event via single-quote attribute break-out
    "'><img src=x onerror=alert(1)>",
    # SVG onload vector
    '"><svg/onload=alert(1)>',
    # javascript: URI (tests href/src attribute reflection)
    "jaVasCript:alert(1)",
    # img src with javascript: protocol
    '<img src="javascript:alert(1)">',
    # Simple angle-bracket injection for weak sanitisers
    "<script>alert(1)</script>",
    # Double-encoded angle bracket (bypasses some naive filters)
    "%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
]

# ─── SQL Injection Detection Payloads ────────────────────────────────────────
# These payloads are designed to trigger SQL SYNTAX ERRORS in the server response
# so we can detect the presence of a SQL injection point heuristically.
# They do NOT attempt data extraction, blind injection, or time-based attacks.

SQLI_PAYLOADS: Final[list[str]] = [
    # Single quote — most fundamental SQL error trigger
    "'",
    # Escaped single quote — tests whether doubling prevents errors
    "''",
    # Classic tautology — may trigger boolean-based behavior
    "' OR '1'='1",
    # ORDER BY with impossible column count — triggers an error in most DBMS
    "1' ORDER BY 999--",
    # HAVING without GROUP BY — another common error trigger
    "1' HAVING 1=1--",
]

# SQL error keywords that suggest the database returned an error message.
# Detection of ANY of these strings (case-insensitive) in a response body
# indicates a potential error-based SQLi.
SQLI_ERROR_SIGNATURES: Final[list[str]] = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "warning: mysql",
    # Generic SQL
    "sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    # Oracle
    "ora-",
    "oracle error",
    # PostgreSQL
    "psql error",
    "pg_query",
    "postgresql",
    # SQLite
    "sqlite",
    "sqlite_step",
    "sqlite_exec",
    # MSSQL
    "microsoft ole db provider for sql server",
    "mssql",
    "odbc microsoft access",
    "jet database engine",
    # Generic DB keywords in errors
    "query failed",
    "db error",
    "database error",
    "sql command not properly ended",
]

# ─── Open Redirect Test Payloads ─────────────────────────────────────────────
# These URLs are appended to redirect-susceptible parameters to check whether
# the server follows an off-domain redirect.
# We only check the Location header — we do NOT actually follow external links.

REDIRECT_PAYLOADS: Final[list[str]] = [
    "//google.com",
    "//evil.com/test",
    "http://evil.com",
    "https://evil.com",
    "/\\evil.com",          # backslash bypass
    "//evil%2ecom",        # dot-encoded bypass
]

# Parameter names that commonly hold redirect targets.
REDIRECT_PARAM_NAMES: Final[list[str]] = [
    "redirect",
    "next",
    "url",
    "return",
    "return_to",
    "returnto",
    "goto",
    "destination",
    "dest",
    "forward",
    "continue",
    "redirect_uri",
    "redirect_url",
    "redir",
    "location",
    "target",
    "link",
    "back",
]

# ─── CSRF Token Field Name Patterns ──────────────────────────────────────────
# A POST form is considered (potentially) CSRF-protected if it contains a hidden
# field whose name matches one of these substrings (case-insensitive).

CSRF_TOKEN_PATTERNS: Final[list[str]] = [
    "csrf",
    "token",
    "_csrf",
    "authenticity",
    "nonce",
    "xsrf",
    "anti-csrf",
    "anticsrf",
    "__requestverificationtoken",
    "verification",
    "_token",
    "form_key",
    "formkey",
]
