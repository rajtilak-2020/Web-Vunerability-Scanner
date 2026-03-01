#!/usr/bin/env python3
"""
HOW TO RUN (important!):
  1. Open a terminal (PowerShell / cmd / bash)
  2. cd into the mini-vuln-scanner folder
  3. Install dependencies (one-time):
       pip install requests beautifulsoup4 colorama
  4. Run the scanner:
       python scanner.py --url https://example.com --depth 2

  ⚠️  Do NOT run `python -m http.server` — that only shows your files
       in a browser; it is NOT this scanner!

  Safe targets to test on (you already have permission):
    http://testphp.vulnweb.com        (Acunetix demo site)
    https://httpbin.org               (echo / reflect service)
    Your own locally hosted pages
"""

# ──────────────────────────────────────────────────────────────────────────────
# scanner.py — Mini Web Vulnerability Scanner
# Main CLI entry point.  No HTTP server is started here — all output goes
# to the terminal only.
# ──────────────────────────────────────────────────────────────────────────────

import argparse
import sys
import time
import logging
from datetime import datetime
from pathlib import Path

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    # Graceful fallback — colorama is optional at import time
    class Fore:       # type: ignore[no-redef]
        RED = YELLOW = CYAN = WHITE = GREEN = ""
    class Style:      # type: ignore[no-redef]
        BRIGHT = RESET_ALL = ""
    _HAS_COLOR = False

from core.crawler import Crawler
from core.session import SessionManager
from core.utils import normalize_url, setup_logging
from checks.headers import check_security_headers
from checks.xss import check_xss
from checks.sqli import check_sqli
from checks.csrf import check_csrf
from checks.redirect import check_open_redirect
from report.generator import ReportGenerator


# ─── Ethical / legal warning ──────────────────────────────────────────────────

_BANNER = f"""
{Fore.RED}{Style.BRIGHT}
┌─────────────────────────────────────────────────────────────┐
│  WARNING – LEGAL & ETHICAL NOTICE                           │
│  This tool is STRICTLY for EDUCATIONAL PURPOSES and for use │
│  ONLY on targets you OWN or have EXPLICIT WRITTEN PERMISSION│
│  to test. Unauthorized scanning is illegal in most countries│
│  (including under CFAA, Computer Misuse Act, etc.).         │
│  The author assumes NO responsibility for misuse.           │
└─────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}"""


def print_banner() -> None:
    """Print the ethical warning and block until the user presses ENTER."""
    print(_BANNER)
    print(
        f"  {Fore.YELLOW}Press {Fore.WHITE}{Style.BRIGHT}ENTER{Style.RESET_ALL}"
        f"{Fore.YELLOW} to continue IF you own or have permission to test the"
        f" target, or {Fore.RED}Ctrl+C{Fore.YELLOW} to abort.{Style.RESET_ALL}\n"
    )
    try:
        input()
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}Aborted. Goodbye.{Style.RESET_ALL}")
        sys.exit(0)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Mini Web Vulnerability Scanner (terminal-only, educational).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scanner.py --url http://testphp.vulnweb.com --depth 2\n"
            "  python scanner.py --url https://example.com --depth 1 --json --verbose\n"
        ),
    )
    parser.add_argument("--url",   required=True, metavar="TARGET_URL",
                        help="Target URL to scan (full URL with scheme).")
    parser.add_argument("--depth", type=int, default=2,
                        choices=range(1, 5), metavar="INT(1-4)",
                        help="Crawl depth limit (default: 2, max: 4).")
    parser.add_argument("--delay", type=float, default=1.5, metavar="FLOAT",
                        help="Seconds between requests (default: 1.5).")
    parser.add_argument("--user-agent", dest="user_agent", default=None,
                        metavar="STR",
                        help="Custom User-Agent (default: rotate built-in list).")
    parser.add_argument("--verbose", action="store_true",
                        help="Show debug-level output.")
    parser.add_argument("--output", default=None, metavar="PATH",
                        help="Text report output path (default: auto-timestamped).")
    parser.add_argument("--json", action="store_true", dest="save_json",
                        help="Also write findings as a .json file.")
    return parser


def validate_args(args: argparse.Namespace) -> argparse.Namespace:
    args.url = normalize_url(args.url)
    args.depth = min(args.depth, 4)
    if args.output is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"vuln_report_{ts}.txt"
    return args


# ─── Scan orchestration ────────────────────────────────────────────────────────

def _cprint(msg: str, color: str = "") -> None:
    """Print a colored line to the terminal (stdout)."""
    print(f"{color}{msg}{Style.RESET_ALL}")


def run_checks(
    crawler: Crawler,
    session_mgr: SessionManager,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> list[dict]:
    """Run all vulnerability modules over the crawled pages and forms."""
    findings: list[dict] = []
    pages     = list(crawler.visited_urls)
    forms     = crawler.collected_forms
    get_params = crawler.collected_get_params
    total     = len(pages)

    _cprint(
        f"\n[*] Running checks on {total} page(s) and {len(forms)} form(s)…",
        Fore.CYAN,
    )

    for idx, page_url in enumerate(pages, 1):
        _cprint(f"\n[{idx}/{total}] Checking: {page_url}", Fore.WHITE + Style.BRIGHT)

        # ── A: Security Headers ───────────────────────────────────────────
        try:
            resp = session_mgr.get(page_url)
            hdr_findings = check_security_headers(page_url, resp)
            for f in hdr_findings:
                sev_col = Fore.RED if f["severity"] == "high" else Fore.YELLOW
                _cprint(
                    f"  [HEADER] {f['severity'].upper()}: {f['detail'][:90]}",
                    sev_col,
                )
            findings.extend(hdr_findings)
            time.sleep(args.delay)
        except Exception as exc:
            _cprint(f"  [!] Header check error on {page_url}: {exc}", Fore.YELLOW)

        page_get = get_params.get(page_url, [])
        page_forms = [f for f in forms if f["source_url"] == page_url]
        post_forms  = [f for f in page_forms if f.get("method", "GET").upper() == "POST"]

        # ── B: XSS ────────────────────────────────────────────────────────
        if page_get or page_forms:
            _cprint(
                f"  [XSS]  Testing {len(page_get)} GET param(s) + "
                f"{len(page_forms)} form(s)…",
                Fore.CYAN,
            )
            try:
                xss = check_xss(page_url, page_get, page_forms, session_mgr, args.delay)
                for f in xss:
                    _cprint(f"  [XSS] 🔴 POTENTIAL FINDING: {f['detail'][:100]}", Fore.RED + Style.BRIGHT)
                findings.extend(xss)
            except Exception as exc:
                _cprint(f"  [!] XSS check error: {exc}", Fore.YELLOW)

        # ── C: SQLi ───────────────────────────────────────────────────────
        if page_get or page_forms:
            _cprint(
                f"  [SQLi] Testing {len(page_get)} GET param(s) + "
                f"{len(page_forms)} form(s)…",
                Fore.CYAN,
            )
            try:
                sqli = check_sqli(page_url, page_get, page_forms, session_mgr, args.delay)
                for f in sqli:
                    sev_col = Fore.RED if f["severity"] == "high" else Fore.YELLOW
                    _cprint(f"  [SQLi] {f['severity'].upper()}: {f['detail'][:100]}", sev_col)
                findings.extend(sqli)
            except Exception as exc:
                _cprint(f"  [!] SQLi check error: {exc}", Fore.YELLOW)

        # ── D: CSRF ───────────────────────────────────────────────────────
        if post_forms:
            _cprint(f"  [CSRF] Checking {len(post_forms)} POST form(s)…", Fore.CYAN)
            try:
                csrf = check_csrf(page_url, post_forms)
                for f in csrf:
                    _cprint(f"  [CSRF] {f['severity'].upper()}: {f['detail'][:100]}", Fore.YELLOW)
                findings.extend(csrf)
            except Exception as exc:
                _cprint(f"  [!] CSRF check error: {exc}", Fore.YELLOW)

        # ── E: Open Redirect ──────────────────────────────────────────────
        if page_get:
            _cprint(f"  [REDIR] Checking {len(page_get)} GET param(s) for open redirects…", Fore.CYAN)
            try:
                redir = check_open_redirect(page_url, page_get, session_mgr, args.delay, args.url)
                for f in redir:
                    _cprint(f"  [REDIR] {f['severity'].upper()}: {f['detail'][:100]}", Fore.YELLOW)
                findings.extend(redir)
            except Exception as exc:
                _cprint(f"  [!] Redirect check error: {exc}", Fore.YELLOW)

    return findings


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    print_banner()

    parser = build_parser()
    args   = parser.parse_args()
    args   = validate_args(args)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger    = setup_logging(log_level)

    _cprint(
        f"\n{'='*62}\n"
        f"  Mini Web Vulnerability Scanner\n"
        f"  Target : {args.url}\n"
        f"  Depth  : {args.depth}  |  Delay: {args.delay}s  |  Verbose: {args.verbose}\n"
        f"{'='*62}",
        Fore.WHITE + Style.BRIGHT,
    )

    # Build HTTP session
    session_mgr = SessionManager(custom_ua=args.user_agent)

    # ── Phase 1: Crawl ────────────────────────────────────────────────────
    _cprint(f"\n[PHASE 1] Starting crawl from: {args.url}", Fore.CYAN + Style.BRIGHT)
    crawler = Crawler(
        start_url=args.url,
        max_depth=args.depth,
        delay=args.delay,
        session_mgr=session_mgr,
        logger=logger,
    )
    try:
        crawler.crawl()
    except KeyboardInterrupt:
        _cprint("\n[!] Crawl interrupted by user. Continuing with partial results.", Fore.YELLOW)
    except Exception as exc:
        _cprint(f"\n[!] Crawl failed unexpectedly: {exc}", Fore.RED)
        _cprint("    Continuing with whatever pages were collected.", Fore.YELLOW)

    _cprint(
        f"\n[+] Crawl done → {len(crawler.visited_urls)} page(s) | "
        f"{len(crawler.collected_forms)} form(s) | "
        f"{sum(len(v) for v in crawler.collected_get_params.values())} GET param(s)",
        Fore.GREEN,
    )

    if not crawler.visited_urls:
        _cprint("[!] No pages were successfully crawled. Nothing to check. Exiting.", Fore.RED)
        sys.exit(1)

    # ── Phase 2: Vulnerability checks ────────────────────────────────────
    _cprint(f"\n[PHASE 2] Running vulnerability checks…", Fore.CYAN + Style.BRIGHT)
    scan_start = time.time()
    findings   = run_checks(crawler, session_mgr, args, logger)
    duration   = time.time() - scan_start

    # ── Phase 3: Report ───────────────────────────────────────────────────
    _cprint(f"\n[PHASE 3] Generating report → {args.output}", Fore.CYAN + Style.BRIGHT)
    reporter = ReportGenerator(
        target_url=args.url,
        findings=findings,
        pages_scanned=list(crawler.visited_urls),
        scan_duration=duration,
    )
    try:
        reporter.save_text(args.output)
        _cprint(f"[+] Text report saved: {args.output}", Fore.GREEN)
    except OSError as exc:
        _cprint(f"[!] Could not save text report: {exc}", Fore.RED)

    if args.save_json:
        json_path = str(Path(args.output).with_suffix(".json"))
        try:
            reporter.save_json(json_path)
            _cprint(f"[+] JSON report saved: {json_path}", Fore.GREEN)
        except OSError as exc:
            _cprint(f"[!] Could not save JSON report: {exc}", Fore.RED)

    # ── Console summary ───────────────────────────────────────────────────
    sev = {"high": 0, "warn": 0, "info": 0}
    for f in findings:
        k = f.get("severity", "info").lower()
        sev[k] = sev.get(k, 0) + 1

    print(
        f"\n{Fore.WHITE}{Style.BRIGHT}"
        f"{'='*62}\n"
        f"  SCAN COMPLETE\n"
        f"  Pages  : {len(crawler.visited_urls)}\n"
        f"  Total  : {len(findings)} finding(s)\n"
        f"  {Fore.RED}High: {sev['high']}{Style.RESET_ALL}  "
        f"{Fore.YELLOW}Warn: {sev['warn']}{Style.RESET_ALL}  "
        f"{Fore.CYAN}Info: {sev.get('info',0)}{Style.RESET_ALL}\n"
        f"  Duration: {duration:.1f}s\n"
        f"{Fore.WHITE}{Style.BRIGHT}{'='*62}{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    main()
