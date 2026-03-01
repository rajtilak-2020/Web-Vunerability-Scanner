"""
report/generator.py — Report generation module.

Produces:
  1. A human-readable plain-text report (always saved)
  2. An optional JSON report (when --json flag is used)

Report sections:
  - Header (target, timestamp, scan metadata)
  - Summary table of findings by severity
  - Detailed findings grouped by vuln_type
  - Disclaimer footer
"""

import json
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Optional


# Width for the text report separator lines
_LINE_WIDTH: int = 70

# Severity priority order (for sorting findings)
_SEVERITY_ORDER: dict[str, int] = {
    "high":   0,
    "medium": 1,
    "warn":   2,
    "info":   3,
}


class ReportGenerator:
    """
    Generates plain-text and JSON vulnerability scan reports.

    Args:
        target_url:    The URL that was scanned.
        findings:      List of finding dicts from the check modules.
        pages_scanned: List of URLs that were visited by the crawler.
        scan_duration: Total scan time in seconds.
    """

    def __init__(
        self,
        target_url: str,
        findings: list[dict],
        pages_scanned: list[str],
        scan_duration: float,
    ) -> None:
        self.target_url = target_url
        self.findings = sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "info").lower(), 99),
        )
        self.pages_scanned = sorted(pages_scanned)
        self.scan_duration = scan_duration
        self.generated_at = datetime.now()

    # ── Public methods ────────────────────────────────────────────────────────

    def save_text(self, output_path: str) -> None:
        """
        Write the human-readable text report to *output_path*.

        Args:
            output_path: File path for the text report.
        """
        content = self._build_text_report()
        Path(output_path).write_text(content, encoding="utf-8")

    def save_json(self, output_path: str) -> None:
        """
        Write machine-readable JSON report to *output_path*.

        Args:
            output_path: File path for the JSON report.
        """
        data = self._build_json_payload()
        Path(output_path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # ── Text report builder ───────────────────────────────────────────────────

    def _build_text_report(self) -> str:
        lines: list[str] = []

        lines.append("=" * _LINE_WIDTH)
        lines.append("  Mini Web Vulnerability Scanner — Scan Report")
        lines.append("=" * _LINE_WIDTH)
        lines.append(f"  Target    : {self.target_url}")
        lines.append(
            f"  Generated : {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        lines.append(f"  Duration  : {self.scan_duration:.1f}s")
        lines.append(f"  Pages     : {len(self.pages_scanned)}")
        lines.append(f"  Findings  : {len(self.findings)}")
        lines.append("=" * _LINE_WIDTH)
        lines.append("")

        # Disclaimer
        lines.append(_box("DISCLAIMER"))
        lines.append(
            textwrap.fill(
                "This report is produced by an EDUCATIONAL tool for AUTHORIZED "
                "security testing only.  Any use against systems without explicit "
                "written permission is illegal and unethical.  The author assumes "
                "NO responsibility for misuse.",
                width=_LINE_WIDTH,
            )
        )
        lines.append("")

        # Summary table
        lines.append(_box("FINDINGS SUMMARY"))
        severity_counts = self._severity_counts()
        lines.append(f"  {'Severity':<12} {'Count':>5}")
        lines.append(f"  {'-'*12} {'-----':>5}")
        for sev in ("high", "medium", "warn", "info"):
            count = severity_counts.get(sev, 0)
            lines.append(f"  {sev.upper():<12} {count:>5}")
        lines.append("")

        # Pages crawled
        lines.append(_box("PAGES CRAWLED"))
        for u in self.pages_scanned:
            lines.append(f"  {u}")
        lines.append("")

        # Detailed findings
        lines.append(_box("DETAILED FINDINGS"))

        if not self.findings:
            lines.append("  No findings detected.")
        else:
            for idx, finding in enumerate(self.findings, start=1):
                lines.append("")
                lines.append(
                    f"  [{idx:03d}] [{finding.get('severity', '?').upper()}] "
                    f"{finding.get('vuln_type', 'Unknown')}"
                )
                lines.append(f"  {'─' * 60}")
                lines.append(f"  URL      : {finding.get('url', '-')}")
                detail = finding.get("detail", "")
                detail_wrapped = textwrap.fill(
                    detail, width=_LINE_WIDTH, initial_indent="  Detail   : ",
                    subsequent_indent="             "
                )
                lines.append(detail_wrapped)
                evidence = finding.get("evidence", "")
                if evidence:
                    evidence_wrapped = textwrap.fill(
                        evidence, width=_LINE_WIDTH,
                        initial_indent="  Evidence : ",
                        subsequent_indent="             "
                    )
                    lines.append(evidence_wrapped)

        lines.append("")
        lines.append("=" * _LINE_WIDTH)
        lines.append(
            "  END OF REPORT — For authorized use only. Handle with care."
        )
        lines.append("=" * _LINE_WIDTH)

        return "\n".join(lines) + "\n"

    # ── JSON payload builder ──────────────────────────────────────────────────

    def _build_json_payload(self) -> dict:
        """Build the structured dict written to the JSON file."""
        return {
            "scanner": "Mini Web Vulnerability Scanner",
            "target_url": self.target_url,
            "generated_at": self.generated_at.isoformat(),
            "scan_duration_seconds": round(self.scan_duration, 2),
            "pages_scanned": self.pages_scanned,
            "summary": self._severity_counts(),
            "findings": self.findings,
            "disclaimer": (
                "This report is for authorized educational/security-testing use only. "
                "Unauthorized scanning is illegal."
            ),
        }

    # ── Helper ────────────────────────────────────────────────────────────────

    def _severity_counts(self) -> dict[str, int]:
        """Return a dict mapping severity labels → count of findings."""
        counts: dict[str, int] = {"high": 0, "medium": 0, "warn": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


# ─── Module-level helpers ─────────────────────────────────────────────────────

def _box(title: str) -> str:
    """Return a section header padded to _LINE_WIDTH."""
    return f"{'─' * 3} {title} {'─' * (_LINE_WIDTH - len(title) - 5)}"
