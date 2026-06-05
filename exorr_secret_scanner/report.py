"""Report generator for secret scanner findings."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .scanner import ScanResult


class SecretReportGenerator:
    """Generate reports from secret scan results."""

    def __init__(self, result: ScanResult, format: str = "json"):
        self.result = result
        self.format = format

    def _to_json(self) -> str:
        return json.dumps({
            "scanner": "exorr-secret-scanner",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": self.result.to_dict(),
        }, indent=2, default=str)

    def _to_markdown(self) -> str:
        d = self.result.to_dict()
        lines = [
            "# EXORR Secret Scanner Report",
            "",
            f"**Target:** `{d['target']}`  ",
            f"**Date:** {datetime.now(timezone.utc).isoformat()}  ",
            "",
            "## Summary",
            "",
            f"- **Files Scanned:** {d['files_scanned']}",
            f"- **Files Skipped:** {d['files_skipped']}",
            f"- **Total Findings:** {d['total_findings']}",
            f"- **Duration:** {d['duration_seconds']}s",
            "",
        ]
        if d["by_severity"]:
            lines.append("### By Severity")
            for sev in ["critical", "high", "medium", "low"]:
                if sev in d["by_severity"]:
                    lines.append(f"- **{sev.upper()}**: {d['by_severity'][sev]}")
            lines.append("")

        if d["findings"]:
            lines.append("## Findings")
            for f in d["findings"]:
                fp = " [FALSE POSITIVE]" if f.get("is_false_positive") else ""
                lines.append(f"- **[{f['severity'].upper()}]{fp}** {f['pattern_name']}: `{f['file']}:{f['line_number']}`")
                lines.append(f"  - {f['description']}")
                lines.append(f"  - Match: `{f['match_value']}`")
                lines.append("")

        lines.append("---")
        lines.append("*Walk with the void. EXORR Security*")
        return "\n".join(lines)

    def save(self, path: str) -> None:
        content = self._to_json() if self.format == "json" else self._to_markdown()
        Path(path).write_text(content, encoding="utf-8")
