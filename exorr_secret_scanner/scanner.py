"""Core scanner — walks directories and scans files for secrets."""

import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .patterns import get_patterns, SECRET_PATTERNS

# Directories and files to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", ".eggs",
    ".idea", ".vscode", "vendor", "Cargo/target",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".o", ".class",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit


@dataclass
class Finding:
    """A single secret detection finding."""
    file: str
    line_number: int
    line_content: str
    pattern_id: str
    pattern_name: str
    severity: str
    description: str
    match_value: str
    is_false_positive: bool = False

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "description": self.description,
            "match_value": self.match_value[:20] + "..." if len(self.match_value) > 20 else self.match_value,
            "is_false_positive": self.is_false_positive,
        }


@dataclass
class ScanResult:
    """Complete scan results."""
    target: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self._by_severity(),
            "by_pattern": self._by_pattern(),
            "duration_seconds": round(self.duration_seconds, 2),
        }

    def _by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _by_pattern(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.pattern_name] = counts.get(f.pattern_name, 0) + 1
        return counts


class SecretScanner:
    """Scan directories for leaked secrets."""

    def __init__(
        self,
        target: str,
        patterns_filter: Optional[Set[str]] = None,
        severity_threshold: str = "low",
        verbose: bool = False,
        entropy_check: bool = True,
    ):
        self.target = Path(target).resolve()
        self.patterns_filter = patterns_filter
        self.severity_threshold = severity_threshold
        self.verbose = verbose
        self.entropy_check = entropy_check
        self._patterns = get_patterns()

    def _should_skip_dir(self, dirname: str) -> bool:
        return dirname in SKIP_DIRS or dirname.startswith(".")

    def _should_skip_file(self, path: Path) -> bool:
        if path.suffix.lower() in SKIP_EXTENSIONS:
            return True
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                return True
        except OSError:
            return True
        return False

    def _is_false_positive(self, line: str, pattern_info: dict) -> bool:
        """Check if a match is likely a false positive."""
        line_lower = line.lower()
        for hint in pattern_info.get("fp_hints", []):
            if hint in line_lower:
                return True
        return False

    def _scan_file(self, file_path: Path, patterns: list) -> List[Finding]:
        """Scan a single file for secrets."""
        findings = []
        try:
            content = file_path.read_text(errors="ignore", encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return findings

        rel_path = str(file_path.relative_to(self.target)) if file_path.is_relative_to(self.target) else str(file_path)

        for line_num, line in enumerate(content.splitlines(), 1):
            for pat in patterns:
                match = pat["compiled"].search(line)
                if match:
                    is_fp = self._is_false_positive(line, pat)
                    findings.append(Finding(
                        file=rel_path,
                        line_number=line_num,
                        line_content=line,
                        pattern_id=pat["id"],
                        pattern_name=pat["name"],
                        severity=pat["severity"],
                        description=pat["description"],
                        match_value=match.group(0),
                        is_false_positive=is_fp,
                    ))
        return findings

    def scan(self) -> ScanResult:
        """Scan the target directory recursively."""
        import time
        start = time.time()

        result = ScanResult(target=str(self.target))

        # Filter patterns
        active_patterns = self._patterns
        if self.patterns_filter:
            active_patterns = [p for p in self._patterns if p["id"] in self.patterns_filter]

        # Walk directory
        for root, dirs, files in os.walk(self.target):
            # Skip directories
            dirs[:] = [d for d in dirs if not self._should_skip_dir(d)]

            for fname in files:
                fpath = Path(root) / fname
                if self._should_skip_file(fpath):
                    result.files_skipped += 1
                    continue

                result.files_scanned += 1
                findings = self._scan_file(fpath, active_patterns)
                result.findings.extend(findings)

        result.duration_seconds = time.time() - start
        return result
