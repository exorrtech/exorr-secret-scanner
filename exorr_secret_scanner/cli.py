#!/usr/bin/env python3
"""EXORR Secret Scanner — Detect leaked secrets in Git repositories and directories."""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .scanner import SecretScanner
from .patterns import SECRET_PATTERNS
from .report import SecretReportGenerator


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="exorr-secret-scanner",
        description="EXORR Secret Scanner — detect leaked secrets in Git repos and directories",
        epilog="Walk with the void. EXORR Security",
    )
    p.add_argument("target", nargs="?", default=".", help="Directory or repo to scan (default: current directory)")
    p.add_argument("-p", "--patterns", default=None, help="Comma-separated pattern IDs to scan (default: all)")
    p.add_argument("--severity-threshold", choices=["low", "medium", "high", "critical"], default="low", help="Min severity (default: low)")
    p.add_argument("--show-fp", action="store_true", help="Show likely false positives")
    p.add_argument("-o", "--output", default=None, help="Output report file path")
    p.add_argument("--format", choices=["json", "markdown"], default="json", help="Report format (default: json)")
    p.add_argument("--list-patterns", action="store_true", help="List all detection patterns and exit")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("-v", "--version", action="version", version="%(prog)s 1.0.0")
    return p.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    if args.list_patterns:
        print(f"\n  EXORR Secret Scanner — Detection Patterns\n")
        for p in SECRET_PATTERNS:
            print(f"  [{p['id']}] {p['name']} — Severity: {p['severity']}")
            print(f"    {p['description']}\n")
        return 0

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"[!] Target not found: {target}", file=sys.stderr)
        return 1

    patterns_filter = set(args.patterns.split(",")) if args.patterns else None

    print(f"\n  EXORR Secret Scanner v1.0.0")
    print(f"  ==========================")
    print(f"  Target: {target}")
    print()

    scanner = SecretScanner(
        target=str(target),
        patterns_filter=patterns_filter,
        severity_threshold=args.severity_threshold,
        verbose=args.verbose,
    )

    result = scanner.scan()

    # Filter findings
    findings = result.findings
    if not args.show_fp:
        findings = [f for f in findings if not f.is_false_positive]
    result.findings = findings

    # Print summary
    print(f"  ==========================")
    print(f"  Scan complete")
    print(f"    Files scanned:  {result.files_scanned}")
    print(f"    Files skipped:  {result.files_skipped}")
    print(f"    Findings:       {len(findings)}")
    print(f"    Duration:       {result.duration_seconds:.2f}s")
    print()

    if findings:
        print(f"  FINDINGS:")
        for f in findings:
            fp_tag = " [FP]" if f.is_false_positive else ""
            print(f"    [{f.severity.upper()}]{fp_tag} {f.pattern_name}: {f.file}:{f.line_number}")
        print()

    # Save report
    if args.output:
        reporter = SecretReportGenerator(result, format=args.format)
        reporter.save(args.output)
        print(f"  Report saved: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
