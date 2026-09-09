"""CedarGuard CLI entry point.

Implements CLI commands (scan, audit-log) and output formatters (text, json, sarif).
Reference: docs/04-data-model-api.md §5 and docs/05-ui-ux-spec.md §2
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from engine.irr import ScanResult, Violation

SEVERITY_WEIGHTS = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


def format_text_output(scan_result: ScanResult) -> str:
    """Format scan results according to docs/05-ui-ux-spec.md §2."""
    lines: list[str] = []
    lines.append("CedarGuard Security Scan Report")
    lines.append("=" * 60)
    lines.append(f"Target: {scan_result.target}")
    lines.append(
        f"Total Resources Scanned: {scan_result.summary.get('total_resources', 0)}"
    )
    lines.append(f"Violations Found:        {scan_result.summary.get('violations', 0)}")
    lines.append(f"  Critical: {scan_result.summary.get('critical', 0)}")
    lines.append(f"  High:     {scan_result.summary.get('high', 0)}")
    lines.append(f"  Medium:   {scan_result.summary.get('medium', 0)}")
    lines.append("=" * 60)

    if not scan_result.violations:
        lines.append(
            "\n[PASS] No policy violations detected. IaC configuration is compliant."
        )
        return "\n".join(lines)

    for v in scan_result.violations:
        lines.append(
            f"\n[{v.severity}] {v.rule_id}: {v.resource_id} ({v.resource_type})"
        )
        lines.append(f"  File: {v.file}:{v.line}")
        lines.append(f"  Why:  {v.explanation}")
        lines.append(f"  Fix:  {v.suggested_fix}")
        if v.fix_snippet:
            lines.append("  Suggested Remediation:")
            for s_line in v.fix_snippet.strip().splitlines():
                lines.append(f"    {s_line}")

    return "\n".join(lines)


def format_json_output(scan_result: ScanResult) -> str:
    """Emit canonical JSON output schema per docs/04-data-model-api.md §4."""
    return json.dumps(scan_result.to_dict(), indent=2)


def run_scan(
    target_path: str,
    output_format: str = "text",
    fail_on: str = "high",
    no_explain: bool = False,
    rules: list[str] | None = None,
) -> int:
    """Execute scan against IaC target directory or file."""
    p = Path(target_path)
    if not p.exists():
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        return 2

    # Scaffolding stub: placeholder scan result
    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    violations: list[Violation] = []

    summary = {
        "total_resources": 0,
        "violations": len(violations),
        "critical": sum(1 for v in violations if v.severity == "CRITICAL"),
        "high": sum(1 for v in violations if v.severity == "HIGH"),
        "medium": sum(1 for v in violations if v.severity == "MEDIUM"),
    }

    result = ScanResult(
        scan_id=scan_id,
        target=str(p),
        summary=summary,
        violations=violations,
    )

    if output_format == "json":
        print(format_json_output(result))
    else:
        print(format_text_output(result))

    threshold = SEVERITY_WEIGHTS.get(fail_on.upper(), 2)
    blocking_violations = [
        v
        for v in violations
        if SEVERITY_WEIGHTS.get(v.severity.upper(), 0) >= threshold
    ]
    return 1 if blocking_violations else 0


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="cedarguard",
        description="Policy-as-code security guardrail engine powered by Cedar.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan subcommand
    scan_parser = subparsers.add_parser(
        "scan", help="Scan IaC templates for security violations"
    )
    scan_parser.add_argument("path", help="Path to IaC file or directory to scan")
    scan_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium"],
        default="high",
        help="Minimum severity that triggers exit code 1 (default: high)",
    )
    scan_parser.add_argument(
        "--no-explain",
        action="store_true",
        help="Skip Bedrock/extended explanation for faster execution",
    )
    scan_parser.add_argument(
        "--rules",
        help="Comma-separated list of rule IDs to evaluate (e.g. R1,R2)",
    )

    # audit-log subcommand (Ship It stretch)
    audit_parser = subparsers.add_parser(
        "audit-log", help="Query live security audit logs"
    )
    audit_parser.add_argument(
        "--since", default="24h", help="Time range filter (default: 24h)"
    )
    audit_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    return parser


def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.command == "scan":
        selected_rules = (
            [r.strip() for r in parsed_args.rules.split(",") if r.strip()]
            if parsed_args.rules
            else None
        )
        return run_scan(
            target_path=parsed_args.path,
            output_format=parsed_args.format,
            fail_on=parsed_args.fail_on,
            no_explain=parsed_args.no_explain,
            rules=selected_rules,
        )
    elif parsed_args.command == "audit-log":
        print(f"Querying audit log since {parsed_args.since}... (Ship It stretch)")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
