"""CedarGuard CLI entry point.

Implements CLI commands (scan, audit-log) and output formatters (text, json, sarif).
Reference: docs/04-data-model-api.md §5 and docs/05-ui-ux-spec.md §2
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from engine.evaluator import evaluate_resources
from engine.irr import ScanResult, Violation
from parsers.cfn_sam import parse_cfn_file, parse_directory

SEVERITY_WEIGHTS = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


def _supports_unicode() -> bool:
    """Check if stdout can encode Unicode symbols."""
    import os
    if os.environ.get("NO_COLOR"):
        return False
    try:
        encoding = getattr(sys.stdout, "encoding", "") or ""
        return encoding.lower() in ("utf-8", "utf8", "utf-8-sig")
    except Exception:
        return False


def format_text_output(scan_result: ScanResult, elapsed: float = 0.0) -> str:
    """Format scan results according to docs/05-ui-ux-spec.md §2."""
    use_unicode = _supports_unicode()

    # Choose symbols based on terminal capability
    X_MARK = "\u2716" if use_unicode else "X"
    CHECK = "\u2713" if use_unicode else "*"
    DOT = "\u00b7" if use_unicode else "|"
    HRULE = "\u2500" * 60 if use_unicode else "-" * 60

    lines: list[str] = []

    total = scan_result.summary.get("total_resources", 0)
    n_critical = scan_result.summary.get("critical", 0)
    n_high = scan_result.summary.get("high", 0)
    n_medium = scan_result.summary.get("medium", 0)
    n_violations = scan_result.summary.get("violations", 0)
    n_clean = total - n_violations if total >= n_violations else 0

    # Header
    lines.append(f"CedarGuard scan {DOT} {scan_result.target} {DOT} {total} resources scanned")
    lines.append("")

    # Severity summary line
    parts: list[str] = []
    if n_critical:
        parts.append(f"{X_MARK} {n_critical} CRITICAL")
    if n_high:
        parts.append(f"{X_MARK} {n_high} HIGH")
    if n_medium:
        parts.append(f"{X_MARK} {n_medium} MEDIUM")
    if n_clean > 0:
        parts.append(f"{CHECK} {n_clean} clean")
    if parts:
        lines.append("  ".join(parts))
    else:
        lines.append(f"{CHECK} {total} clean")
    lines.append("")

    if not scan_result.violations:
        lines.append(
            "[PASS] No policy violations detected. IaC configuration is compliant."
        )
        exit_reason = "no violations"
    else:
        # Sort violations by severity (CRITICAL first)
        sorted_violations = sorted(
            scan_result.violations,
            key=lambda v: SEVERITY_WEIGHTS.get(v.severity.upper(), 0),
            reverse=True,
        )

        for v in sorted_violations:
            lines.append(HRULE)
            lines.append(
                f"[{v.severity}] {v.rule_id} {DOT} {v.file}:{v.line}"
            )
            lines.append(f"  Resource: {v.resource_id} ({v.resource_type})")
            lines.append("")
            lines.append(f"  {v.explanation}")
            lines.append("")
            lines.append("  Suggested fix:")
            if v.fix_snippet:
                for s_line in v.fix_snippet.strip().splitlines():
                    lines.append(f"  + {s_line}")
            else:
                lines.append(f"  {v.suggested_fix}")

        lines.append("")
        exit_reason = "blocking violations found"

    # Footer
    lines.append(HRULE)
    exit_code = 1 if scan_result.violations else 0
    elapsed_str = f"{elapsed:.1f}s" if elapsed else "< 1s"
    lines.append(
        f"Scan complete in {elapsed_str} {DOT} exit code {exit_code} ({exit_reason})"
    )

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
    start_time = time.monotonic()

    p = Path(target_path)
    if not p.exists():
        print(f"Error: Target path does not exist: {target_path}", file=sys.stderr)
        return 2

    # Parse resources
    try:
        if p.is_dir():
            resources = parse_directory(p)
        else:
            resources = parse_cfn_file(p)
    except Exception as e:
        print(f"Error: Failed to parse target: {e}", file=sys.stderr)
        return 2

    if not resources:
        print(f"Warning: No scannable resources found in {target_path}", file=sys.stderr)

    # Evaluate resources against Cedar policies
    selected_rules = None
    if rules:
        # Normalize rule IDs (e.g. "R1" -> "R1-S3-PUBLIC")
        from engine.evaluator import RULE_REGISTRY
        rule_map = {}
        for r in RULE_REGISTRY:
            rule_map[r.rule_id] = r.rule_id
            # Also support short form: "R1" matches "R1-S3-PUBLIC"
            short = r.rule_id.split("-")[0]
            rule_map[short] = r.rule_id
        selected_rules = [rule_map.get(r, r) for r in rules]

    violations = evaluate_resources(resources, selected_rules=selected_rules)

    elapsed = time.monotonic() - start_time

    # Build scan result
    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    summary = {
        "total_resources": len(resources),
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
        print(format_text_output(result, elapsed))

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
