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
from typing import Any

from engine.evaluator import evaluate_resources
from engine.irr import ScanResult
from parsers.cfn_sam import parse_cfn_file, parse_directory

SEVERITY_WEIGHTS = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


def _supports_unicode() -> bool:
    """Check if stdout can encode Unicode symbols. Independent of color support."""
    try:
        encoding = getattr(sys.stdout, "encoding", "") or ""
        return encoding.lower() in ("utf-8", "utf8", "utf-8-sig")
    except Exception:
        return False


def _supports_color() -> bool:
    """Check if stdout is a real TTY and NO_COLOR is not set.

    Per docs/05-ui-ux-spec.md §7: CLI must degrade to plain ASCII/no-color when
    NO_COLOR is set or output isn't a TTY (e.g. piped to a file or CI log parser).
    """
    import os

    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


class _Ansi:
    """ANSI color codes, applied only when _supports_color() is True."""

    RESET = "\033[0m"
    RED = "\033[31m"
    BOLD_RED = "\033[1;31m"
    YELLOW = "\033[33m"
    BOLD_YELLOW = "\033[1;33m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    DIM = "\033[2m"


SEVERITY_COLOR = {
    "CRITICAL": _Ansi.BOLD_RED,
    "HIGH": _Ansi.BOLD_YELLOW,
    "MEDIUM": _Ansi.YELLOW,
    "LOW": _Ansi.CYAN,
}


def _colorize(text: str, color: str, enabled: bool) -> str:
    """Wrap text in an ANSI color code if colorization is enabled."""
    if not enabled:
        return text
    return f"{color}{text}{_Ansi.RESET}"


def format_text_output(scan_result: ScanResult, elapsed: float = 0.0) -> str:
    """Format scan results according to docs/05-ui-ux-spec.md §2."""
    use_unicode = _supports_unicode()
    use_color = _supports_color()

    # Choose symbols based on terminal capability
    X_MARK = "\u2716" if use_unicode else "X"
    CHECK = "\u2713" if use_unicode else "*"
    DOT = "\u00b7" if use_unicode else "|"
    HRULE = "\u2500" * 60 if use_unicode else "-" * 60

    def sev(text: str, severity: str) -> str:
        return _colorize(text, SEVERITY_COLOR.get(severity.upper(), ""), use_color)

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
        parts.append(sev(f"{X_MARK} {n_critical} CRITICAL", "CRITICAL"))
    if n_high:
        parts.append(sev(f"{X_MARK} {n_high} HIGH", "HIGH"))
    if n_medium:
        parts.append(sev(f"{X_MARK} {n_medium} MEDIUM", "MEDIUM"))
    if n_clean > 0:
        parts.append(_colorize(f"{CHECK} {n_clean} clean", _Ansi.GREEN, use_color))
    if parts:
        lines.append("  ".join(parts))
    else:
        lines.append(_colorize(f"{CHECK} {total} clean", _Ansi.GREEN, use_color))
    lines.append("")

    if not scan_result.violations:
        lines.append(
            _colorize(
                "[PASS] No policy violations detected. IaC configuration is compliant.",
                _Ansi.GREEN,
                use_color,
            )
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
                sev(f"[{v.severity}] {v.rule_id}", v.severity) + f" {DOT} {v.file}:{v.line}"
            )
            lines.append(f"  Resource: {v.resource_id} ({v.resource_type})")
            lines.append("")
            lines.append(f"  {v.explanation}")
            lines.append("")
            lines.append("  Suggested fix:")
            if v.fix_snippet:
                for s_line in v.fix_snippet.strip().splitlines():
                    # Diff-style: '+' added lines in green, '-' removed lines in red,
                    # per docs/05-ui-ux-spec.md §2.
                    if s_line.strip().startswith("-"):
                        lines.append(
                            "  " + _colorize(f"- {s_line.lstrip('- ')}", _Ansi.RED, use_color)
                        )
                    else:
                        clean = s_line.lstrip("+ ")
                        lines.append(
                            "  " + _colorize(f"+ {clean}", _Ansi.GREEN, use_color)
                        )
            else:
                lines.append(f"  {v.suggested_fix}")

        lines.append("")
        exit_reason = "blocking violations found"

    # Footer
    lines.append(HRULE)
    exit_code = 1 if scan_result.violations else 0
    elapsed_str = f"{elapsed:.1f}s" if elapsed else "< 1s"
    footer_color = _Ansi.BOLD_RED if exit_code else _Ansi.GREEN
    lines.append(
        _colorize(
            f"Scan complete in {elapsed_str} {DOT} exit code {exit_code} ({exit_reason})",
            footer_color,
            use_color,
        )
    )

    return "\n".join(lines)


def format_json_output(scan_result: ScanResult) -> str:
    """Emit canonical JSON output schema per docs/04-data-model-api.md §4."""
    return json.dumps(scan_result.to_dict(), indent=2)


_SARIF_SEVERITY_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def format_sarif_output(scan_result: ScanResult) -> str:
    """Emit SARIF 2.1.0 output, consumable by GitHub code-scanning.

    Reference: docs/04-data-model-api.md §5 (--format sarif) and AC9.
    """
    # One SARIF "rule" definition per distinct rule_id seen, so the same
    # rule appearing on multiple resources isn't redefined multiple times.
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for v in scan_result.violations:
        if v.rule_id not in rules_seen:
            rules_seen[v.rule_id] = {
                "id": v.rule_id,
                "shortDescription": {"text": v.rule_id.replace("-", " ").title()},
                "fullDescription": {"text": v.explanation},
                "helpUri": "https://github.com/Shashidhar-Pawadashetti/cedarguard",
                "properties": {"security-severity": v.severity},
            }

        results.append(
            {
                "ruleId": v.rule_id,
                "level": _SARIF_SEVERITY_LEVEL.get(v.severity.upper(), "warning"),
                "message": {"text": f"{v.explanation} Suggested fix: {v.suggested_fix}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": v.file},
                            "region": {"startLine": max(v.line, 1)},
                        }
                    }
                ],
                "properties": {"resourceId": v.resource_id, "resourceType": v.resource_type},
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CedarGuard",
                        "informationUri": "https://github.com/Shashidhar-Pawadashetti/cedarguard",
                        "version": "0.1.0",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


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

    violations = evaluate_resources(resources, selected_rules=selected_rules, no_explain=no_explain)

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
    elif output_format == "sarif":
        print(format_sarif_output(result))
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
