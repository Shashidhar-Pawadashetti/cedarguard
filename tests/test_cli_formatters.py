"""Unit tests for CLI output formatters.

Unlike tests/test_cli_e2e.py, these construct ScanResult/Violation objects
directly rather than invoking the full parse->evaluate pipeline, so they run
without requiring the Cedar CLI binary to be installed.
Reference: docs/05-ui-ux-spec.md §2-3, docs/07-acceptance-criteria.md AC9.
"""

from __future__ import annotations

import json

from cli.main import _colorize, _supports_color, format_sarif_output, format_text_output
from engine.irr import ScanResult, Violation


def _make_violation(rule_id="R1-S3-PUBLIC", severity="CRITICAL", line=14) -> Violation:
    return Violation(
        rule_id=rule_id,
        severity=severity,
        resource_id="MyBucket",
        resource_type="AWS::S3::Bucket",
        file="infra/storage.yaml",
        line=line,
        explanation="This S3 bucket allows public read/write access.",
        suggested_fix="Block public access at the bucket level.",
        fix_snippet="PublicAccessBlockConfiguration:\n  BlockPublicAcls: true",
    )


def _make_scan_result(violations: list[Violation]) -> ScanResult:
    n_crit = sum(1 for v in violations if v.severity == "CRITICAL")
    n_high = sum(1 for v in violations if v.severity == "HIGH")
    n_med = sum(1 for v in violations if v.severity == "MEDIUM")
    return ScanResult(
        scan_id="scan-test",
        target="./demo-repo/broken",
        summary={
            "total_resources": max(len(violations), 1),
            "violations": len(violations),
            "critical": n_crit,
            "high": n_high,
            "medium": n_med,
        },
        violations=violations,
    )


class TestSarifOutput:
    """AC9: --format sarif must produce valid, schema-shaped SARIF 2.1.0."""

    def test_sarif_is_valid_json_with_correct_version(self):
        result = _make_scan_result([_make_violation()])
        sarif = json.loads(format_sarif_output(result))
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif and len(sarif["runs"]) == 1

    def test_sarif_result_maps_rule_and_severity(self):
        result = _make_scan_result([_make_violation(severity="CRITICAL")])
        sarif = json.loads(format_sarif_output(result))
        sarif_result = sarif["runs"][0]["results"][0]
        assert sarif_result["ruleId"] == "R1-S3-PUBLIC"
        assert sarif_result["level"] == "error"  # CRITICAL -> error
        assert sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
            "infra/storage.yaml"
        )

    def test_sarif_medium_severity_maps_to_warning(self):
        result = _make_scan_result([_make_violation(rule_id="R5-NO-MFA-CONDITION", severity="MEDIUM")])
        sarif = json.loads(format_sarif_output(result))
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_sarif_rule_not_duplicated_across_multiple_violations(self):
        violations = [_make_violation(line=10), _make_violation(line=20)]
        result = _make_scan_result(violations)
        sarif = json.loads(format_sarif_output(result))
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids == ["R1-S3-PUBLIC"]  # defined once, not twice
        assert len(sarif["runs"][0]["results"]) == 2  # but both results present

    def test_sarif_empty_violations_produces_empty_results(self):
        result = _make_scan_result([])
        sarif = json.loads(format_sarif_output(result))
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


class TestColorSupport:
    """NFR: colorization must respect NO_COLOR and non-TTY output (05-ui-ux-spec §7)."""

    def test_no_color_env_disables_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert _supports_color() is False

    def test_colorize_noop_when_disabled(self):
        assert _colorize("text", "\033[31m", enabled=False) == "text"

    def test_colorize_wraps_when_enabled(self):
        out = _colorize("text", "\033[31m", enabled=True)
        assert out.startswith("\033[31m")
        assert out.endswith("\033[0m")
        assert "text" in out

    def test_text_output_has_no_ansi_codes_when_color_disabled(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        result = _make_scan_result([_make_violation()])
        text = format_text_output(result, elapsed=0.3)
        assert "\033[" not in text


class TestTextOutputContent:
    """Sanity checks independent of the e2e pipeline."""

    def test_clean_scan_shows_pass_message(self):
        result = _make_scan_result([])
        text = format_text_output(result, elapsed=0.1)
        assert "No policy violations detected" in text

    def test_violations_sorted_critical_first(self):
        violations = [
            _make_violation(rule_id="R5-NO-MFA-CONDITION", severity="MEDIUM"),
            _make_violation(rule_id="R1-S3-PUBLIC", severity="CRITICAL"),
        ]
        result = _make_scan_result(violations)
        text = format_text_output(result, elapsed=0.1)
        assert text.index("R1-S3-PUBLIC") < text.index("R5-NO-MFA-CONDITION")
