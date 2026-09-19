"""End-to-end CLI tests.

Tests the full scan pipeline: parse → evaluate → format → exit code.
Per docs/07-acceptance-criteria.md AC1.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run the CLI via `python -m cli.main` and return the result."""
    cmd = [PYTHON, "-m", "cli.main", *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        cwd=str(ROOT_DIR),
    )


class TestBrokenRepoScan:
    """AC1: broken repo produces 5 violations and exit code 1."""

    def test_json_output_violations_count(self):
        result = _run_cli("scan", "./demo-repo/broken", "--format", "json")
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert data["summary"]["violations"] == 5

    def test_json_output_total_resources(self):
        result = _run_cli("scan", "./demo-repo/broken", "--format", "json")
        data = json.loads(result.stdout)
        assert data["summary"]["total_resources"] == 7

    def test_all_rule_ids_present(self):
        result = _run_cli("scan", "./demo-repo/broken", "--format", "json")
        data = json.loads(result.stdout)
        rule_ids = {v["rule_id"] for v in data["violations"]}
        assert rule_ids == {
            "R1-S3-PUBLIC",
            "R2-IAM-WILDCARD-ACTION",
            "R3-IAM-WILDCARD-RESOURCE",
            "R4-SG-OPEN-INGRESS",
            "R5-NO-MFA-CONDITION",
        }

    def test_severity_counts(self):
        result = _run_cli("scan", "./demo-repo/broken", "--format", "json")
        data = json.loads(result.stdout)
        assert data["summary"]["critical"] == 2
        assert data["summary"]["high"] == 2
        assert data["summary"]["medium"] == 1

    def test_text_output_contains_violations(self):
        result = _run_cli("scan", "./demo-repo/broken")
        assert result.returncode == 1
        assert "R1-S3-PUBLIC" in result.stdout
        assert "R2-IAM-WILDCARD-ACTION" in result.stdout
        assert "blocking violations found" in result.stdout


class TestFixedRepoScan:
    """AC1: fixed repo produces 0 violations and exit code 0."""

    def test_json_output_no_violations(self):
        result = _run_cli("scan", "./demo-repo/fixed", "--format", "json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["summary"]["violations"] == 0
        assert data["violations"] == []

    def test_text_output_pass(self):
        result = _run_cli("scan", "./demo-repo/fixed")
        assert result.returncode == 0
        assert "No policy violations detected" in result.stdout


class TestRuleFiltering:
    """Test --rules flag for selective evaluation."""

    def test_single_rule_filter(self):
        result = _run_cli(
            "scan", "./demo-repo/broken", "--format", "json", "--rules", "R1-S3-PUBLIC"
        )
        data = json.loads(result.stdout)
        rule_ids = {v["rule_id"] for v in data["violations"]}
        assert rule_ids == {"R1-S3-PUBLIC"}

    def test_nonexistent_path_returns_error(self):
        result = _run_cli("scan", "./nonexistent-path", "--format", "json")
        assert result.returncode == 2
