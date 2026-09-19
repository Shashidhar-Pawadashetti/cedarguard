"""Unit tests for ci/github_action/post_comment.py.

Tests the pure comment-building and de-duplication logic (no network calls).
Reference: docs/04-data-model-api.md §7, docs/05-ui-ux-spec.md §4, AC3.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ci" / "github_action"))

from post_comment import (
    COMMENT_MARKER,
    build_comment_body,
    compute_new_violations,
)


def _violation(rule_id="R1-S3-PUBLIC", resource_id="MyBucket", file="infra/storage.yaml"):
    return {
        "rule_id": rule_id,
        "severity": "CRITICAL",
        "resource_id": resource_id,
        "resource_type": "AWS::S3::Bucket",
        "file": file,
        "line": 14,
        "explanation": "This S3 bucket allows public read/write access.",
        "suggested_fix": "Block public access at the bucket level.",
        "fix_snippet": "BlockPublicAcls: true",
    }


class TestComputeNewViolations:
    """FR4.2: report only violations introduced by this PR, not every pre-existing one."""

    def test_no_base_scan_reports_all_violations(self):
        violations = [_violation()]
        assert compute_new_violations(violations, base_violations=None) == violations

    def test_violation_present_in_base_is_not_new(self):
        v = _violation()
        assert compute_new_violations([v], base_violations=[v]) == []

    def test_violation_absent_from_base_is_new(self):
        base = [_violation(resource_id="OldBucket")]
        pr = [_violation(resource_id="OldBucket"), _violation(resource_id="NewBucket")]
        new = compute_new_violations(pr, base_violations=base)
        assert len(new) == 1
        assert new[0]["resource_id"] == "NewBucket"

    def test_same_rule_different_resource_is_new(self):
        base = [_violation(resource_id="BucketA")]
        pr = [_violation(resource_id="BucketB")]
        new = compute_new_violations(pr, base_violations=base)
        assert len(new) == 1


class TestBuildCommentBody:
    """AC3: single upserted comment, correct table + collapsible details format."""

    def test_body_contains_marker(self):
        body = build_comment_body([_violation()], total_violations=1)
        assert COMMENT_MARKER in body

    def test_clean_scan_message(self):
        body = build_comment_body([], total_violations=0)
        assert "no issues found" in body
        assert COMMENT_MARKER in body

    def test_no_new_but_preexisting_violations_message(self):
        body = build_comment_body([], total_violations=3)
        assert "no *new* issues" in body
        assert "3 pre-existing" in body

    def test_table_and_details_present_for_new_violations(self):
        body = build_comment_body([_violation()], total_violations=1)
        assert "| Severity | Rule | Resource | File |" in body
        assert "`MyBucket`" in body
        assert "<details>" in body and "</details>" in body

    def test_severity_emoji_present(self):
        body = build_comment_body([_violation()], total_violations=1)
        assert "\U0001f534" in body  # red circle for CRITICAL

    def test_singular_plural_issue_wording(self):
        one = build_comment_body([_violation()], total_violations=1)
        two = build_comment_body([_violation(), _violation(resource_id="B")], total_violations=2)
        assert "1 new issue " in one or "1 new issue\n" in one or "1 new issue<" in one or "1 new issue in" in one
        assert "2 new issues in" in two
