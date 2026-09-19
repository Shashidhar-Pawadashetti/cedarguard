"""Tests for R2-IAM-WILDCARD-ACTION Cedar policy.

Verifies that the policy:
- DENY: IAM policy with hasWildcardAction == true
- ALLOW: IAM policy with hasWildcardAction == false
"""

import json
import subprocess
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CEDAR_BIN = str(ROOT_DIR / "bin" / ("cedar.exe" if __import__("sys").platform == "win32" else "cedar"))
SCHEMA_PATH = str(ROOT_DIR / "policies" / "schema.cedarschema.json")
PERMIT_POLICY = (ROOT_DIR / "policies" / "permit_default.cedar").read_text(encoding="utf-8")
R2_POLICY = (ROOT_DIR / "policies" / "r2_iam_wildcard_action.cedar").read_text(encoding="utf-8")


def _run_authorization(entities: list[dict], resource_id: str) -> str:
    combined_policy = PERMIT_POLICY + "\n" + R2_POLICY
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as ef:
        json.dump(entities, ef)
        entity_path = ef.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cedar", delete=False, encoding="utf-8") as pf:
        pf.write(combined_policy)
        policy_path = pf.name
    try:
        cmd = [
            CEDAR_BIN, "authorize",
            "--schema", SCHEMA_PATH, "--schema-format", "json",
            "--policies", policy_path, "--entities", entity_path,
            "--principal", 'CedarGuard::Scanner::"scanner"',
            "--action", 'CedarGuard::Action::"EvaluateIamWildcardAction"',
            "--resource", f'CedarGuard::IamPolicy::"{resource_id}"',
            "-v",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = res.stdout + res.stderr
        if "DENY" in output:
            return "DENY"
        if "ALLOW" in output:
            return "ALLOW"
        return "UNKNOWN"
    finally:
        import os
        for p in (entity_path, policy_path):
            if os.path.exists(p):
                os.remove(p)


def test_r2_violating_wildcard_action():
    """IAM policy with Action: '*' should be DENIED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::IamPolicy", "id": "AdminPolicy"},
            "attrs": {
                "hasWildcardAction": True,
                "hasWildcardResource": False,
                "hasMfaCondition": False,
                "isSensitiveAction": False,
            },
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "AdminPolicy") == "DENY"


def test_r2_compliant_scoped_action():
    """IAM policy with scoped actions should be ALLOWED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::IamPolicy", "id": "ScopedPolicy"},
            "attrs": {
                "hasWildcardAction": False,
                "hasWildcardResource": False,
                "hasMfaCondition": True,
                "isSensitiveAction": False,
            },
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "ScopedPolicy") == "ALLOW"
