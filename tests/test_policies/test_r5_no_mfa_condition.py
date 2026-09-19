"""Tests for R5-NO-MFA-CONDITION Cedar policy.

Verifies that the policy:
- DENY: IAM policy with sensitive action and no MFA condition
- ALLOW: IAM policy with sensitive action AND MFA condition
- ALLOW: IAM policy with non-sensitive action and no MFA condition
"""

import json
import subprocess
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CEDAR_BIN = str(ROOT_DIR / "bin" / ("cedar.exe" if __import__("sys").platform == "win32" else "cedar"))
SCHEMA_PATH = str(ROOT_DIR / "policies" / "schema.cedarschema.json")
PERMIT_POLICY = (ROOT_DIR / "policies" / "permit_default.cedar").read_text(encoding="utf-8")
R5_POLICY = (ROOT_DIR / "policies" / "r5_no_mfa_condition.cedar").read_text(encoding="utf-8")


def _run_authorization(entities: list[dict], resource_id: str) -> str:
    combined_policy = PERMIT_POLICY + "\n" + R5_POLICY
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
            "--action", 'CedarGuard::Action::"EvaluateMfaCondition"',
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


def test_r5_violating_sensitive_no_mfa():
    """Sensitive IAM action without MFA condition should be DENIED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::IamPolicy", "id": "NoMfaPolicy"},
            "attrs": {
                "hasWildcardAction": False,
                "hasWildcardResource": False,
                "hasMfaCondition": False,
                "isSensitiveAction": True,
            },
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "NoMfaPolicy") == "DENY"


def test_r5_compliant_sensitive_with_mfa():
    """Sensitive IAM action WITH MFA condition should be ALLOWED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::IamPolicy", "id": "MfaPolicy"},
            "attrs": {
                "hasWildcardAction": False,
                "hasWildcardResource": False,
                "hasMfaCondition": True,
                "isSensitiveAction": True,
            },
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "MfaPolicy") == "ALLOW"
