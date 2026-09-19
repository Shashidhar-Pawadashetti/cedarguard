"""Tests for R4-SG-OPEN-INGRESS Cedar policy.

Verifies that the policy:
- DENY: SecurityGroup with open ingress on sensitive ports (22, 5432)
- ALLOW: SecurityGroup with no open ingress ports
"""

import json
import subprocess
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CEDAR_BIN = str(ROOT_DIR / "bin" / ("cedar.exe" if __import__("sys").platform == "win32" else "cedar"))
SCHEMA_PATH = str(ROOT_DIR / "policies" / "schema.cedarschema.json")
PERMIT_POLICY = (ROOT_DIR / "policies" / "permit_default.cedar").read_text(encoding="utf-8")
R4_POLICY = (ROOT_DIR / "policies" / "r4_sg_open_ingress.cedar").read_text(encoding="utf-8")


def _run_authorization(entities: list[dict], resource_id: str) -> str:
    combined_policy = PERMIT_POLICY + "\n" + R4_POLICY
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
            "--action", 'CedarGuard::Action::"EvaluateSgOpenIngress"',
            "--resource", f'CedarGuard::SecurityGroup::"{resource_id}"',
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


def test_r4_violating_open_ingress():
    """SecurityGroup open to 0.0.0.0/0 on SSH (22) and PostgreSQL (5432) should be DENIED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::SecurityGroup", "id": "OpenSG"},
            "attrs": {"openIngressPorts": [22, 5432]},
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "OpenSG") == "DENY"


def test_r4_compliant_restricted_ingress():
    """SecurityGroup with no open sensitive ports should be ALLOWED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::SecurityGroup", "id": "RestrictedSG"},
            "attrs": {"openIngressPorts": []},
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "RestrictedSG") == "ALLOW"
