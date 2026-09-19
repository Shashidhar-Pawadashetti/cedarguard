"""Tests for R1-S3-PUBLIC Cedar policy.

Verifies that the policy:
- DENY: S3 bucket with public-read ACL and no PublicAccessBlock
- ALLOW: S3 bucket with private ACL and full PublicAccessBlock
"""

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
CEDAR_BIN = str(ROOT_DIR / "bin" / ("cedar.exe" if __import__("sys").platform == "win32" else "cedar"))
SCHEMA_PATH = str(ROOT_DIR / "policies" / "schema.cedarschema.json")
PERMIT_POLICY = (ROOT_DIR / "policies" / "permit_default.cedar").read_text(encoding="utf-8")
R1_POLICY = (ROOT_DIR / "policies" / "r1_s3_public.cedar").read_text(encoding="utf-8")


def _run_authorization(entities: list[dict], resource_id: str) -> str:
    """Run cedar authorize and return the decision (ALLOW/DENY)."""
    combined_policy = PERMIT_POLICY + "\n" + R1_POLICY

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
            "--action", 'CedarGuard::Action::"EvaluateS3Public"',
            "--resource", f'CedarGuard::S3Bucket::"{resource_id}"',
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


def test_r1_violating_public_bucket():
    """Public S3 bucket with public-read ACL should be DENIED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::S3Bucket", "id": "PublicBucket"},
            "attrs": {"acl": "public-read", "blockPublicAcls": False, "blockPublicPolicy": False},
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "PublicBucket") == "DENY"


def test_r1_compliant_private_bucket():
    """Private S3 bucket with full PublicAccessBlock should be ALLOWED."""
    entities = [
        {"uid": {"type": "CedarGuard::Scanner", "id": "scanner"}, "attrs": {}, "parents": []},
        {
            "uid": {"type": "CedarGuard::S3Bucket", "id": "SecureBucket"},
            "attrs": {"acl": "private", "blockPublicAcls": True, "blockPublicPolicy": True},
            "parents": [],
        },
    ]
    assert _run_authorization(entities, "SecureBucket") == "ALLOW"
