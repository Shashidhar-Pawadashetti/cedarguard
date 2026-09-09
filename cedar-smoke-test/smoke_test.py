"""Cedar 10-Minute Smoke Test.

Evaluates a trivial Cedar policy against sample entities (compliant & non-compliant)
using the official Cedar CLI, confirming that policy evaluation and decision extraction
work cleanly from Python.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def find_cedar_bin() -> str:
    """Locate the cedar binary in bin/ or on system PATH."""
    root_dir = Path(__file__).resolve().parent.parent
    local_bin = root_dir / "bin" / ("cedar.exe" if sys.platform == "win32" else "cedar")
    if local_bin.is_file():
        return str(local_bin)
    env_bin = os.environ.get("CEDAR_BIN_PATH")
    if env_bin and Path(env_bin).is_file():
        return env_bin
    return "cedar"


def run_authorization(
    cedar_bin: str,
    schema_path: str,
    policies_path: str,
    entities_path: str,
    principal: str,
    action: str,
    resource: str,
) -> tuple[str, list[str]]:
    """Invoke cedar authorize and return (decision, reasons)."""
    cmd = [
        cedar_bin,
        "authorize",
        "--schema",
        schema_path,
        "--schema-format",
        "json",
        "--policies",
        policies_path,
        "--entities",
        entities_path,
        "--principal",
        principal,
        "--action",
        action,
        "--resource",
        resource,
        "-v",
    ]

    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    output = res.stdout + res.stderr

    decision = "UNKNOWN"
    if "ALLOW" in output:
        decision = "ALLOW"
    elif "DENY" in output:
        decision = "DENY"

    reasons = []
    lines = output.splitlines()
    in_reasons = False
    for line in lines:
        stripped = line.strip()
        if "this decision was due to the following policies:" in line:
            in_reasons = True
            continue
        if in_reasons:
            if stripped.startswith("note:") or not stripped:
                continue
            reasons.append(stripped)

    return decision, reasons


def main() -> int:
    base_dir = Path(__file__).resolve().parent
    schema_file = str(base_dir / "schema.cedarschema.json")
    policies_file = str(base_dir / "test.cedar")
    entities_file = str(base_dir / "entities.json")

    cedar_bin = find_cedar_bin()
    print(f"[1/4] Found Cedar CLI binary at: {cedar_bin}")

    # Verify version
    ver = subprocess.run(
        [cedar_bin, "--version"], capture_output=True, text=True, check=True
    )
    print(f"[2/4] Cedar CLI version: {ver.stdout.strip()}")

    # Test 1: Public bucket (violating)
    print("\n[3/4] Testing violating entity (PublicBucket)...")
    dec1, reasons1 = run_authorization(
        cedar_bin=cedar_bin,
        schema_path=schema_file,
        policies_path=policies_file,
        entities_path=entities_file,
        principal='CedarGuard::Scanner::"local_scanner"',
        action='CedarGuard::Action::"EvaluateS3Public"',
        resource='CedarGuard::S3Bucket::"PublicBucket"',
    )
    print(f"      Decision: {dec1}")
    print(f"      Triggered policies: {reasons1}")
    assert dec1 == "DENY", f"Expected DENY, got {dec1}"
    assert "R1-S3-PUBLIC" in reasons1, (
        f"Expected R1-S3-PUBLIC in reasons, got {reasons1}"
    )
    print(
        "      [PASS] Violating bucket successfully flagged by R1-S3-PUBLIC forbid rule."
    )

    # Test 2: Secure bucket (compliant)
    print("\n[4/4] Testing compliant entity (SecureBucket)...")
    dec2, reasons2 = run_authorization(
        cedar_bin=cedar_bin,
        schema_path=schema_file,
        policies_path=policies_file,
        entities_path=entities_file,
        principal='CedarGuard::Scanner::"local_scanner"',
        action='CedarGuard::Action::"EvaluateS3Public"',
        resource='CedarGuard::S3Bucket::"SecureBucket"',
    )
    print(f"      Decision: {dec2}")
    print(f"      Triggered policies: {reasons2}")
    assert dec2 == "ALLOW", f"Expected ALLOW, got {dec2}"
    print("      [PASS] Compliant bucket successfully permitted.")

    print("\n==================================================")
    print("SMOKE TEST SUCCESSFUL: Cedar policy engine is ready!")
    print("==================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
