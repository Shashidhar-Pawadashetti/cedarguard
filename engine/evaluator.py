"""Cedar policy evaluation engine for CedarGuard.

Orchestrates transforming IRR objects into Cedar entities, executing the Cedar CLI
authorization engine, and mapping forbid/allow decisions into structured Violations.
Reference: docs/03-architecture.md §2.2 and docs/04-data-model-api.md §2-3
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from engine.irr import Resource, Violation
from explain.templates import get_explanation


def resolve_cedar_bin() -> str:
    """Locate the cedar binary in the project bin/ or PATH."""
    root_dir = Path(__file__).resolve().parent.parent
    local_bin = root_dir / "bin" / ("cedar.exe" if sys.platform == "win32" else "cedar")
    if local_bin.is_file():
        return str(local_bin)
    env_bin = os.environ.get("CEDAR_BIN_PATH")
    if env_bin and Path(env_bin).is_file():
        return env_bin
    return "cedar"


def evaluate_resource_with_cedar(
    resource: Resource,
    rule_action: str,
    rule_id: str,
    schema_path: str,
    policy_path: str,
    cedar_bin: str | None = None,
) -> Violation | None:
    """Evaluate a single IRR resource against a Cedar rule policy.

    Returns a Violation if the rule forbids the configuration, None if allowed.
    """
    cedar_exec = cedar_bin or resolve_cedar_bin()

    # Map IRR attributes to Cedar entity representation
    entity_type = (
        "S3Bucket"
        if resource.resource_type == "AWS::S3::Bucket"
        else "IamPolicy"
        if "IAM" in resource.resource_type
        else "SecurityGroup"
        if "SecurityGroup" in resource.resource_type
        else "GenericResource"
    )

    entities: list[dict[str, Any]] = [
        {
            "uid": {"type": "CedarGuard::Scanner", "id": "scanner"},
            "attrs": {},
            "parents": [],
        },
        {
            "uid": {"type": f"CedarGuard::{entity_type}", "id": resource.resource_id},
            "attrs": resource.attributes,
            "parents": [],
        },
    ]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as entity_file:
        json.dump(entities, entity_file)
        entity_path = entity_file.name

    try:
        cmd = [
            cedar_exec,
            "authorize",
            "--schema",
            schema_path,
            "--schema-format",
            "json",
            "--policies",
            policy_path,
            "--entities",
            entity_path,
            "--principal",
            'CedarGuard::Scanner::"scanner"',
            "--action",
            f'CedarGuard::Action::"{rule_action}"',
            "--resource",
            f'CedarGuard::{entity_type}::"{resource.resource_id}"',
            "-v",
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = res.stdout + res.stderr

        # Check for DENY due to this specific rule policy ID
        if "DENY" in output and (rule_id in output or "forbid" in output):
            expl = get_explanation(rule_id)
            return Violation(
                rule_id=rule_id,
                severity=expl.get("severity", "HIGH"),
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                file=resource.source_file,
                line=resource.source_line,
                explanation=expl.get("explanation", ""),
                suggested_fix=expl.get("suggested_fix", ""),
                fix_snippet=expl.get("fix_snippet", ""),
            )
        return None
    finally:
        if os.path.exists(entity_path):
            try:
                os.remove(entity_path)
            except OSError:
                pass
