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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from engine.irr import Resource, Violation
from explain.bedrock_client import get_ai_explanation
from explain.templates import get_explanation


@dataclass(frozen=True)
class RuleSpec:
    """Specification for a single CedarGuard rule."""

    rule_id: str
    action: str
    entity_type: str
    resource_type_match: str  # substring match against IRR resource_type
    policy_file: str


# Registry of all rules — one rule = one policy file = one Cedar action
RULE_REGISTRY: list[RuleSpec] = [
    RuleSpec(
        rule_id="R1-S3-PUBLIC",
        action="EvaluateS3Public",
        entity_type="S3Bucket",
        resource_type_match="AWS::S3::Bucket",
        policy_file="r1_s3_public.cedar",
    ),
    RuleSpec(
        rule_id="R2-IAM-WILDCARD-ACTION",
        action="EvaluateIamWildcardAction",
        entity_type="IamPolicy",
        resource_type_match="AWS::IAM::",
        policy_file="r2_iam_wildcard_action.cedar",
    ),
    RuleSpec(
        rule_id="R3-IAM-WILDCARD-RESOURCE",
        action="EvaluateIamWildcardResource",
        entity_type="IamPolicy",
        resource_type_match="AWS::IAM::",
        policy_file="r3_iam_wildcard_resource.cedar",
    ),
    RuleSpec(
        rule_id="R4-SG-OPEN-INGRESS",
        action="EvaluateSgOpenIngress",
        entity_type="SecurityGroup",
        resource_type_match="AWS::EC2::SecurityGroup",
        policy_file="r4_sg_open_ingress.cedar",
    ),
    RuleSpec(
        rule_id="R5-NO-MFA-CONDITION",
        action="EvaluateMfaCondition",
        entity_type="IamPolicy",
        resource_type_match="AWS::IAM::",
        policy_file="r5_no_mfa_condition.cedar",
    ),
]


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


def _get_policies_dir() -> Path:
    """Locate the policies/ directory at the project root."""
    return Path(__file__).resolve().parent.parent / "policies"


_demo_cache_singleton: dict[str, dict[str, str]] | None = None


def _load_demo_cache() -> dict[str, dict[str, str]]:
    """Load explain/demo_cache.json once per process.

    Missing file or malformed JSON degrades to an empty cache (i.e. every
    lookup falls through to a live Bedrock call or the template fallback) —
    the cache is a demo convenience, never a hard dependency.
    Reference: docs/06-engineering-rules.md §5.
    """
    global _demo_cache_singleton
    if _demo_cache_singleton is not None:
        return _demo_cache_singleton

    cache_path = Path(__file__).resolve().parent.parent / "explain" / "demo_cache.json"
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
        _demo_cache_singleton = {k: v for k, v in raw.items() if not k.startswith("_")}
    except (FileNotFoundError, json.JSONDecodeError):
        _demo_cache_singleton = {}
    return _demo_cache_singleton


def _build_cedar_entities(resource: Resource, entity_type: str) -> list[dict[str, Any]]:
    """Build the Cedar entities JSON array for a resource evaluation.

    Converts IRR attributes to Cedar-compatible types:
    - Lists (openIngressPorts) → Cedar sets
    - All other types pass through as-is
    """
    cedar_attrs: dict[str, Any] = {}
    for key, value in resource.attributes.items():
        if isinstance(value, list):
            # Convert list to Cedar set representation
            cedar_attrs[key] = value
        else:
            cedar_attrs[key] = value

    return [
        {
            "uid": {"type": "CedarGuard::Scanner", "id": "scanner"},
            "attrs": {},
            "parents": [],
        },
        {
            "uid": {"type": f"CedarGuard::{entity_type}", "id": resource.resource_id},
            "attrs": cedar_attrs,
            "parents": [],
        },
    ]


def evaluate_single_rule(
    resource: Resource,
    rule: RuleSpec,
    cedar_bin: str | None = None,
    no_explain: bool = False,
) -> Violation | None:
    """Evaluate a single IRR resource against one Cedar rule.

    Returns a Violation if the rule forbids the configuration, None if allowed.
    """
    cedar_exec = cedar_bin or resolve_cedar_bin()
    policies_dir = _get_policies_dir()

    schema_path = str(policies_dir / "schema.cedarschema.json")
    # We need both the permit default and the specific rule policy
    # Cedar CLI can accept a directory, but we want to be explicit
    # Create a temp file combining both policies
    permit_policy = (policies_dir / "permit_default.cedar").read_text(encoding="utf-8")
    rule_policy = (policies_dir / rule.policy_file).read_text(encoding="utf-8")
    combined_policy = permit_policy + "\n" + rule_policy

    entities = _build_cedar_entities(resource, rule.entity_type)

    # Write temp files
    entity_path = None
    policy_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as ef:
            json.dump(entities, ef)
            entity_path = ef.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cedar", delete=False, encoding="utf-8"
        ) as pf:
            pf.write(combined_policy)
            policy_path = pf.name

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
            f'CedarGuard::Action::"{rule.action}"',
            "--resource",
            f'CedarGuard::{rule.entity_type}::"{resource.resource_id}"',
            "-v",
        ]

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = res.stdout + res.stderr

        # DENY means the forbid policy fired → violation found
        if "DENY" in output:
            if no_explain:
                # Fast path: skip Bedrock/cache entirely, template only.
                # Cedar's decision (pass/fail) never depends on this branch —
                # only the explanation text does (FR3, NFR6).
                expl = get_explanation(rule.rule_id)
            else:
                cache_key = f"{rule.rule_id}:{resource.resource_id}"
                expl = get_ai_explanation(
                    rule_id=rule.rule_id,
                    resource_id=resource.resource_id,
                    resource_type=resource.resource_type,
                    raw_snippet=resource.raw_snippet,
                    demo_cache=_load_demo_cache(),
                    cache_key=cache_key,
                )
            return Violation(
                rule_id=rule.rule_id,
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
        for path in (entity_path, policy_path):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass


def evaluate_resource(
    resource: Resource,
    cedar_bin: str | None = None,
    selected_rules: list[str] | None = None,
    no_explain: bool = False,
) -> list[Violation]:
    """Evaluate a resource against all applicable rules.

    Returns a list of Violations (may be empty if the resource is compliant).
    """
    violations: list[Violation] = []

    for rule in RULE_REGISTRY:
        # Filter by selected rules if specified
        if selected_rules and rule.rule_id not in selected_rules:
            continue

        # Only evaluate rules that match this resource type
        if rule.resource_type_match not in resource.resource_type:
            continue

        violation = evaluate_single_rule(resource, rule, cedar_bin, no_explain=no_explain)
        if violation is not None:
            violations.append(violation)

    return violations


def evaluate_resources(
    resources: list[Resource],
    cedar_bin: str | None = None,
    selected_rules: list[str] | None = None,
    no_explain: bool = False,
) -> list[Violation]:
    """Evaluate all resources against all applicable rules.

    Returns a combined list of all Violations found.
    """
    all_violations: list[Violation] = []
    for resource in resources:
        violations = evaluate_resource(resource, cedar_bin, selected_rules, no_explain=no_explain)
        all_violations.extend(violations)
    return all_violations
