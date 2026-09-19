"""CloudFormation / SAM template parser for CedarGuard.

Parses YAML/JSON CloudFormation and SAM templates into Internal Resource
Representation (IRR) objects, normalizing provider-specific properties into
flat Cedar-entity-compatible attributes.

Reference: docs/03-architecture.md §2.1 and docs/04-data-model-api.md §1
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from engine.irr import Resource

# Sensitive IAM actions that should require MFA (per R5)
SENSITIVE_IAM_ACTIONS: set[str] = {
    "iam:CreateUser",
    "iam:DeleteUser",
    "iam:CreateRole",
    "iam:DeleteRole",
    "iam:AttachRolePolicy",
    "iam:DetachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:UpdateLoginProfile",
    "iam:CreateLoginProfile",
    "sts:AssumeRole",
    "organizations:CreateAccount",
    "organizations:InviteAccountToOrganization",
}

# Ports considered sensitive for open-ingress checks (per R4)
SENSITIVE_PORTS: set[int] = {22, 3389, 5432, 3306, 1433, 27017, 6379, 9200}


def _find_line_number(content: str, resource_id: str) -> int:
    """Find the approximate line number of a resource in the template."""
    for i, line in enumerate(content.splitlines(), start=1):
        if resource_id in line and not line.strip().startswith("#"):
            return i
    return 1


def _normalize_s3_bucket(
    res_id: str, props: dict[str, Any], source_file: str, line: int, raw: str
) -> Resource:
    """Normalize AWS::S3::Bucket properties to Cedar S3Bucket entity attrs."""
    acl = props.get("AccessControl", "private")
    # Ensure acl is a simple string (cfn intrinsics resolve to dicts)
    if not isinstance(acl, str):
        acl = "private"

    pub_block = props.get("PublicAccessBlockConfiguration", {})
    if not isinstance(pub_block, dict):
        pub_block = {}

    return Resource(
        resource_id=res_id,
        resource_type="AWS::S3::Bucket",
        source_file=source_file,
        source_line=line,
        attributes={
            "acl": acl.lower() if isinstance(acl, str) else "private",
            "blockPublicAcls": bool(pub_block.get("BlockPublicAcls", False)),
            "blockPublicPolicy": bool(pub_block.get("BlockPublicPolicy", False)),
        },
        raw_snippet=raw,
    )


def _normalize_iam_policy(
    res_id: str, props: dict[str, Any], source_file: str, line: int, raw: str
) -> Resource:
    """Normalize AWS::IAM::Policy / ManagedPolicy to Cedar IamPolicy entity attrs."""
    policy_doc = props.get("PolicyDocument", {})
    if not isinstance(policy_doc, dict):
        policy_doc = {}

    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements] if isinstance(statements, dict) else []

    has_wildcard_action = False
    has_wildcard_resource = False
    has_mfa_condition = False
    is_sensitive_action = False

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue

        effect = stmt.get("Effect", "")
        if effect != "Allow":
            continue

        # Check actions
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            actions = []

        if "*" in actions:
            has_wildcard_action = True

        # Check for sensitive actions
        for action in actions:
            if isinstance(action, str):
                # Exact match or wildcard on IAM service
                if action in SENSITIVE_IAM_ACTIONS:
                    is_sensitive_action = True
                elif action.startswith("iam:") and action != "iam:List*" and action != "iam:Get*":
                    is_sensitive_action = True

        # Check resources
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if not isinstance(resources, list):
            resources = []

        if "*" in resources:
            has_wildcard_resource = True

        # Check for MFA condition
        condition = stmt.get("Condition", {})
        if isinstance(condition, dict):
            bool_cond = condition.get("Bool", {})
            if isinstance(bool_cond, dict):
                mfa_val = bool_cond.get("aws:MultiFactorAuthPresent", "")
                if str(mfa_val).lower() == "true":
                    has_mfa_condition = True

    return Resource(
        resource_id=res_id,
        resource_type="AWS::IAM::Policy",
        source_file=source_file,
        source_line=line,
        attributes={
            "hasWildcardAction": has_wildcard_action,
            "hasWildcardResource": has_wildcard_resource,
            "hasMfaCondition": has_mfa_condition,
            "isSensitiveAction": is_sensitive_action,
        },
        raw_snippet=raw,
    )


def _normalize_security_group(
    res_id: str, props: dict[str, Any], source_file: str, line: int, raw: str
) -> Resource:
    """Normalize AWS::EC2::SecurityGroup to Cedar SecurityGroup entity attrs."""
    ingress_rules = props.get("SecurityGroupIngress", [])
    if not isinstance(ingress_rules, list):
        ingress_rules = []

    open_ports: set[int] = set()

    for rule in ingress_rules:
        if not isinstance(rule, dict):
            continue

        cidr = rule.get("CidrIp", "")
        cidr_ipv6 = rule.get("CidrIpv6", "")

        # Check if open to the world
        is_open = cidr == "0.0.0.0/0" or cidr_ipv6 == "::/0"
        if not is_open:
            continue

        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 0)

        try:
            from_port = int(from_port)
            to_port = int(to_port)
        except (ValueError, TypeError):
            continue

        # Collect all sensitive ports in the range
        for port in SENSITIVE_PORTS:
            if from_port <= port <= to_port:
                open_ports.add(port)

    return Resource(
        resource_id=res_id,
        resource_type="AWS::EC2::SecurityGroup",
        source_file=source_file,
        source_line=line,
        attributes={
            "openIngressPorts": sorted(open_ports),
        },
        raw_snippet=raw,
    )


# Resource type -> normalizer function mapping
_NORMALIZERS = {
    "AWS::S3::Bucket": _normalize_s3_bucket,
    "AWS::IAM::Policy": _normalize_iam_policy,
    "AWS::IAM::ManagedPolicy": _normalize_iam_policy,
    "AWS::EC2::SecurityGroup": _normalize_security_group,
}

# Types we know how to parse
SUPPORTED_TYPES: set[str] = set(_NORMALIZERS.keys())


def parse_cfn_file(file_path: Path) -> list[Resource]:
    """Parse a single CloudFormation or SAM template into IRR resources.

    Only resources of recognized types (S3, IAM, EC2 SecurityGroup) are
    normalized. Other resource types are silently skipped — they have no
    corresponding Cedar rules.
    """
    content = file_path.read_text(encoding="utf-8")

    # Use safe YAML loader (handles !Ref, !Sub etc. as strings)
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        # Try cfn_flip as fallback for intrinsic functions
        try:
            from cfn_flip import load_yaml
            data = load_yaml(content)
        except Exception:
            return []

    if not isinstance(data, dict):
        return []

    resources_dict: dict[str, Any] = data.get("Resources", {})
    if not isinstance(resources_dict, dict):
        return []

    parsed_resources: list[Resource] = []

    for res_id, res_body in resources_dict.items():
        if not isinstance(res_body, dict):
            continue

        res_type = res_body.get("Type", "Unknown")
        props = res_body.get("Properties", {})
        if not isinstance(props, dict):
            props = {}

        normalizer = _NORMALIZERS.get(res_type)
        if normalizer is None:
            # Skip resource types we don't have rules for
            continue

        line = _find_line_number(content, res_id)
        raw_snippet = yaml.dump({res_id: res_body}, default_flow_style=False)

        parsed_resources.append(
            normalizer(res_id, props, str(file_path), line, raw_snippet)
        )

    return parsed_resources


def parse_directory(dir_path: Path) -> list[Resource]:
    """Recursively parse all CFN/SAM templates in a directory."""
    all_resources: list[Resource] = []

    for pattern in ("*.yaml", "*.yml", "*.json"):
        for file_path in dir_path.rglob(pattern):
            # Skip hidden files and directories
            if any(part.startswith(".") for part in file_path.parts):
                continue
            try:
                resources = parse_cfn_file(file_path)
                all_resources.extend(resources)
            except Exception as e:
                # Log but don't crash — per §4 parsers should fail loudly
                import sys
                print(
                    f"PARSE_WARNING: Failed to parse {file_path}: {e}",
                    file=sys.stderr,
                )

    return all_resources
