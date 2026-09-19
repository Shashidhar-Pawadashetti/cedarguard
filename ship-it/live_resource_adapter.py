"""Live AWS resource and CloudTrail event adapter for CedarGuard.

Converts live AWS SDK (boto3) describe responses or CloudTrail API call events
received via EventBridge into canonical Internal Resource Representation (IRR)
Resource objects.

This enables the exact same Cedar policies (policies/*.cedar) used for IaC
scanning to evaluate live AWS resources at runtime.

Reference: docs/03-architecture.md §2.6 and docs/04-data-model-api.md §1.
"""

from __future__ import annotations

import json
from typing import Any

from engine.irr import Resource

# Sensitive ports monitored for open-ingress (matches R4)
SENSITIVE_PORTS: set[int] = {22, 3389, 5432, 3306, 1433, 27017, 6379, 9200}

# Sensitive IAM actions requiring MFA (matches R5)
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

# AWS AllUsers group URI for public S3 grants
S3_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
S3_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def normalize_security_group_from_sdk(
    group_id: str,
    ip_permissions: list[dict[str, Any]],
    source: str = "aws:ec2:security-group",
) -> Resource:
    """Normalize EC2 DescribeSecurityGroups or CloudTrail IpPermissions into IRR Resource (R4)."""
    open_ports: set[int] = set()

    for perm in ip_permissions:
        if not isinstance(perm, dict):
            continue

        ranges = perm.get("IpRanges") or perm.get("ipRanges") or []
        if isinstance(ranges, dict):
            ranges = ranges.get("items", [])
        if not isinstance(ranges, list):
            ranges = [ranges]

        ipv6_ranges = perm.get("Ipv6Ranges") or perm.get("ipv6Ranges") or []
        if isinstance(ipv6_ranges, dict):
            ipv6_ranges = ipv6_ranges.get("items", [])
        if not isinstance(ipv6_ranges, list):
            ipv6_ranges = [ipv6_ranges]

        # Check IPv4 and IPv6 CIDRs
        is_open = False
        for ip_range in ranges:
            if isinstance(ip_range, dict):
                cidr = ip_range.get("CidrIp") or ip_range.get("cidrIp")
                if cidr in ("0.0.0.0/0", "::/0"):
                    is_open = True
                    break
        for ipv6_range in ipv6_ranges:
            if isinstance(ipv6_range, dict):
                cidr = ipv6_range.get("CidrIpv6") or ipv6_range.get("cidrIpv6")
                if cidr in ("::/0", "0.0.0.0/0"):
                    is_open = True
                    break

        if not is_open:
            continue

        ip_protocol = str(perm.get("IpProtocol") or perm.get("ipProtocol") or "")
        from_port = perm.get("FromPort") if perm.get("FromPort") is not None else perm.get("fromPort")
        to_port = perm.get("ToPort") if perm.get("ToPort") is not None else perm.get("toPort")

        try:
            from_port = int(from_port) if from_port is not None else None
            to_port = int(to_port) if to_port is not None else None
        except (ValueError, TypeError):
            pass

        if ip_protocol == "-1":
            # All ports open!
            open_ports.update(SENSITIVE_PORTS)
        elif from_port is not None and to_port is not None:
            for port in SENSITIVE_PORTS:
                if from_port <= port <= to_port:
                    open_ports.add(port)
        elif from_port is not None and from_port in SENSITIVE_PORTS:
            open_ports.add(from_port)

    return Resource(
        resource_id=group_id,
        resource_type="AWS::EC2::SecurityGroup",
        source_file=source,
        source_line=1,
        attributes={
            "openIngressPorts": sorted(open_ports),
        },
        raw_snippet=json.dumps({"GroupId": group_id, "IpPermissions": ip_permissions}, indent=2),
    )


def normalize_security_group_event(detail: dict[str, Any]) -> Resource | None:
    """Normalize an EC2 AuthorizeSecurityGroupIngress CloudTrail event."""
    params = detail.get("requestParameters", {})
    group_id = params.get("groupId") or params.get("groupName") or "UnknownSecurityGroup"

    # CloudTrail can package ingress permissions under ipPermissions or individual fields
    ip_permissions = []
    if "ipPermissions" in params and isinstance(params["ipPermissions"], dict):
        items = params["ipPermissions"].get("items", [])
        ip_permissions = items if isinstance(items, list) else [items]
    elif "ipPermissions" in params and isinstance(params["ipPermissions"], list):
        ip_permissions = params["ipPermissions"]
    else:
        # Single rule authorization format
        cidr = params.get("cidrIp")
        from_port = params.get("fromPort")
        to_port = params.get("toPort")
        proto = params.get("ipProtocol", "tcp")
        if cidr:
            ip_permissions = [{
                "IpProtocol": proto,
                "FromPort": from_port,
                "ToPort": to_port,
                "IpRanges": [{"CidrIp": cidr}],
            }]

    return normalize_security_group_from_sdk(
        group_id=group_id,
        ip_permissions=ip_permissions,
        source=f"cloudtrail:{detail.get('eventName', 'AuthorizeSecurityGroupIngress')}",
    )


def normalize_s3_bucket_from_sdk(
    bucket_name: str,
    acl_grants: list[dict[str, Any]] | None = None,
    public_access_block: dict[str, Any] | None = None,
    source: str = "aws:s3:bucket",
) -> Resource:
    """Normalize S3 bucket ACL & PublicAccessBlock into IRR Resource (R1)."""
    is_public_read = False
    is_public_write = False

    for grant in acl_grants or []:
        grantee = grant.get("Grantee", {})
        permission = grant.get("Permission", "")
        uri = grantee.get("URI", "")
        if uri in (S3_ALL_USERS_URI, S3_AUTH_USERS_URI):
            if permission in ("READ", "FULL_CONTROL"):
                is_public_read = True
            if permission in ("WRITE", "FULL_CONTROL"):
                is_public_write = True

    if is_public_write and is_public_read:
        acl_str = "public-read-write"
    elif is_public_read:
        acl_str = "public-read"
    else:
        acl_str = "private"

    pab = public_access_block or {}
    block_public_acls = bool(pab.get("BlockPublicAcls", False))
    block_public_policy = bool(pab.get("BlockPublicPolicy", False))

    return Resource(
        resource_id=bucket_name,
        resource_type="AWS::S3::Bucket",
        source_file=source,
        source_line=1,
        attributes={
            "acl": acl_str,
            "blockPublicAcls": block_public_acls,
            "blockPublicPolicy": block_public_policy,
        },
        raw_snippet=json.dumps(
            {"Bucket": bucket_name, "Grants": acl_grants, "PublicAccessBlock": pab}, indent=2
        ),
    )


def normalize_s3_event(detail: dict[str, Any]) -> Resource | None:
    """Normalize an S3 PutBucketAcl or PutPublicAccessBlock CloudTrail event."""
    params = detail.get("requestParameters", {})
    bucket_name = params.get("bucketName", "UnknownBucket")
    event_name = detail.get("eventName", "")

    acl_grants: list[dict[str, Any]] = []
    pab: dict[str, Any] = {}

    if "AccessControlPolicy" in params:
        acp = params["AccessControlPolicy"]
        if isinstance(acp, dict):
            acl_grants = acp.get("AccessControlList", {}).get("Grant", [])
    elif "x-amz-acl" in params:
        canned_acl = str(params["x-amz-acl"]).lower()
        if "public-read" in canned_acl:
            acl_grants = [{
                "Grantee": {"URI": S3_ALL_USERS_URI},
                "Permission": "READ",
            }]

    if "PublicAccessBlockConfiguration" in params:
        pab = params["PublicAccessBlockConfiguration"]

    return normalize_s3_bucket_from_sdk(
        bucket_name=bucket_name,
        acl_grants=acl_grants,
        public_access_block=pab,
        source=f"cloudtrail:{event_name}",
    )


def normalize_iam_policy_doc(
    policy_id: str,
    policy_doc: dict[str, Any] | str,
    source: str = "aws:iam:policy",
) -> Resource:
    """Normalize an IAM Policy Document into IRR Resource (R2, R3, R5)."""
    if isinstance(policy_doc, str):
        try:
            doc_dict = json.loads(policy_doc)
        except Exception:
            doc_dict = {}
    else:
        doc_dict = policy_doc

    statements = doc_dict.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        statements = []

    has_wildcard_action = False
    has_wildcard_resource = False
    has_mfa_condition = False
    is_sensitive_action = False

    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        elif not isinstance(actions, list):
            actions = []

        if "*" in actions:
            has_wildcard_action = True

        for act in actions:
            if isinstance(act, str) and (
                act in SENSITIVE_IAM_ACTIONS
                or (act.startswith("iam:") and not act.startswith("iam:Get") and not act.startswith("iam:List"))
            ):
                is_sensitive_action = True

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        elif not isinstance(resources, list):
            resources = []

        if "*" in resources:
            has_wildcard_resource = True

        conditions = stmt.get("Condition", {})
        if isinstance(conditions, dict):
            for val_map in conditions.values():
                if isinstance(val_map, dict):
                    for cond_key, cond_val in val_map.items():
                        if "MultiFactorAuthPresent" in cond_key and str(cond_val).lower() == "true":
                            has_mfa_condition = True

    return Resource(
        resource_id=policy_id,
        resource_type="AWS::IAM::Policy",
        source_file=source,
        source_line=1,
        attributes={
            "hasWildcardAction": has_wildcard_action,
            "hasWildcardResource": has_wildcard_resource,
            "hasMfaCondition": has_mfa_condition,
            "isSensitiveAction": is_sensitive_action,
        },
        raw_snippet=json.dumps({"Policy": policy_id, "Document": doc_dict}, indent=2),
    )


def normalize_iam_event(detail: dict[str, Any]) -> Resource | None:
    """Normalize an IAM CreatePolicy / PutRolePolicy CloudTrail event."""
    params = detail.get("requestParameters", {})
    policy_name = (
        params.get("policyName")
        or params.get("roleName")
        or params.get("userName")
        or "UnknownPolicy"
    )
    doc = params.get("policyDocument", {})
    return normalize_iam_policy_doc(
        policy_id=policy_name,
        policy_doc=doc,
        source=f"cloudtrail:{detail.get('eventName', 'IAMMutation')}",
    )


def cloudtrail_event_to_resource(event: dict[str, Any]) -> Resource | None:
    """Entry point: dispatch an EventBridge CloudTrail event to the right normalizer."""
    detail = event.get("detail", event)
    event_source = detail.get("eventSource", "")
    event_name = detail.get("eventName", "")

    if "ec2" in event_source or event_name.startswith("AuthorizeSecurityGroup"):
        return normalize_security_group_event(detail)
    elif "s3" in event_source or "Bucket" in event_name:
        return normalize_s3_event(detail)
    elif "iam" in event_source or "Policy" in event_name:
        return normalize_iam_event(detail)

    return None
