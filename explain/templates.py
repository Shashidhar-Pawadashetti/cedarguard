"""Fallback explanation templates for CedarGuard rules.

Used when Bedrock is unavailable, disabled (--no-explain), or in deterministic demo runs.
Reference: docs/04-data-model-api.md §4 and docs/06-engineering-rules.md §5
"""

from typing import Any

RULE_TEMPLATES: dict[str, dict[str, Any]] = {
    "R1-S3-PUBLIC": {
        "rule_id": "R1-S3-PUBLIC",
        "severity": "CRITICAL",
        "title": "S3 Bucket Public Access Enabled",
        "explanation": (
            "This S3 bucket allows public read/write access, meaning anyone on the "
            "internet can list or modify its contents."
        ),
        "suggested_fix": (
            "Set BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls and "
            "RestrictPublicBuckets to true, and remove public ACLs."
        ),
        "fix_snippet": (
            "PublicAccessBlockConfiguration:\n"
            "  BlockPublicAcls: true\n"
            "  BlockPublicPolicy: true\n"
            "  IgnorePublicAcls: true\n"
            "  RestrictPublicBuckets: true"
        ),
    },
    "R2-IAM-WILDCARD-ACTION": {
        "rule_id": "R2-IAM-WILDCARD-ACTION",
        "severity": "CRITICAL",
        "title": "IAM Policy Allows Wildcard Actions (*)",
        "explanation": (
            "This IAM policy grants Action: '*' across services, effectively giving "
            "unrestricted administrative permissions."
        ),
        "suggested_fix": (
            "Replace wildcard actions with specific, least-privilege actions "
            "required by the workload (e.g. s3:GetObject, dynamodb:Query)."
        ),
        "fix_snippet": ("Action:\n  - 's3:GetObject'\n  - 's3:PutObject'"),
    },
    "R3-IAM-WILDCARD-RESOURCE": {
        "rule_id": "R3-IAM-WILDCARD-RESOURCE",
        "severity": "HIGH",
        "title": "IAM Policy Applies to All Resources (*)",
        "explanation": (
            "This IAM policy permits actions on Resource: '*', allowing access "
            "to all resources of that type in the account."
        ),
        "suggested_fix": (
            "Scope the Resource element to specific ARNs rather than using '*'."
        ),
        "fix_snippet": ("Resource:\n  - 'arn:aws:s3:::my-specific-bucket/*'"),
    },
    "R4-SG-OPEN-INGRESS": {
        "rule_id": "R4-SG-OPEN-INGRESS",
        "severity": "HIGH",
        "title": "Security Group Ingress Open to 0.0.0.0/0 on Sensitive Ports",
        "explanation": (
            "This Security Group allows unrestricted inbound traffic (0.0.0.0/0) "
            "on sensitive ports (SSH 22, RDP 3389, or database ports)."
        ),
        "suggested_fix": (
            "Restrict the CIDR range to authorized IP blocks or security group references."
        ),
        "fix_snippet": ("CidrIp: '10.0.0.0/16'"),
    },
    "R5-NO-MFA-CONDITION": {
        "rule_id": "R5-NO-MFA-CONDITION",
        "severity": "MEDIUM",
        "title": "Sensitive IAM Action Permitted Without MFA Condition",
        "explanation": (
            "Privileged or sensitive actions are permitted without requiring "
            "multi-factor authentication (aws:MultiFactorAuthPresent condition)."
        ),
        "suggested_fix": (
            "Add a Condition block requiring aws:MultiFactorAuthPresent: 'true'."
        ),
        "fix_snippet": (
            "Condition:\n  Bool:\n    'aws:MultiFactorAuthPresent': 'true'"
        ),
    },
}


def get_explanation(rule_id: str) -> dict[str, Any]:
    """Retrieve fallback explanation data for a rule."""
    return RULE_TEMPLATES.get(
        rule_id,
        {
            "rule_id": rule_id,
            "severity": "HIGH",
            "title": f"Security policy violation: {rule_id}",
            "explanation": f"The resource violates CedarGuard policy rule {rule_id}.",
            "suggested_fix": "Review resource configuration and remediate according to security best practices.",
            "fix_snippet": "",
        },
    )
