"""AWS Lambda handlers for CedarGuard Ship It live security audit loop.

Provides:
- evaluate_handler: Evaluates CloudTrail events routed via EventBridge using
  the exact same Cedar policies and IRR normalization. Returns findings for
  Step Functions orchestration.
- audit_log_query_handler: Minimal query handler for reading audit log records
  from DynamoDB (consumed by API Gateway or CLI).

Reference: docs/03-architecture.md §2.6 and docs/04-data-model-api.md §6.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.evaluator import evaluate_resource
from engine.irr import Resource, Violation

_ship_it_dir = Path(__file__).resolve().parent
if str(_ship_it_dir) not in sys.path:
    sys.path.insert(0, str(_ship_it_dir))

try:
    from live_resource_adapter import cloudtrail_event_to_resource
except ImportError:
    from .live_resource_adapter import cloudtrail_event_to_resource


def _format_sns_alert(violation: Violation, account_id: str, resource: Resource) -> str:
    """Format a clean, urgent SNS security notification."""
    lines = [
        "🚨 CedarGuard Security Alert: Policy Violation Detected",
        "============================================================",
        f"Account ID:    {account_id}",
        f"Rule ID:       {violation.rule_id}",
        f"Severity:      {violation.severity}",
        f"Resource:      {violation.resource_id} ({violation.resource_type})",
        f"Event Source:  {resource.source_file}",
        "",
        "Issue Description:",
        f"  {violation.explanation}",
        "",
        "Suggested Remediation:",
        f"  {violation.suggested_fix}",
    ]
    if violation.fix_snippet:
        lines.extend([
            "",
            "Recommended Configuration Snippet:",
            f"{violation.fix_snippet}",
        ])
    lines.append("============================================================")
    return "\n".join(lines)


def _build_dynamodb_item(violation: Violation, account_id: str, timestamp: str, event_source: str) -> dict[str, Any]:
    """Build a DynamoDB PutItem payload matching docs/04-data-model-api.md §6."""
    return {
        "pk": {"S": f"ACCOUNT#{account_id}"},
        "sk": {"S": f"TS#{timestamp}#{violation.rule_id}"},
        "rule_id": {"S": violation.rule_id},
        "severity": {"S": violation.severity},
        "resource_id": {"S": violation.resource_id},
        "resource_type": {"S": violation.resource_type},
        "explanation": {"S": violation.explanation},
        "suggested_fix": {"S": violation.suggested_fix},
        "fix_snippet": {"S": violation.fix_snippet},
        "event_source": {"S": event_source},
        "detected_at": {"S": timestamp},
    }


def evaluate_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Main evaluation entry point for EventBridge / Step Functions.

    Accepts an EventBridge event containing a CloudTrail API call detail,
    normalizes it to an IRR Resource, evaluates against Cedar policies,
    and returns a structured payload for the Step Functions State Machine.
    """
    detail = event.get("detail", event)
    account_id = (
        event.get("account")
        or detail.get("recipientAccountId")
        or detail.get("userIdentity", {}).get("accountId")
        or "123456789012"
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    event_source = detail.get("eventSource", "aws:cloudtrail")

    resource: Resource | None = None

    # Check if this is a direct IRR payload (used in integration tests)
    if "resource_id" in event and "attributes" in event:
        resource = Resource(
            resource_id=event["resource_id"],
            resource_type=event.get("resource_type", "AWS::EC2::SecurityGroup"),
            source_file=event.get("source_file", "direct:invocation"),
            source_line=1,
            attributes=event["attributes"],
            raw_snippet=event.get("raw_snippet", ""),
        )
    else:
        resource = cloudtrail_event_to_resource(event)

    if resource is None:
        return {
            "has_violations": False,
            "violations": [],
            "total_violations": 0,
            "account_id": account_id,
            "message": "Event does not match any monitored IaC/CloudTrail resource type",
        }

    # Evaluate against the SAME Cedar policies used in CLI
    violations = evaluate_resource(resource)
    has_violations = len(violations) > 0

    serialized_violations: list[dict[str, Any]] = []
    dynamo_items: list[dict[str, Any]] = []
    sns_messages: list[str] = []

    for v in violations:
        serialized_violations.append({
            "rule_id": v.rule_id,
            "severity": v.severity,
            "resource_id": v.resource_id,
            "resource_type": v.resource_type,
            "explanation": v.explanation,
            "suggested_fix": v.suggested_fix,
            "fix_snippet": v.fix_snippet,
            "detected_at": timestamp,
        })
        dynamo_items.append(_build_dynamodb_item(v, account_id, timestamp, event_source))
        sns_messages.append(_format_sns_alert(v, account_id, resource))

    return {
        "has_violations": has_violations,
        "total_violations": len(violations),
        "account_id": account_id,
        "resource_id": resource.resource_id,
        "resource_type": resource.resource_type,
        "timestamp": timestamp,
        "violations": serialized_violations,
        # Fields consumed directly by Step Functions tasks:
        "first_dynamodb_item": dynamo_items[0] if dynamo_items else {},
        "all_dynamodb_items": dynamo_items,
        "sns_message": "\n\n".join(sns_messages) if sns_messages else "",
    }


def audit_log_query_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Query audit log findings from DynamoDB table."""
    params = event.get("queryStringParameters") or event
    account_id = params.get("account", "123456789012")
    limit = int(params.get("limit", 50))
    table_name = os.environ.get("AUDIT_LOG_TABLE", "cedarguard-audit-log")

    try:
        import boto3
        dynamodb = boto3.client("dynamodb")
        resp = dynamodb.query(
            TableName=table_name,
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": {"S": f"ACCOUNT#{account_id}"}},
            ScanIndexForward=False,  # Latest first
            Limit=limit,
        )
        items = []
        for raw in resp.get("Items", []):
            items.append({k: next(iter(v.values())) for k, v in raw.items()})
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"account_id": account_id, "findings": items}),
        }
    except Exception as e:
        # Graceful degradation for local/offline execution
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "account_id": account_id,
                "findings": [],
                "note": f"Audit log query offline fallback ({e})",
            }),
        }
