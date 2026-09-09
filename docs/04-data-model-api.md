# Data Model & API Spec — CedarGuard

## 1. Internal Resource Representation (IRR)

The IRR is the provider-agnostic shape every parser must normalize into, and the
only shape the Cedar engine ever sees.

```json
{
  "resource_id": "MyPublicBucket",
  "resource_type": "AWS::S3::Bucket",
  "source_file": "infra/storage.yaml",
  "source_line": 14,
  "attributes": {
    "public_access_block": {
      "block_public_acls": false,
      "block_public_policy": false,
      "ignore_public_acls": false,
      "restrict_public_buckets": false
    },
    "acl": "public-read-write",
    "tags": { "Environment": "prod" }
  },
  "raw_snippet": "..."
}
```

For IAM-related resources:

```json
{
  "resource_id": "AdminRolePolicy",
  "resource_type": "AWS::IAM::Policy",
  "source_file": "infra/iam.yaml",
  "source_line": 42,
  "attributes": {
    "statements": [
      {
        "effect": "Allow",
        "action": ["*"],
        "resource": ["*"],
        "condition": {}
      }
    ]
  },
  "raw_snippet": "..."
}
```

For Security Groups:

```json
{
  "resource_id": "DbSecurityGroup",
  "resource_type": "AWS::EC2::SecurityGroup",
  "source_file": "infra/network.yaml",
  "source_line": 8,
  "attributes": {
    "ingress_rules": [
      { "protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr": "0.0.0.0/0" }
    ]
  },
  "raw_snippet": "..."
}
```

## 2. Cedar Entity Schema (excerpt)

```json
{
  "CedarGuard": {
    "entityTypes": {
      "S3Bucket": {
        "shape": {
          "type": "Record",
          "attributes": {
            "blockPublicAcls": { "type": "Boolean" },
            "blockPublicPolicy": { "type": "Boolean" },
            "acl": { "type": "String" }
          }
        }
      },
      "IamPolicy": {
        "shape": {
          "type": "Record",
          "attributes": {
            "hasWildcardAction": { "type": "Boolean" },
            "hasWildcardResource": { "type": "Boolean" },
            "hasMfaCondition": { "type": "Boolean" },
            "isSensitiveAction": { "type": "Boolean" }
          }
        }
      },
      "SecurityGroup": {
        "shape": {
          "type": "Record",
          "attributes": {
            "openIngressPorts": { "type": "Set", "element": { "type": "Long" } }
          }
        }
      },
      "Scanner": { "shape": { "type": "Record", "attributes": {} } }
    },
    "actions": {
      "EvaluateS3Public": { "appliesTo": { "principalTypes": ["Scanner"], "resourceTypes": ["S3Bucket"] } },
      "EvaluateIamWildcardAction": { "appliesTo": { "principalTypes": ["Scanner"], "resourceTypes": ["IamPolicy"] } },
      "EvaluateIamWildcardResource": { "appliesTo": { "principalTypes": ["Scanner"], "resourceTypes": ["IamPolicy"] } },
      "EvaluateSgOpenIngress": { "appliesTo": { "principalTypes": ["Scanner"], "resourceTypes": ["SecurityGroup"] } },
      "EvaluateMfaCondition": { "appliesTo": { "principalTypes": ["Scanner"], "resourceTypes": ["IamPolicy"] } }
    }
  }
}
```

## 3. Example Cedar Policy (R1 — S3 Public Bucket)

```cedar
// policies/r1_s3_public.cedar
forbid (
  principal,
  action == CedarGuard::Action::"EvaluateS3Public",
  resource
)
when {
  resource.acl == "public-read" ||
  resource.acl == "public-read-write" ||
  resource.blockPublicAcls == false
};
```

## 4. Violation Output Schema

This is the canonical shape emitted by the CLI (`--format json`) and consumed by
the GitHub Action and the Ship It Lambda's DynamoDB writer.

```json
{
  "rule_id": "R1-S3-PUBLIC",
  "severity": "CRITICAL",
  "resource_id": "MyPublicBucket",
  "resource_type": "AWS::S3::Bucket",
  "file": "infra/storage.yaml",
  "line": 14,
  "explanation": "This S3 bucket allows public read/write access, meaning anyone on the internet can list or modify its contents.",
  "suggested_fix": "Set BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls and RestrictPublicBuckets to true, and remove the public-read-write ACL.",
  "fix_snippet": "PublicAccessBlockConfiguration:\n  BlockPublicAcls: true\n  BlockPublicPolicy: true\n  IgnorePublicAcls: true\n  RestrictPublicBuckets: true",
  "detected_at": "2026-09-19T10:32:00Z"
}
```

Top-level scan result:

```json
{
  "scan_id": "b3f1...",
  "target": "./infra",
  "summary": { "total_resources": 12, "violations": 4, "critical": 2, "high": 1, "medium": 1 },
  "violations": [ /* array of violation objects above */ ]
}
```

## 5. CLI Interface Spec

```
cedarguard scan <path>
  --format text|json|sarif        (default: text)
  --fail-on critical|high|medium  (default: high)
  --no-explain                    (skip Bedrock/template explanation, faster)
  --rules R1,R2,...                (default: all)

cedarguard audit-log              (Ship It stretch — reads DynamoDB via API)
  --since 24h
  --format text|json
```

Exit codes: `0` = no blocking violations, `1` = blocking violations found,
`2` = internal error (parse failure, engine error).

## 6. Ship It API Surface (minimal)

### `POST /internal/evaluate` (invoked by Lambda internally, not public)
Triggered by EventBridge; input is the CloudTrail event detail, output is a
violation object (schema above) written to DynamoDB.

### `GET /audit-log` (API Gateway → Lambda, optional read view)
```
Query params: since (ISO8601 or "24h"/"7d"), severity
Response: { "results": [ <violation objects with account_id, event_source> ] }
```

### DynamoDB Table: `cedarguard-audit-log`
| Attribute | Type | Notes |
|---|---|---|
| `pk` | String | `ACCOUNT#<account_id>` |
| `sk` | String | `TS#<iso8601>#<rule_id>` |
| `rule_id` | String | |
| `severity` | String | |
| `resource_id` | String | |
| `explanation` | String | |
| `raw_event` | Map | original CloudTrail event (trimmed) |
| `ttl` | Number | optional expiry for demo cleanup |

## 7. GitHub Action Interface

`action.yml` inputs:
```yaml
inputs:
  path:
    description: 'Path to IaC directory to scan'
    default: '.'
  fail-on:
    description: 'Minimum severity that fails the check'
    default: 'high'
  github-token:
    required: true
```
Output: PR comment (upserted, identified by a hidden marker
`<!-- cedarguard-comment -->`) + a GitHub Check Run with pass/fail status.
