# CedarGuard

> **Policy-as-code infrastructure security guardrail engine powered by Cedar.**

[![CedarGuard CI](https://github.com/Shashidhar-Pawadashetti/cedarguard/actions/workflows/cedarguard.yml/badge.svg)](https://github.com/Shashidhar-Pawadashetti/cedarguard/actions/workflows/cedarguard.yml)
[![Tests](https://img.shields.io/badge/tests-95%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.14-blue.svg)]()
[![Cedar](https://img.shields.io/badge/cedar-v4.12.0-orange.svg)](https://www.cedarpolicy.com/)

---

## Overview

CedarGuard repurposes AWS Cedar's deterministic policy engine as a **static assertion and live security guardrail engine**:
- **Build It (Local / CI)**: Scans CloudFormation & SAM IaC templates, normalizes them into an Internal Resource Representation (IRR), asserts Cedar security policies, enriches findings with Amazon Bedrock (Claude Haiku 4.5) explanations, and blocks PRs via GitHub Actions.
- **Ship It (Live AWS Account)**: CloudTrail mutation events routed via EventBridge trigger a Step Functions workflow that normalizes live AWS resources with the same IRR adapters, runs the **exact same Cedar policies**, records findings into DynamoDB, and publishes alerts to SNS.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              BUILD IT (local)                           │
│                                                                         │
│   IaC files          CFN Parser              Cedar Policy Engine        │
│  (CFN/SAM YAML) ───▶ (parsers/*.py)     ───▶ (engine/cedar_engine.py)   │
│                              │                          │               │
│                              ▼                          ▼               │
│                     Internal Resource            Policy Decisions       │
│                     Representation (IRR)         (ALLOW / FORBID)       │
│                              │                          │               │
│                              └──────────┬───────────────┘               │
│                                         ▼                               │
│                              Explanation Layer                          │
│                        (Bedrock Claude Haiku 4.5 / Cache / Fallback)    │
│                                         │                               │
│                                         ▼                               │
│                          CLI Output (text / json / sarif)               │
│                                         │                               │
│                          ┌──────────────┴──────────────┐                │
│                          ▼                              ▼               │
│                 GitHub Action (PR comment)      Local terminal output   │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                         SHIP IT (live AWS audit loop)                   │
│                                                                         │
│  Live AWS Account (e.g. AuthorizeSecurityGroupIngress / PutBucketAcl)   │
│           │                                                             │
│           ▼                                                             │
│      CloudTrail ──▶ EventBridge Rule ──▶ Step Functions State Machine   │
│                                                  │                      │
│                                                  ▼                      │
│                                           Lambda Evaluator              │
│                                        (Live Adapter + Cedar)           │
│                                                  │                      │
│                                       ┌──────────┴──────────┐           │
│                                       ▼                     ▼           │
│                               SNS Security Alert    DynamoDB Audit Log  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## How to Test Locally (Build It Track — No AWS Account Needed)

### On Linux / macOS / WSL

```bash
# 1. Clone repository
git clone https://github.com/Shashidhar-Pawadashetti/cedarguard.git
cd cedarguard

# 2. Set up virtual environment and install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Get the real Cedar CLI binary
mkdir -p bin
curl -fsSL -o /tmp/cedar.tar.xz "https://github.com/cedar-policy/cedar/releases/download/cedar-policy-cli-v4.12.0/cedar-policy-cli-x86_64-unknown-linux-gnu.tar.xz"
tar -xJf /tmp/cedar.tar.xz -C /tmp
cp /tmp/cedar-policy-cli-x86_64-unknown-linux-gnu/cedar bin/cedar
chmod +x bin/cedar

# 4. Run the test suite (95 tests)
pytest -q

# 5. Run local scans
python -m cli.main scan ./demo-repo/broken   # Reports 5 violations, exits with code 1
python -m cli.main scan ./demo-repo/fixed    # Reports 0 violations (clean), exits with code 0
```

### On Windows (PowerShell)

```powershell
# 1. Set up virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Fetch the native Windows Cedar CLI binary
.\scripts\fetch_cedar_windows.ps1

# 3. Run the test suite (95 tests)
python -m pytest -q

# 4. Run local scans
python -m cli.main scan ./demo-repo/broken
python -m cli.main scan ./demo-repo/fixed
python -m cli.main audit-log
```

---

## Core Security Policies

All policies are written in declarative Cedar (`policies/*.cedar`) and use the `forbid` pattern:

| Rule ID | Cedar Action | Monitored Resource | Severity | Description |
|---|---|---|---|---|
| **`R1-S3-PUBLIC`** | `EvaluateS3Public` | `AWS::S3::Bucket` | **CRITICAL** | Forbids public-read/write ACLs and missing S3 PublicAccessBlock settings. |
| **`R2-IAM-WILDCARD-ACTION`** | `EvaluateIamWildcardAction` | `AWS::IAM::Policy` | **CRITICAL** | Forbids `Action: "*"` allowing unrestricted administrative AWS permissions. |
| **`R3-IAM-WILDCARD-RESOURCE`** | `EvaluateIamWildcardResource` | `AWS::IAM::Policy` | **HIGH** | Forbids `Resource: "*"` across IAM statements. |
| **`R4-SG-OPEN-INGRESS`** | `EvaluateSgOpenIngress` | `AWS::EC2::SecurityGroup` | **HIGH** | Forbids unrestricted ingress (`0.0.0.0/0`, `::/0`) on sensitive ports (SSH 22, RDP 3389, DB 5432/3306). |
| **`R5-NO-MFA-CONDITION`** | `EvaluateMfaCondition` | `AWS::IAM::Policy` | **MEDIUM** | Forbids sensitive IAM privilege mutations without `aws:MultiFactorAuthPresent`. |

---

## CLI Usage

```powershell
# Scan an IaC template or folder (default: colored human-readable text)
python -m cli.main scan ./demo-repo/broken

# Machine-readable output formats
python -m cli.main scan ./demo-repo/broken --format json
python -m cli.main scan ./demo-repo/broken --format sarif

# Ultra-fast local scan (skips Bedrock/enrichment)
python -m cli.main scan ./demo-repo/broken --no-explain

# Target specific policies
python -m cli.main scan ./demo-repo/broken --rules R1,R4

# Query live security audit log from DynamoDB
python -m cli.main audit-log --account 123456789012 --since 24h
```

---

## Ship It Deployment (Live AWS Audit Loop)

1. Fetch the prebuilt Cedar CLI binary for the Lambda Layer:
   ```bash
   ./scripts/fetch_cedar_layer.sh
   ```
2. Build and deploy via AWS SAM:
   ```bash
   sam build -t ship-it/infra.template.yaml
   sam deploy --guided
   ```

The deployed stack deploys:
- `CedarCliLayer`: Packages the Cedar CLI binary to `/opt/bin/cedar`.
- `CedarGuardEvaluatorFunction`: Python 3.11 Lambda using the `ship-it/live_resource_adapter.py` and `engine/evaluator.py`.
- `CedarGuardStateMachine`: Step Functions state machine with retry and catch blocks.
- `CedarGuardAuditLogTable`: DynamoDB table (`cedarguard-audit-log`).
- `CedarGuardAlertsTopic`: SNS topic (`cedarguard-alerts`).
- `CedarGuardCloudTrailRule`: EventBridge rule listening for CloudTrail mutation events.

---

## Architecture Highlights

1. **Identical Policies across Local & Cloud**: Both the local CLI and the live AWS Lambda evaluator execute the exact same Cedar policies (`policies/*.cedar`) and schema (`policies/schema.cedarschema.json`).
2. **Three-Tier Explanation Resolution**: AI explanations use Amazon Bedrock (`global.anthropic.claude-haiku-4-5-20251001-v1:0`), with automatic fallback to precomputed demo cache (`explain/demo_cache.json`) and deterministic templates (`explain/templates.py`).
3. **PR Diff-Only Reporting**: GitHub Action only reports newly introduced violations relative to the PR's base branch.
