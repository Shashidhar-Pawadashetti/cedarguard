# Technical Design / Architecture — CedarGuard

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              BUILD IT (local)                            │
│                                                                            │
│   IaC files          Parser/Normalizer        Cedar Policy Engine        │
│  (CFN/SAM/TF)  ───▶  (parsers/*.py)     ───▶  (cedar-agent / cedar-cli)  │
│                              │                          │                 │
│                              ▼                          ▼                 │
│                     Internal Resource            Policy Decisions         │
│                     Representation (IRR)         (ALLOW/FORBID + rule)    │
│                              │                          │                 │
│                              └──────────┬───────────────┘                 │
│                                         ▼                                 │
│                              Explanation Layer                            │
│                        (Bedrock call OR template fallback)                │
│                                         │                                 │
│                                         ▼                                 │
│                          CLI Output (text / json / sarif)                 │
│                                         │                                 │
│                          ┌──────────────┴──────────────┐                  │
│                          ▼                              ▼                 │
│                 GitHub Action (PR comment)      Local terminal output     │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                         SHIP IT (stretch, deployed)                       │
│                                                                            │
│  Live AWS Account                                                        │
│   Resource change (e.g. PutBucketAcl)                                    │
│           │                                                              │
│           ▼                                                              │
│      CloudTrail ──▶ EventBridge Rule ──▶ Lambda (reuses IRR + Cedar)     │
│                                              │                            │
│                                              ▼                            │
│                                     Step Functions workflow               │
│                                     ┌─────────────────────┐               │
│                                     │ Evaluate → Notify →  │               │
│                                     │ Log to DynamoDB      │               │
│                                     └─────────────────────┘               │
│                                              │                            │
│                                              ▼                            │
│                              SNS/webhook alert + audit log (read view)    │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. Component Breakdown

### 2.1 Parser / Normalizer
- **Input:** raw IaC file (CloudFormation JSON/YAML, SAM template, Terraform HCL —
  stretch).
- **Output:** a list of `Resource` objects in the Internal Resource Representation
  (IRR) — a flattened, provider-agnostic shape (see `04-data-model-api.md`).
- **Design choice:** parse-then-normalize keeps the Cedar policies decoupled from IaC
  syntax. Adding Terraform support later only means writing a new parser, not
  touching policies.
- **Tech:** Python (`cfn-flip`/`pyyaml` for CFN; `python-hcl2` for Terraform stretch).

### 2.2 Cedar Policy Engine
- **What Cedar evaluates:** `(principal, action, resource, context)` against
  policies. We model it as: principal = "the scanner", action = the rule being
  checked (e.g., `Action::"S3BucketIsPublic"`), resource = the IRR resource,
  context = extra flags (e.g., `is_production: true`).
- **Why Cedar fits:** we're not doing runtime authorization — we're repurposing
  Cedar's policy evaluation as a **static assertion engine**: "FORBID this
  resource-shape from matching this action unless conditions hold." This is a
  legitimate, judge-visible use of Cedar (not just calling it once for show).
- **Execution:** invoke via the `cedar-agent` local service (HTTP) or the Rust
  `cedar` CLI/WASM bindings, called from the CLI process.
- **Policy files:** `policies/r1_s3_public.cedar`, `policies/r2_iam_wildcard_action.cedar`,
  etc. Each paired with a Cedar schema fragment describing the resource entity type.

### 2.3 Explanation Layer
- Input: a Cedar `FORBID` decision + the offending resource's raw config snippet.
- Calls Bedrock (Claude via Bedrock, or Titan) with a constrained prompt:
  *"Given this Cedar policy violation and this resource config, explain in 1–2
  plain-English sentences why this is risky, and suggest a minimal fix."*
- **Fallback:** a hand-written template per rule ID, used if Bedrock is unavailable/
  slow/rate-limited, and always used for the cached demo-repo run to keep the demo
  deterministic.

### 2.4 CLI (`cedarguard`)
- Entry point: `cedarguard scan <path> [--format text|json|sarif] [--fail-on
  <severity>]`.
- Orchestrates: parse → normalize → evaluate (Cedar) → explain → format output →
  set exit code.

### 2.5 GitHub Action
- Thin wrapper: checks out PR, runs CLI in `--format json`, diffs against base
  branch's violations (only report *new* ones), posts/updates a PR comment via
  GitHub API, sets check status from exit code.

### 2.6 (Ship It) Live Audit Path
- **CloudTrail** already logs management events; an **EventBridge rule** filters
  for the specific event names relevant to our 5 rules.
- **Lambda** receives the event, fetches the current resource state (via AWS SDK
  describe-calls), builds the same IRR shape, and re-runs the identical Cedar
  policies used locally (code reuse — this is the architectural point worth
  highlighting to judges).
- **Step Functions** sequences: Evaluate → Notify (SNS) → Log (DynamoDB) with
  retry/catch for the notify step.
- **DynamoDB** stores audit records for a minimal read view (`cedarguard
  audit-log` CLI command hitting an API Gateway + Lambda read endpoint, or a
  static S3-hosted page).

## 3. AWS Services Used (mapped to tracks)

| Service | Track | Purpose |
|---|---|---|
| Cedar | Both | Policy evaluation engine (core, mandatory) |
| SAM CLI / LocalStack | Build It | Simulate serverless resources locally without an AWS account |
| Amazon Bedrock | Both (degrades gracefully) | Plain-English explanation + fix suggestion |
| AWS Lambda | Ship It | Re-evaluation on live resource change |
| Amazon EventBridge | Ship It | Event routing from CloudTrail to Lambda |
| AWS Step Functions | Ship It | Orchestrate evaluate → notify → log |
| Amazon DynamoDB | Ship It | Audit log storage |
| Amazon SNS | Ship It | Alerting |
| API Gateway | Ship It (optional) | Expose read endpoint for audit log view |

## 4. Key Architectural Decisions (ADRs, abbreviated)

**ADR-1: Cedar as a static-assertion engine, not runtime authZ.**
Alternative considered: hand-rolled rule engine (regex/AST checks). Rejected because
Cedar is mandatory-for-prize-eligibility per rubric, and genuinely fits the "policy
as code" framing better than ad hoc code, and is a better learning story.

**ADR-2: Normalize to an Internal Resource Representation before policy evaluation.**
Decouples parsing (format-specific, messy) from policy logic (format-agnostic,
clean). Enables reusing identical Cedar policies for both the local CLI and the
live Lambda path — a genuine architecture win to call out in judging §2 (Built on
AWS) and §4 (execution/engineering quality).

**ADR-3: Explanation layer has a template fallback, always used for demo.**
Avoids demo fragility from live model latency/rate limits. Judges see the AI layer
is real (shown once live, ideally) but the recorded demo is deterministic.

**ADR-4: CloudFormation/SAM parsing prioritized over Terraform.**
JSON/YAML parsing is fast and low-risk; HCL parsing is a bigger time sink for
lower marginal demo value. Terraform support is explicitly a stretch goal.

## 5. Repository Structure

```
cedarguard/
├── cli/                     # CLI entry point & orchestration
│   └── main.py
├── parsers/
│   ├── cfn_sam.py
│   └── terraform.py         # stretch
├── policies/
│   ├── r1_s3_public.cedar
│   ├── r2_iam_wildcard_action.cedar
│   ├── r3_iam_wildcard_resource.cedar
│   ├── r4_sg_open_ingress.cedar
│   ├── r5_no_mfa_condition.cedar
│   └── schema.cedarschema.json
├── engine/
│   ├── evaluator.py          # calls Cedar, maps decisions
│   └── irr.py                # Internal Resource Representation models
├── explain/
│   ├── bedrock_client.py
│   └── templates.py          # fallback explanations
├── ci/
│   └── github_action/        # action.yml + comment poster script
├── ship-it/
│   ├── lambda_handler.py
│   ├── statemachine.asl.json
│   └── infra.template.yaml   # SAM template deploying EventBridge/Lambda/StepFn/DynamoDB
├── demo-repo/
│   ├── broken/                # planted violations
│   └── fixed/                 # after-state
├── tests/
│   ├── test_policies/         # one test file per rule
│   └── test_parsers/
└── docs/                      # this doc set
```
