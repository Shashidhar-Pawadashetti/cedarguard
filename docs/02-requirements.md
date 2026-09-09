# Requirements — CedarGuard

## 1. Functional Requirements

### FR1 — Local CLI Scan
- FR1.1 `cedarguard scan <path>` accepts a file or directory of IaC configs
  (CloudFormation/SAM JSON or YAML; Terraform HCL as stretch).
- FR1.2 Parser normalizes each supported format into an internal resource
  representation (see `04-data-model-api.md`).
- FR1.3 Each normalized resource is evaluated against all active Cedar policies.
- FR1.4 Output includes: rule ID, severity, resource identifier, file path + line
  number (best-effort), plain-English explanation, suggested fix.
- FR1.5 Exit code is non-zero if any `HIGH` or `CRITICAL` severity violation is found
  (for CI gating).
- FR1.6 Supports `--format json|text|sarif` output (SARIF for GitHub code-scanning
  compatibility, stretch).

### FR2 — Policy Engine (Cedar)
- FR2.1 Each of the 5 rules (see PRD §7) is expressed as a Cedar policy plus a
  matching "entity schema" describing the resource shape.
- FR2.2 Policies are loaded from a `policies/*.cedar` directory; adding a rule =
  adding a file, no code change required.
- FR2.3 Engine returns `ALLOW`/`DENY`/`FORBID` decisions per (resource, rule) pair,
  which the CLI translates into pass/fail + severity.

### FR3 — Human-Readable Explanation Layer
- FR3.1 For each violation, call Bedrock (or a local rules-based template as
  fallback) to generate: a 1–2 sentence plain-English explanation, and a suggested
  fix (ideally as a diff/snippet).
- FR3.2 Explanations must be deterministic enough for a stable demo — cache results
  for the fixed demo repo so the video doesn't depend on live model calls.

### FR4 — CI Integration (GitHub Action)
- FR4.1 Action runs `cedarguard scan` against the PR's changed IaC files.
- FR4.2 Posts/updates a single PR comment listing new violations (not a comment per
  push).
- FR4.3 Fails the check (non-zero exit) on `HIGH`/`CRITICAL` findings; PR remains
  mergeable at maintainer discretion (non-blocking by default, configurable).

### FR5 — (Ship It / Stretch) Live Audit Loop
- FR5.1 CloudTrail → EventBridge rule filters for resource-mutation events relevant
  to the 5 rules (e.g., `PutBucketAcl`, `AuthorizeSecurityGroupIngress`,
  `PutRolePolicy`).
- FR5.2 EventBridge triggers a Lambda that re-evaluates the changed resource via the
  same Cedar policy set.
- FR5.3 On violation, Step Functions orchestrates: notify (SNS/webhook) → optionally
  open a tracking ticket (stub) → log to DynamoDB for the dashboard view.
- FR5.4 A minimal read view (could be CLI `cedarguard audit-log` or a static page)
  shows recent live findings.

### FR6 — Sample/Demo Repo
- FR6.1 A seeded sample repo (`/demo-repo`) contains realistic IaC with exactly the
  5 violation types planted, plus a "fixed" branch/version for the after-state.

## 2. Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR1 | Local scan of a directory with ≤50 resources completes in **< 5 seconds** (excluding first-run Bedrock calls). |
| NFR2 | CLI has **zero required AWS credentials** for the Build It path. |
| NFR3 | Explanation output must **never fabricate a rule** — if Cedar returns no violation, no explanation is generated for that resource. |
| NFR4 | All Cedar policies are **version-controlled, human-readable**, and independently testable (unit tests per policy). |
| NFR5 | CLI works on macOS/Linux (WSL acceptable on Windows) without needing a real AWS account for Build It track. |
| NFR6 | Ship It Lambda cold start should not block on Bedrock synchronously if it risks timing out — degrade to template-based explanation if Bedrock call exceeds ~2s budget. |
| NFR7 | Secrets (AWS creds, API keys) are never logged or included in CLI/CI output. |
| NFR8 | Codebase is small enough (~1,500–2,500 LOC) to be fully understood and demoed by a 1–4 person team in 4 days. |

## 3. Out-of-Scope Requirements (explicitly deferred)

- User authentication / multi-user accounts.
- Persistent hosted dashboard beyond a minimal read view.
- Auto-remediation (applying fixes automatically to the repo).
- Support for non-AWS providers (Azure/GCP policies).
- Full IaC diff/state tracking (Terraform state file parsing).
