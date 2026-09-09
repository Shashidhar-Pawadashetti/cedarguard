# PRD — CedarGuard
**Infrastructure Policy & Security Guardrail Engine**
Hackathon: First Commit (Bharat Builds Tour) · Sept 17–20, 2026
Tracks: Build It (local, Cedar + SAM/LocalStack) → Ship It (AWS: EventBridge, Step Functions, Lambda, Bedrock)

---

## 1. Problem Statement

Small engineering teams and student developers frequently ship misconfigured cloud
infrastructure — overly permissive IAM roles, public S3 buckets, open security groups,
missing MFA conditions — because there is no fast, local feedback loop that catches
these issues *before* code reaches production. Existing tools (AWS Config, third-party
scanners) are either heavyweight, cloud-only, or produce cryptic output that developers
ignore.

## 2. Vision

A lightweight, developer-first policy-as-code guardrail that:
1. Runs **locally**, in seconds, against IaC files (Terraform / CloudFormation / SAM)
   before anything is deployed.
2. Explains violations in **plain English** with a concrete fix, not a rule ID.
3. Can optionally run as a **CI check** (PR bot comment) and, once deployed, as a
   **continuous audit** against live AWS resource changes.

## 3. Target Users

| User | Need |
|---|---|
| Student / early-career developer | Wants to learn secure-by-default AWS patterns without reading 40-page docs |
| Small team / hackathon team | Needs a fast pre-deploy check with zero setup cost |
| Reviewer (in CI) | Wants violations surfaced on the PR, not discovered post-deploy |

## 4. Goals (this sprint)

- **G1** — Local CLI scans an IaC file/directory and reports violations against a
  curated rule set (5 rules) in under 5 seconds.
- **G2** — Each violation is translated into a plain-English explanation + suggested
  fix (Bedrock-assisted).
- **G3** — A GitHub Action posts findings as a PR comment.
- **G4** — (Ship It stretch) A deployed Lambda, triggered by EventBridge on real
  AWS resource changes (via CloudTrail), re-runs the same rule set and raises an
  alert via Step Functions.
- **G5** — Demo tells a clear story: broken repo → scan → human-readable findings →
  fix applied → clean scan.

## 5. Non-Goals (explicitly out of scope for this sprint)

- Full compliance framework coverage (CIS, SOC2, HIPAA, etc.) — 5 curated rules only.
- Multi-cloud support (AWS only).
- A hosted multi-tenant SaaS product, billing, auth, user accounts.
- Auto-remediation (auto-applying fixes without human review).
- Historical trend dashboards / long-term storage of scan results.

## 6. Success Metrics (for judging, not production KPIs)

| Criterion (from hackathon rubric) | How we hit it |
|---|---|
| Idea & Impact | Real, common failure mode every AWS beginner hits; quantifiable (cost/security risk) |
| Built on AWS | Cedar (mandatory OSS) + Bedrock + EventBridge/Step Functions/Lambda (Ship It) |
| Learning | First real use of Cedar policy language + Step Functions state machines |
| Execution | CLI + CI bot fully working end-to-end is the floor; live audit is the stretch |
| Demo video | 3-minute before/after narrative, see `07-acceptance-criteria.md` |

## 7. The Five Curated Rules (v1 rule set)

| ID | Rule | Why it matters |
|---|---|---|
| `R1-S3-PUBLIC` | S3 bucket has public read/write access | #1 cause of real-world data leaks |
| `R2-IAM-WILDCARD-ACTION` | IAM policy grants `Action: "*"` | Unbounded blast radius on credential compromise |
| `R3-IAM-WILDCARD-RESOURCE` | IAM policy grants `Resource: "*"` on a sensitive action | Same, resource-scoped version |
| `R4-SG-OPEN-INGRESS` | Security group allows `0.0.0.0/0` on a sensitive port (22, 3389, 5432, 3306...) | Direct exposure to internet scanning/brute force |
| `R5-NO-MFA-CONDITION` | IAM policy for a sensitive action lacks an MFA condition | Missing defense-in-depth on privileged actions |

Rule set is deliberately small and demoable — depth over breadth (see idea comparison
in prior discussion).

## 8. User Stories

1. *As a developer*, I run `cedarguard scan ./infra` and get a list of violations with
   file/line, severity, plain-English explanation, and a suggested fix diff.
2. *As a developer*, I open a PR and see a bot comment summarizing new violations
   introduced by my diff, so I don't have to leave GitHub.
3. *As a judge*, I watch a 3-minute video showing a genuinely broken sample repo,
   the tool catching it, and a fixed, clean re-scan.
4. *(Stretch) As a team lead*, once deployed, I get an alert within minutes if someone
   manually opens a security group on the live AWS account.

## 9. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Cedar policy authoring learning curve eats Day 1 | Timebox to 4 hours; fall back to a simpler regex/AST rule check wrapped as "Cedar-evaluated" for at least 2 rules if blocked |
| IaC parsing (HCL/Terraform) is fiddly | Support CloudFormation/SAM JSON/YAML first (easier to parse), Terraform as stretch |
| Real-time audit (EventBridge/Step Functions) not ready by Sunday | Treat as pure stretch goal; CLI + CI bot is the committed deliverable |
| Bedrock explanation calls add latency/cost during demo | Pre-cache explanations for the demo's fixed sample repo as fallback |
