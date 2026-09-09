# Project Context / AI Instructions — CedarGuard

Purpose: paste this (or point Claude Code / your AI assistant to this file) at the
start of every session during the hackathon so the assistant has consistent
context and doesn't re-litigate decisions already made. Pairs with
`06-engineering-rules.md`.

---

## 1. One-Paragraph Project Summary

CedarGuard is a policy-as-code security guardrail engine for infrastructure-as-
code. It parses CloudFormation/SAM (and, as stretch, Terraform) into a
provider-agnostic Internal Resource Representation, evaluates it against 5
curated Cedar policies covering common AWS misconfigurations (public S3, IAM
wildcards, open security groups, missing MFA conditions), and produces
plain-English explanations and suggested fixes (via Bedrock, with a template
fallback). It runs as a local CLI and a GitHub Action; a stretch goal wires the
same policy set into a live EventBridge → Lambda → Step Functions audit loop on
a real AWS account. Built for the First Commit hackathon (Sept 17–20, 2026,
Bharat Builds Tour).

## 2. Source of Truth Documents

When in doubt, defer to these files in this order:
1. `01-PRD.md` — what and why
2. `02-requirements.md` — functional/non-functional scope boundaries
3. `03-architecture.md` — component design, ADRs, repo layout
4. `04-data-model-api.md` — exact schemas (IRR, violation output, CLI flags, API)
5. `05-ui-ux-spec.md` — exact output formatting for CLI/PR comment
6. `06-engineering-rules.md` — how to write code in this repo
7. `07-acceptance-criteria.md` — what "done" means, what to demo

**If a request conflicts with these documents, flag the conflict rather than
silently picking one — these are the team's agreed scope for a 4-day sprint, and
scope drift is the biggest risk.**

## 3. Ground Rules for the AI Assistant

- **Don't expand scope unprompted.** If asked to "add a rule" or "support X IaC
  format," implement exactly what's asked using the existing IRR/parser/policy
  pattern — don't proactively add unrequested rules, formats, or dashboard
  features "while you're at it."
- **Cedar policies must be reviewed, not trusted blindly.** Generate the policy,
  but always also generate/update the paired violating + compliant test fixture
  in the same response, and state in plain English what the policy does so a
  human can sanity-check the logic against `01-PRD.md` §7.
- **Never fabricate AWS behavior.** If unsure whether a specific CloudTrail event
  name, EventBridge pattern, or Cedar syntax detail is correct, say so explicitly
  and suggest verifying against AWS/Cedar docs rather than presenting a guess as
  fact — this is exactly the kind of error that breaks a demo at the worst time.
- **Keep the demo path green.** Before making structural changes to the parser,
  engine, or CLI output shape, check that `demo-repo/broken` and `demo-repo/fixed`
  fixtures still produce the expected result — these are the acceptance-tested
  backbone of the submission.
- **Respect the fallback-first rule for explanations.** Any explanation-layer code
  must work with `--no-explain`/template fallback with zero network calls; Bedrock
  is additive, never a hard dependency for the CLI to function.
- **Timebox awareness.** If a requested task looks like it will take
  meaningfully longer than the relevant slot in the weekend schedule
  (`01-PRD.md` scoping section), say so up front and suggest what to cut, rather
  than silently building the full version.
- **No secrets, ever.** Never write real AWS account IDs, ARNs from a real
  account, credentials, or API keys into code, fixtures, docs, or commit
  messages — always use placeholder values (`123456789012`, `arn:aws:iam::
  123456789012:role/example`).

## 4. Session Startup Checklist (paste at top of a new AI session)

```
Context: CedarGuard, infra policy guardrail engine, built for First Commit
hackathon (4-day sprint, team of <N>). Stack: Python 3.11, Cedar policy engine,
AWS SAM/LocalStack (Build It), Bedrock + Lambda + EventBridge + Step Functions +
DynamoDB (Ship It stretch). Full spec in /docs (PRD, requirements, architecture,
data model, UI/UX, engineering rules, acceptance criteria).

Current status: [fill in — e.g. "Day 1, parser done, starting on R1-R2 policies"]
Today's goal: [fill in from the weekend scoping plan]

Rules: don't expand scope unprompted, always pair new Cedar policies with test
fixtures, never fabricate AWS/Cedar behavior — flag uncertainty instead, keep
demo-repo fixtures passing, no real credentials/account IDs anywhere.
```

## 5. Team Roles & Ownership (fill in with your actual team)

| Area | Owner | Docs to know well |
|---|---|---|
| Parsers + IRR | _______ | `03-architecture.md` §2.1, `04-data-model-api.md` §1 |
| Cedar policies + schema | _______ | `04-data-model-api.md` §2–3, `06-engineering-rules.md` §3 |
| CLI + explanation layer | _______ | `04-data-model-api.md` §5, `05-ui-ux-spec.md` §2–3 |
| GitHub Action | _______ | `04-data-model-api.md` §7, `05-ui-ux-spec.md` §4 |
| Ship It (Lambda/EventBridge/StepFn) | _______ | `03-architecture.md` §2.6, `04-data-model-api.md` §6 |
| Demo video + writeup | _______ | `05-ui-ux-spec.md` §6, `07-acceptance-criteria.md` §2 (AC5) |

## 6. Daily Checkpoint Ritual (recommended)

At the end of each day, confirm as a team (not just individually):
1. Does `cedarguard scan ./demo-repo/broken` still work end-to-end on `main`?
2. What's genuinely done vs. "90% done" (be honest — 90% done features are the
   #1 hackathon demo-day killer)?
3. Is today's stretch work actually additive, or did it silently eat time from
   tomorrow's committed deliverables?
4. Record a rough safety-net demo clip if anything customer-facing changed.

## 7. Links

- Hackathon page: https://www.wemakedevs.org/aws/first-commit
- Schedule: https://www.wemakedevs.org/aws/first-commit/schedule
- Rules: https://www.wemakedevs.org/aws/first-commit/rules
- AWS Builder Center: https://builder.aws.com
- In-person Bangalore day signup (Luma): https://luma.com/first-commit
