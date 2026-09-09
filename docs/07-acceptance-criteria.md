# Acceptance Criteria / Definition of Done — CedarGuard

## 1. Definition of Done — per feature slice

A feature slice is **Done** only when:
- [ ] Code merged to `main` with passing tests.
- [ ] Unit tests exist for both violating and compliant cases (rules) or
      real-world-shaped fixtures (parsers).
- [ ] No secrets/credentials committed.
- [ ] Manually verified against the plain-English rule definition (not just "tests
      pass" — tests can be wrong too).
- [ ] Output reviewed for the UX rules in `05-ui-ux-spec.md` (severity color/label
      consistency, plain-English-first).

## 2. Acceptance Criteria — Committed Deliverables (must-have for submission)

### AC1 — Local CLI Scan (Build It, core)
- **Given** the `demo-repo/broken` sample, **when** running
  `cedarguard scan ./demo-repo/broken`, **then** all 5 planted violations are
  detected with correct rule IDs and severities, output completes in under 5
  seconds, and exit code is `1`.
- **Given** the `demo-repo/fixed` sample, **when** running the same scan,
  **then** zero violations are reported and exit code is `0`.

### AC2 — Explanation Layer
- **Given** any of the 5 violation types, **when** explanation is generated
  (Bedrock or fallback), **then** output includes a non-empty plain-English
  explanation and a non-empty suggested fix, and never fabricates a 6th rule or a
  violation Cedar didn't flag.

### AC3 — GitHub Action / PR Comment
- **Given** a PR that introduces one of the 5 violation types into an IaC file,
  **when** the CedarGuard Action runs, **then** exactly one PR comment is posted
  (or updated on subsequent pushes — never duplicated), listing the new
  violation(s), and the GitHub check status reflects the exit code.

### AC4 — Cedar Policies Are Independently Valid
- **Given** each `.cedar` policy file in isolation, **when** loaded against the
  schema, **then** it parses without error and its unit tests (violating +
  compliant fixture) both pass.

### AC5 — Demo Video
- **Given** the final recording, **when** watched start to finish, **then** it is
  ≤ 3 minutes, shows the broken → detected → fixed → clean loop, states what AWS
  services/OSS were used, and states what the team learned.

### AC6 — Submission Package Complete
- [ ] Public repo link (with this doc set included, e.g. under `/docs`).
- [ ] 3-minute demo video linked/uploaded.
- [ ] Short writeup published (AWS Builder Center blog counts toward the Top-5
      blog prize — see hackathon page).
- [ ] Builder ID / AWS Builder Center profile set up.
- [ ] Team confirms which track(s) are being submitted for (Build It / Ship It /
      Best UI eligibility is automatic across all submissions).

## 3. Acceptance Criteria — Stretch Deliverables (nice-to-have)

### AC7 — Live Audit Loop (Ship It stretch)
- **Given** a live, deployed test AWS account, **when** a security group is
  manually opened to `0.0.0.0/0` on a sensitive port, **then** within ~1 minute an
  entry appears in the DynamoDB audit log and an SNS notification fires.
- Acceptable partial credit: this can be demoed via a manually-triggered
  EventBridge test event if real CloudTrail propagation delay risks the demo
  timing — note this honestly in the video/writeup rather than implying it's
  always sub-minute in production.

### AC8 — Terraform Parser Support
- **Given** a Terraform `.tf` file with an equivalent violation (e.g., a public
  `aws_s3_bucket`), **when** scanned, **then** it's normalized into the same IRR
  and evaluated identically to the CloudFormation case — proving the
  parser/engine decoupling actually works.

### AC9 — SARIF Output
- **Given** `--format sarif`, **when** run, **then** output validates against the
  SARIF 2.1.0 schema and is consumable by GitHub's code-scanning UI.

### AC10 — Minimal Audit Log Web View
- A single static page reachable by URL shows the last 24h of live findings with
  no auth flow errors and correct severity styling matching the CLI/PR comment.

## 4. Non-Acceptance (would fail review even if "technically working")

- A demo that only works against a synthetic, trivially-minimal fixture (judges
  will notice if the "broken repo" looks fake/contrived vs. realistic).
- Any violation explanation that isn't grounded in an actual Cedar `FORBID`
  decision (i.e., hard-coded/hallucinated findings).
- A CI bot that spams a new comment on every push instead of updating one.
- Hard-coding AWS account IDs/credentials anywhere reachable in the repo history.
- A demo video that exceeds 3 minutes or relies on narration promising features
  that aren't actually shown working on screen.

## 5. Judging Rubric Cross-Check

Before submission, explicitly re-read each rubric line from the hackathon page
and confirm this project's writeup/video addresses it directly:
- **Idea & Impact** → AC5 states the real problem + who benefits, on screen.
- **Built on AWS** → AC1–AC4 (Cedar mandatory), AC7–AC9 (Ship It services) are
  visibly demonstrated, not just claimed in text.
- **Learning** → AC5/writeup explicitly states what was newly learned (Cedar,
  Step Functions, etc.).
- **Execution** → AC1–AC4 must work live/recorded, not "almost."
- **Demo video** → AC5, the only thing judges actually watch — treat as the
  single highest-leverage acceptance criterion.
