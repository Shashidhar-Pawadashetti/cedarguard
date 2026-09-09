# UI/UX Specification — CedarGuard

CedarGuard is primarily a **developer tool**, so "UI" mostly means CLI output
quality and the GitHub PR comment — these ARE the product experience. There is one
optional minimal web view for the Ship It audit log.

## 1. Design Principles

1. **Signal over noise.** Never show more than what's actionable. Group by
   severity, most critical first.
2. **Plain English first, rule ID second.** Lead with the human explanation; the
   rule ID is metadata for filtering, not the headline.
3. **Show the fix, not just the flaw.** Every violation ends with a concrete
   suggested change (diff-style where possible).
4. **Consistent severity vocabulary and color:** `CRITICAL` (red), `HIGH`
   (orange), `MEDIUM` (yellow) — used identically in CLI, PR comment, and any web
   view.

## 2. CLI Output (Text Mode) — Primary Surface

```
CedarGuard scan · ./infra · 12 resources scanned

✖ 2 CRITICAL   ✖ 1 HIGH   ✖ 1 MEDIUM   ✓ 8 clean

──────────────────────────────────────────────────────────────
[CRITICAL] R1-S3-PUBLIC · infra/storage.yaml:14
  Resource: MyPublicBucket (AWS::S3::Bucket)

  This S3 bucket allows public read/write access — anyone on the
  internet can list or modify its contents.

  Suggested fix:
  + PublicAccessBlockConfiguration:
  +   BlockPublicAcls: true
  +   BlockPublicPolicy: true
  +   IgnorePublicAcls: true
  +   RestrictPublicBuckets: true

──────────────────────────────────────────────────────────────
[CRITICAL] R2-IAM-WILDCARD-ACTION · infra/iam.yaml:42
  Resource: AdminRolePolicy (AWS::IAM::Policy)

  This policy grants every possible action ("*") on every resource.
  If this credential is ever leaked, the blast radius is the entire
  account.

  Suggested fix:
  - Action: "*"
  + Action:
  +   - "s3:GetObject"
  +   - "s3:PutObject"

──────────────────────────────────────────────────────────────
Scan complete in 2.4s · exit code 1 (blocking violations found)
```

Design details:
- Header line always shows total scanned + a one-line severity summary before any
  detail (skimmable in a terminal).
- Each violation block is visually separated (`──`) for scan-ability.
- Diff-style (`+`/`-`) suggested fixes, colorized in terminal (green add, red
  remove) when TTY supports it; plain text otherwise.
- Final line always states exit code meaning explicitly — no ambiguity for CI logs.

## 3. CLI Output (JSON Mode)
Machine-readable, schema per `04-data-model-api.md` §4. No design opinions needed
beyond: stable field names, ISO8601 timestamps, never omit `null`/empty fields
(consumers shouldn't need optional-chaining surprises).

## 4. GitHub PR Comment

```markdown
### 🛡️ CedarGuard found 3 new issues in this PR

| Severity | Rule | Resource | File |
|---|---|---|---|
| 🔴 CRITICAL | S3 bucket is public | `MyPublicBucket` | `infra/storage.yaml:14` |
| 🔴 CRITICAL | IAM wildcard action | `AdminRolePolicy` | `infra/iam.yaml:42` |
| 🟠 HIGH | Security group open to internet | `DbSecurityGroup` | `infra/network.yaml:8` |

<details>
<summary>MyPublicBucket — public S3 bucket</summary>

This S3 bucket allows public read/write access — anyone on the internet
can list or modify its contents.

**Suggested fix:**
```yaml
PublicAccessBlockConfiguration:
  BlockPublicAcls: true
  BlockPublicPolicy: true
```
</details>

<!-- more <details> blocks per violation -->

_Powered by [CedarGuard](#) · Comment updates automatically on new commits._
<!-- cedarguard-comment -->
```

Design details:
- **One comment, updated in place** (never spam new comments per push) — identified
  by the hidden HTML marker.
- **Table first** for a fast scan; **collapsed `<details>`** per violation to avoid
  wall-of-text on large PRs.
- Emoji severity markers for fast visual triage in GitHub's rendered markdown.
- Footer states clearly that it self-updates, so reviewers trust the latest state.

## 5. (Ship It, Optional) Minimal Audit Log View

If time allows, a single static HTML page (S3-hosted or served via a small
Lambda) listing recent live findings — **not** a dashboard framework, just a
readable table:

```
CedarGuard — Live Audit Log (last 24h)

Time              Severity   Rule                        Resource
10:32 AM          CRITICAL   S3 bucket made public        prod-uploads-bucket
09:15 AM          HIGH       Security group opened        db-sg-prod
```

- No auth/login flow needed for demo — a single account/session is fine given
  scope.
- No charts, no filters beyond a simple severity dropdown if time permits — this
  view exists to prove the live loop works, not to be a product.

## 6. Demo Video Storyboard (ties UX to the judging "demo video" criterion)

1. **0:00–0:20** — State the problem in one sentence over a shot of a real (but
   anonymized) misconfigured bucket/policy.
2. **0:20–1:00** — Run `cedarguard scan ./demo-repo/broken` live in terminal; show
   the CLI output above.
3. **1:00–1:40** — Cut to a GitHub PR showing the same findings as a bot comment.
4. **1:40–2:20** — Apply the suggested fix, re-run scan → clean output (0
   violations, exit 0).
5. **2:20–2:50** — Cut to Ship It: show a live AWS console change (e.g., opening a
   security group) and the alert/audit-log entry appearing within seconds.
6. **2:50–3:00** — One sentence on what was learned (Cedar policy authoring +
   Step Functions) and AWS services used.

## 7. Accessibility & Usability Notes
- CLI must degrade gracefully to plain ASCII (no color/emoji) when `NO_COLOR` env
  var is set or output isn't a TTY (CI logs) — never break log parsers.
- PR comment markdown must render correctly on both github.com and the GitHub
  mobile app (avoid unsupported markdown extensions).
