# CedarGuard — Hackathon Documentation Set

**First Commit** · Bharat Builds Tour · Sept 17–20, 2026

Infrastructure Policy & Security Guardrail Engine, built on Cedar + AWS.

## Contents

| # | Doc | What's in it |
|---|---|---|
| 01 | [PRD](01-PRD.md) | Problem, vision, goals, 5-rule set, user stories, risks |
| 02 | [Requirements](02-requirements.md) | Functional + non-functional requirements |
| 03 | [Architecture](03-architecture.md) | Component design, ADRs, AWS service map, repo layout |
| 04 | [Data Model & API Spec](04-data-model-api.md) | IRR schema, Cedar entity schema, violation output, CLI/API spec |
| 05 | [UI/UX Spec](05-ui-ux-spec.md) | CLI output design, PR comment format, demo video storyboard |
| 06 | [Engineering Rules](06-engineering-rules.md) | Coding conventions, testing, security hygiene, time-boxing |
| 07 | [Acceptance Criteria / DoD](07-acceptance-criteria.md) | Given/when/then criteria, submission checklist, rubric cross-check |
| 08 | [Project Context / AI Instructions](08-project-context-ai-instructions.md) | Paste-at-session-start context for Claude Code / AI pair programming |

## Suggested reading order

- **Before you write code:** 01 → 02 → 03 → 04
- **While building:** keep 04 (schemas) and 06 (rules) open as reference
- **Before recording the demo:** 05 §6 (storyboard) and 07 (acceptance criteria)
- **Every AI coding session:** paste the checklist in 08 §4

## Quick facts

- **Team size:** 1–4
- **Tracks:** Build It (local, Cedar + SAM/LocalStack) → Ship It (AWS deployed)
- **Committed deliverable:** local CLI + 5 Cedar rules + explanation layer + GitHub Action
- **Stretch deliverable:** live EventBridge → Lambda → Step Functions audit loop
- **Demo video:** ≤ 3 minutes, no live demo accepted — recorded video is the only thing judges see
