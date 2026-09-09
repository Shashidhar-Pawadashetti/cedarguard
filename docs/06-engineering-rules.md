# Coding / Engineering Rules — CedarGuard

These rules exist to keep a 1–4 person team moving fast for 4 days without
producing something unreviewable or undemoable. Optimize for **working and
explainable**, not for production hardening.

## 1. Language & Tooling
- **Primary language:** Python 3.11+ for CLI, parsers, explanation layer, Lambda
  handlers (consistency > polyglot cleverness under time pressure).
- **Cedar:** use the official `cedar-agent` (HTTP sidecar) or `cedar-policy`
  Python/Rust bindings — do not hand-roll a policy evaluator.
- **Package management:** `uv` or `pip + venv`, pinned in `requirements.txt`.
- **IaC for Ship It infra:** AWS SAM template (`ship-it/infra.template.yaml`) —
  matches the "SAM Local" Build It story and is fast to author.
- **Formatting/linting:** `ruff` (format + lint in one tool, fast, no config
  bikeshedding).

## 2. Repository Conventions
- One PR per feature slice (parser, one rule, explanation layer, CLI, CI action,
  ship-it path) — keeps review fast even under time pressure.
- Commit messages: `<area>: <what>` e.g. `policies: add R4 open ingress rule`.
- No commented-out code, no `TODO` without a linked issue/checklist item in
  `PLAN.md`.
- `main` branch must always run `cedarguard scan ./demo-repo/broken` successfully —
  never leave main in a broken state overnight (you need a working demo at every
  checkpoint, not just Sunday night).

## 3. Policy Authoring Rules (Cedar-specific)
- One rule = one `.cedar` file = one corresponding entry in the schema file. Never
  combine multiple checks into one policy (breaks the "add a rule = add a file"
  design goal and hurts explainability).
- Every policy file has a header comment: what it checks, why it matters, and one
  example of a resource that would trigger it.
- Every policy has a matching unit test in `tests/test_policies/` with **both** a
  violating and a compliant fixture — a rule without both is not done.
- Prefer `forbid` policies over trying to encode the "safe" case as `permit` —
  keeps each rule independently reason-about-able (a bug in one rule can't
  accidentally permit something another rule should catch).

## 4. Parser Rules
- Parsers only ever produce IRR objects (§04-data-model-api.md) — they must never
  leak provider-specific fields into the engine or explanation layer. If the
  engine needs a new attribute, add it to the IRR schema explicitly, don't pass
  raw provider JSON through "just this once."
- Parsers must fail loudly and specifically (which file, which line, what was
  expected) — never silently skip a resource it doesn't understand. Unparseable
  resources are reported as a `PARSE_WARNING`, not swallowed.

## 5. Explanation Layer Rules
- The template fallback (`explain/templates.py`) is not optional/nice-to-have —
  it must exist and be tested for all 5 rules before Bedrock integration is
  considered "done." Bedrock is an enhancement layer, not a dependency for core
  function.
- Never let a Bedrock call block the CLI exit code decision — violation
  pass/fail is decided by Cedar alone; explanation text is cosmetic and must be
  addable/retriable without re-running the scan.
- Cache Bedrock responses for the fixed demo-repo fixtures and check the cache
  file into the repo — the recorded demo must not depend on live network/model
  availability.

## 6. Testing Expectations (pragmatic, not exhaustive)
- Every rule: 1 violating fixture + 1 compliant fixture, asserted via CLI exit
  code and via direct Cedar decision.
- Every parser: at least one real-world-shaped sample file (not synthetic
  minimal JSON) to catch format assumptions early.
- No requirement for >80% coverage or similar vanity metrics — prioritize tests
  that would embarrass you in the demo if they failed.
- Run the full test suite before every merge to `main`; keep it under 30 seconds
  so nobody skips it under deadline pressure.

## 7. Security & Secrets Hygiene
- No AWS credentials, API keys, or account IDs committed to the repo, including
  in demo fixtures — use clearly fake values (`123456789012`, `example.com`).
- `.env` is gitignored; a `.env.example` documents required vars
  (`BEDROCK_MODEL_ID`, `AWS_REGION`, etc.).
- Ship It Lambda IAM role follows least privilege scoped to exactly the
  describe-calls and DynamoDB/SNS actions it needs — this is also a nice
  "we practice what we preach" demo beat.

## 8. Time-Boxing Rules (hackathon-specific)
- If a task exceeds its allotted block (see `01-PRD.md` §"Suggested weekend
  scoping") by more than 50%, stop and reassess scope — cut, don't silently
  extend, or the whole schedule slips.
- Anything not required for the committed demo path (CLI → CI bot → before/after)
  is a stretch goal and gets built only after the committed path is fully working
  and recorded as a backup demo.
- Record a "safety" demo video Saturday night even if it's not final — never risk
  having zero video if Sunday goes wrong.

## 9. AI-Assisted Coding Rules (for Claude Code / Copilot usage during the sprint)
- Always generate/modify one component at a time (parser, one policy, CLI
  command) — don't ask the assistant for the whole system in one shot; review
  each slice before moving on.
- Every AI-generated Cedar policy must be manually read and matched against the
  rule's plain-English definition in `01-PRD.md` §7 before being trusted — Cedar
  syntax errors fail loudly, but *logically wrong but valid* policies won't.
- Ask the assistant to write the test fixtures (violating + compliant) alongside
  any new policy or parser change in the same request, not as a follow-up
  afterthought.
