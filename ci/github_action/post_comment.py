"""Post (or update) a single CedarGuard findings comment on a GitHub PR.

Reads scan JSON output (docs/04-data-model-api.md §4) from stdin or a file,
formats it per docs/05-ui-ux-spec.md §4, and upserts a PR comment identified
by a hidden HTML marker so re-runs on new commits update the same comment
instead of spamming new ones (AC3 in docs/07-acceptance-criteria.md).

Usage:
    python ci/github_action/post_comment.py --scan-json scan_result.json \
        --repo owner/name --pr-number 42 --token $GITHUB_TOKEN \
        [--base-scan-json base_scan_result.json]

If --base-scan-json is provided, only violations NOT present in the base
scan are reported as "new" (per FR4.2: report new violations, not every
pre-existing one on every push).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

COMMENT_MARKER = "<!-- cedarguard-comment -->"

SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",  # red circle
    "HIGH": "\U0001f7e0",  # orange circle
    "MEDIUM": "\U0001f7e1",  # yellow circle
    "LOW": "\U0001f535",  # blue circle
}


def _violation_key(v: dict) -> tuple:
    """Identity for de-duplicating a violation between base and PR scans."""
    return (v["rule_id"], v["resource_id"], v["file"])


def compute_new_violations(pr_violations: list[dict], base_violations: list[dict] | None) -> list[dict]:
    """Return violations present in the PR scan but not in the base scan.

    If base_violations is None (no base comparison requested/available),
    all PR violations are treated as reportable.
    """
    if base_violations is None:
        return pr_violations
    base_keys = {_violation_key(v) for v in base_violations}
    return [v for v in pr_violations if _violation_key(v) not in base_keys]


def build_comment_body(new_violations: list[dict], total_violations: int) -> str:
    """Render the PR comment markdown per docs/05-ui-ux-spec.md §4."""
    if not new_violations:
        if total_violations == 0:
            return (
                "### \U0001f6e1\ufe0f CedarGuard: no issues found\n\n"
                "This PR introduces no new infrastructure security violations.\n\n"
                f"_Powered by [CedarGuard](https://github.com/Shashidhar-Pawadashetti/cedarguard)."
                f" Comment updates automatically on new commits._\n{COMMENT_MARKER}"
            )
        return (
            "### \U0001f6e1\ufe0f CedarGuard: no *new* issues in this PR\n\n"
            f"{total_violations} pre-existing violation(s) remain in the target branch "
            "but nothing new was introduced by this PR.\n\n"
            f"_Powered by [CedarGuard](https://github.com/Shashidhar-Pawadashetti/cedarguard)."
            f" Comment updates automatically on new commits._\n{COMMENT_MARKER}"
        )

    n = len(new_violations)
    lines: list[str] = [f"### \U0001f6e1\ufe0f CedarGuard found {n} new issue{'s' if n != 1 else ''} in this PR", ""]

    lines.append("| Severity | Rule | Resource | File |")
    lines.append("|---|---|---|---|")
    for v in new_violations:
        emoji = SEVERITY_EMOJI.get(v["severity"].upper(), "\u26aa")
        title = v.get("explanation", "").split(".")[0]
        lines.append(
            f"| {emoji} {v['severity']} | {title} | `{v['resource_id']}` | "
            f"`{v['file']}:{v['line']}` |"
        )
    lines.append("")

    for v in new_violations:
        lines.append(f"<details>\n<summary>{v['resource_id']} — {v['rule_id']}</summary>\n")
        lines.append(v.get("explanation", ""))
        lines.append("")
        fix_snippet = v.get("fix_snippet") or ""
        if fix_snippet:
            lines.append("**Suggested fix:**")
            lines.append("```yaml")
            lines.append(fix_snippet)
            lines.append("```")
        else:
            lines.append(f"**Suggested fix:** {v.get('suggested_fix', '')}")
        lines.append("\n</details>\n")

    lines.append(
        "_Powered by [CedarGuard](https://github.com/Shashidhar-Pawadashetti/cedarguard)."
        " Comment updates automatically on new commits._"
    )
    lines.append(COMMENT_MARKER)
    return "\n".join(lines)


def _gh_api(url: str, token: str, method: str = "GET", data: dict | None = None) -> dict | list:
    """Minimal GitHub REST API helper using stdlib only (no extra CI deps)."""
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        print(f"GitHub API error {e.code} for {method} {url}: {e.read().decode()}", file=sys.stderr)
        raise


def upsert_pr_comment(repo: str, pr_number: int, token: str, body: str) -> None:
    """Find an existing CedarGuard comment on the PR and update it, or create one."""
    comments_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    existing = _gh_api(comments_url, token)

    existing_id = None
    for c in existing:
        if COMMENT_MARKER in c.get("body", ""):
            existing_id = c["id"]
            break

    if existing_id is not None:
        update_url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_id}"
        _gh_api(update_url, token, method="PATCH", data={"body": body})
        print(f"Updated existing CedarGuard comment (id={existing_id}) on PR #{pr_number}")
    else:
        _gh_api(comments_url, token, method="POST", data={"body": body})
        print(f"Created new CedarGuard comment on PR #{pr_number}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Post CedarGuard findings as a PR comment.")
    parser.add_argument("--scan-json", required=True, help="Path to CedarGuard --format json output for the PR")
    parser.add_argument("--base-scan-json", default=None, help="Optional path to scan output for the base branch")
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--token", required=True)
    parser.add_argument("--dry-run", action="store_true", help="Print comment body instead of posting")
    args = parser.parse_args(argv)

    with open(args.scan_json, encoding="utf-8") as f:
        pr_scan = json.load(f)

    base_violations = None
    if args.base_scan_json:
        try:
            with open(args.base_scan_json, encoding="utf-8") as f:
                base_violations = json.load(f).get("violations", [])
        except FileNotFoundError:
            print(f"Warning: base scan file {args.base_scan_json} not found, treating all violations as new",
                  file=sys.stderr)

    pr_violations = pr_scan.get("violations", [])
    new_violations = compute_new_violations(pr_violations, base_violations)
    body = build_comment_body(new_violations, total_violations=len(pr_violations))

    if args.dry_run:
        print(body)
        return 0

    upsert_pr_comment(args.repo, args.pr_number, args.token, body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
