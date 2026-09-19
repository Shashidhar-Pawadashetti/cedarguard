"""Bedrock-backed explanation enrichment for CedarGuard violations.

Calls Amazon Bedrock to turn a Cedar policy violation into a plain-English
explanation + suggested fix. This is strictly an ENHANCEMENT layer:
- Pass/fail (Cedar's decision) never depends on this module.
- Any failure (no credentials, network error, timeout, throttling, malformed
  response) falls back to explain/templates.py silently — the CLI must keep
  working with zero AWS configuration (NFR2, NFR6).
- Never fabricates a violation: this module is only ever called for a
  resource Cedar has already flagged as FORBID.

Reference: docs/02-requirements.md FR3, docs/03-architecture.md §2.3,
docs/06-engineering-rules.md §5.
"""

from __future__ import annotations

import json
import os
from typing import Any

from explain.templates import get_explanation

# Keep the Bedrock call budget small — NFR6 says a live-audit Lambda must not
# block synchronously if it risks timing out, and the same discipline keeps
# the local CLI fast even with --no-explain unset.
_BEDROCK_TIMEOUT_SECONDS = 4
_DEFAULT_MODEL_ID = "global.anthropic.claude-haiku-4-5-20251001-v1:0"

_PROMPT_TEMPLATE = """You are a security reviewer. A policy engine flagged this \
infrastructure-as-code resource as a violation.

Rule violated: {rule_id}
Resource type: {resource_type}
Resource id: {resource_id}
Raw config snippet:
{raw_snippet}

Respond with ONLY a JSON object (no markdown fences, no preamble) with exactly \
these keys:
{{"explanation": "<1-2 plain-English sentences on why this is risky>", \
"suggested_fix": "<one sentence describing the fix>", \
"fix_snippet": "<minimal YAML/config snippet showing the fix, or empty string>"}}
"""


def _get_bedrock_client():
    """Lazily construct a boto3 bedrock-runtime client, or return None if unavailable."""
    try:
        import boto3
    except ImportError:
        return None

    region = os.environ.get("AWS_REGION", "us-east-1")
    try:
        return boto3.client("bedrock-runtime", region_name=region)
    except Exception:
        # No credentials configured, no AWS config file, etc. — this is an
        # expected/normal state for the Build It track (NFR2: zero required
        # AWS credentials), not an error worth surfacing to the user.
        return None


def _parse_model_response(raw_text: str) -> dict[str, str] | None:
    """Parse the model's JSON reply, tolerating minor formatting noise."""
    text = raw_text.strip()
    # Strip accidental markdown fences if the model adds them anyway.
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed, dict):
        return None
    if "explanation" not in parsed or "suggested_fix" not in parsed:
        return None
    return {
        "explanation": str(parsed.get("explanation", "")).strip(),
        "suggested_fix": str(parsed.get("suggested_fix", "")).strip(),
        "fix_snippet": str(parsed.get("fix_snippet", "")).strip(),
    }


def _invoke_bedrock(client: Any, model_id: str, prompt: str) -> str | None:
    """Call bedrock-runtime InvokeModel with an Anthropic-on-Bedrock request body."""
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 300,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        response = client.invoke_model(
            modelId=model_id,
            body=json.dumps(body),
            contentType="application/json",
            accept="application/json",
        )
        payload = json.loads(response["body"].read())
        content = payload.get("content", [])
        text_parts = [c.get("text", "") for c in content if c.get("type") == "text"]
        return "".join(text_parts) if text_parts else None
    except Exception:
        # Throttling, malformed response, network error, model-not-enabled,
        # etc. — all degrade to the template fallback, never raise.
        return None


def get_ai_explanation(
    rule_id: str,
    resource_id: str,
    resource_type: str,
    raw_snippet: str,
    demo_cache: dict[str, dict[str, str]] | None = None,
    cache_key: str | None = None,
) -> dict[str, str]:
    """Return an explanation dict for a violation, enriched by Bedrock when possible.

    Resolution order (per docs/06-engineering-rules.md §5):
      1. Cached demo response, if a cache + key were provided and it hits —
         keeps the recorded demo deterministic and network-free.
      2. Live Bedrock call, if boto3/credentials/model access are available.
      3. Template fallback (explain/templates.py) — always available, always
         the final safety net.

    Never raises; never returns an empty explanation.
    """
    template = get_explanation(rule_id)

    if demo_cache is not None and cache_key is not None and cache_key in demo_cache:
        cached = demo_cache[cache_key]
        return {**template, **cached}

    client = _get_bedrock_client()
    if client is None:
        return template

    model_id = os.environ.get("BEDROCK_MODEL_ID", _DEFAULT_MODEL_ID)
    prompt = _PROMPT_TEMPLATE.format(
        rule_id=rule_id,
        resource_type=resource_type,
        resource_id=resource_id,
        raw_snippet=raw_snippet or "(not available)",
    )

    raw_text = _invoke_bedrock(client, model_id, prompt)
    if raw_text is None:
        return template

    parsed = _parse_model_response(raw_text)
    if parsed is None:
        return template

    # Merge over the template so a partially-useful AI response (e.g. a good
    # explanation but empty fix_snippet) still benefits from the template's
    # fields rather than showing blank output.
    merged = dict(template)
    for key in ("explanation", "suggested_fix", "fix_snippet"):
        if parsed.get(key):
            merged[key] = parsed[key]
    return merged
