"""Unit tests for explain/bedrock_client.py.

Covers the resolution chain (demo cache -> live Bedrock -> template fallback)
without requiring real AWS credentials or network access — the live-call path
is exercised with a monkeypatched client so NFR2 (zero required AWS creds for
Build It) is never violated by the test suite itself.
Reference: docs/02-requirements.md FR3, docs/06-engineering-rules.md §5.
"""

from __future__ import annotations

import json

import pytest

from explain.bedrock_client import (
    _invoke_bedrock,
    _parse_model_response,
    get_ai_explanation,
)
from explain.templates import get_explanation


class _FakeBody:
    def __init__(self, payload: dict):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


class _FakeBedrockClient:
    """Stands in for a boto3 bedrock-runtime client."""

    def __init__(self, response_text: str | None = None, raise_error: bool = False):
        self._response_text = response_text
        self._raise_error = raise_error

    def invoke_model(self, **kwargs):
        if self._raise_error:
            raise RuntimeError("simulated Bedrock failure (throttling/network/etc.)")
        payload = {"content": [{"type": "text", "text": self._response_text}]}
        return {"body": _FakeBody(payload)}


class TestParseModelResponse:
    def test_parses_clean_json(self):
        raw = '{"explanation": "risky", "suggested_fix": "fix it", "fix_snippet": "x: true"}'
        parsed = _parse_model_response(raw)
        assert parsed == {"explanation": "risky", "suggested_fix": "fix it", "fix_snippet": "x: true"}

    def test_strips_markdown_fences(self):
        raw = '```json\n{"explanation": "risky", "suggested_fix": "fix it"}\n```'
        parsed = _parse_model_response(raw)
        assert parsed["explanation"] == "risky"

    def test_malformed_json_returns_none(self):
        assert _parse_model_response("not json at all") is None

    def test_missing_required_keys_returns_none(self):
        assert _parse_model_response('{"explanation": "only this"}') is None

    def test_non_dict_json_returns_none(self):
        assert _parse_model_response("[1, 2, 3]") is None


class TestInvokeBedrock:
    def test_extracts_text_from_content_blocks(self):
        client = _FakeBedrockClient(response_text='{"explanation": "e", "suggested_fix": "f"}')
        result = _invoke_bedrock(client, "model-id", "prompt")
        assert result == '{"explanation": "e", "suggested_fix": "f"}'

    def test_any_exception_returns_none_not_raise(self):
        client = _FakeBedrockClient(raise_error=True)
        # Must not raise -- this is the core NFR6/FR3 contract.
        result = _invoke_bedrock(client, "model-id", "prompt")
        assert result is None


class TestGetAiExplanationResolutionChain:
    """The three-tier fallback: cache -> live call -> template."""

    def test_cache_hit_short_circuits_and_preserves_template_severity(self):
        cache = {
            "R1-S3-PUBLIC:MyBucket": {
                "explanation": "cached text",
                "suggested_fix": "cached fix",
                "fix_snippet": "cached snippet",
            }
        }
        result = get_ai_explanation(
            "R1-S3-PUBLIC", "MyBucket", "AWS::S3::Bucket", "raw",
            demo_cache=cache, cache_key="R1-S3-PUBLIC:MyBucket",
        )
        assert result["explanation"] == "cached text"
        # Severity is a property of the rule, never overwritten by cache/AI.
        assert result["severity"] == get_explanation("R1-S3-PUBLIC")["severity"]

    def test_cache_miss_falls_through_past_cache(self):
        # Empty cache + no real AWS client available in test env -> template.
        result = get_ai_explanation(
            "R1-S3-PUBLIC", "OtherBucket", "AWS::S3::Bucket", "raw",
            demo_cache={}, cache_key="R1-S3-PUBLIC:OtherBucket",
        )
        assert result["explanation"] == get_explanation("R1-S3-PUBLIC")["explanation"]

    def test_no_client_available_falls_back_to_template(self, monkeypatch):
        import explain.bedrock_client as bc

        monkeypatch.setattr(bc, "_get_bedrock_client", lambda: None)
        result = get_ai_explanation("R4-SG-OPEN-INGRESS", "MySg", "AWS::EC2::SecurityGroup", "raw")
        assert result == get_explanation("R4-SG-OPEN-INGRESS")

    def test_live_call_success_merges_over_template(self, monkeypatch):
        import explain.bedrock_client as bc

        fake_client = _FakeBedrockClient(
            response_text=json.dumps(
                {
                    "explanation": "AI-generated explanation text",
                    "suggested_fix": "AI-generated fix",
                    "fix_snippet": "ai: true",
                }
            )
        )
        monkeypatch.setattr(bc, "_get_bedrock_client", lambda: fake_client)
        result = get_ai_explanation("R1-S3-PUBLIC", "MyBucket", "AWS::S3::Bucket", "raw")
        assert result["explanation"] == "AI-generated explanation text"
        assert result["severity"] == get_explanation("R1-S3-PUBLIC")["severity"]

    def test_live_call_failure_falls_back_to_template_never_raises(self, monkeypatch):
        import explain.bedrock_client as bc

        fake_client = _FakeBedrockClient(raise_error=True)
        monkeypatch.setattr(bc, "_get_bedrock_client", lambda: fake_client)
        result = get_ai_explanation("R2-IAM-WILDCARD-ACTION", "MyPolicy", "AWS::IAM::ManagedPolicy", "raw")
        assert result == get_explanation("R2-IAM-WILDCARD-ACTION")

    def test_live_call_malformed_response_falls_back_to_template(self, monkeypatch):
        import explain.bedrock_client as bc

        fake_client = _FakeBedrockClient(response_text="not valid json")
        monkeypatch.setattr(bc, "_get_bedrock_client", lambda: fake_client)
        result = get_ai_explanation("R3-IAM-WILDCARD-RESOURCE", "MyPolicy", "AWS::IAM::ManagedPolicy", "raw")
        assert result == get_explanation("R3-IAM-WILDCARD-RESOURCE")

    def test_partial_ai_response_keeps_template_for_missing_fields(self, monkeypatch):
        import explain.bedrock_client as bc

        # AI gives a good explanation but empty fix_snippet -- template's
        # fix_snippet should be kept rather than showing a blank one.
        fake_client = _FakeBedrockClient(
            response_text=json.dumps(
                {"explanation": "AI explanation", "suggested_fix": "AI fix", "fix_snippet": ""}
            )
        )
        monkeypatch.setattr(bc, "_get_bedrock_client", lambda: fake_client)
        result = get_ai_explanation("R1-S3-PUBLIC", "MyBucket", "AWS::S3::Bucket", "raw")
        assert result["explanation"] == "AI explanation"
        assert result["fix_snippet"] == get_explanation("R1-S3-PUBLIC")["fix_snippet"]

    @pytest.mark.parametrize("rule_id", ["R1-S3-PUBLIC", "R2-IAM-WILDCARD-ACTION", "R3-IAM-WILDCARD-RESOURCE",
                                          "R4-SG-OPEN-INGRESS", "R5-NO-MFA-CONDITION"])
    def test_never_returns_empty_explanation_for_any_rule(self, rule_id, monkeypatch):
        import explain.bedrock_client as bc

        monkeypatch.setattr(bc, "_get_bedrock_client", lambda: None)
        result = get_ai_explanation(rule_id, "SomeResource", "SomeType", "raw")
        assert result["explanation"]
        assert result["suggested_fix"]
