"""Unit tests for ship-it/lambda_handler.py, statemachine.asl.json, and infra.template.yaml.

Verifies end-to-end event evaluation, Step Functions state machine schema,
and CloudFormation/SAM infrastructure template validity.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "ship-it"))

from lambda_handler import audit_log_query_handler, evaluate_handler


class TestLambdaEvaluatorHandler:
    """Tests for evaluate_handler processing CloudTrail events."""

    def test_open_ingress_event_returns_violation_and_payloads(self):
        event = {
            "account": "112233445566",
            "detail": {
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-db-prod",
                    "cidrIp": "0.0.0.0/0",
                    "fromPort": 5432,
                    "toPort": 5432,
                },
            },
        }
        result = evaluate_handler(event)
        assert result["has_violations"] is True
        assert result["total_violations"] == 1
        assert result["account_id"] == "112233445566"
        assert result["resource_id"] == "sg-db-prod"

        violation = result["violations"][0]
        assert violation["rule_id"] == "R4-SG-OPEN-INGRESS"
        assert violation["severity"] == "HIGH"

        # Verify DynamoDB payload formatting for Step Functions
        dynamo_item = result["first_dynamodb_item"]
        assert dynamo_item["pk"]["S"] == "ACCOUNT#112233445566"
        assert "R4-SG-OPEN-INGRESS" in dynamo_item["sk"]["S"]
        assert dynamo_item["rule_id"]["S"] == "R4-SG-OPEN-INGRESS"

        # Verify SNS alert formatting
        sns_msg = result["sns_message"]
        assert "🚨 CedarGuard Security Alert" in sns_msg
        assert "R4-SG-OPEN-INGRESS" in sns_msg
        assert "sg-db-prod" in sns_msg

    def test_compliant_event_returns_no_violations(self):
        event = {
            "account": "112233445566",
            "detail": {
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-internal",
                    "cidrIp": "10.0.0.0/16",
                    "fromPort": 443,
                    "toPort": 443,
                },
            },
        }
        result = evaluate_handler(event)
        assert result["has_violations"] is False
        assert result["total_violations"] == 0
        assert result["violations"] == []

    def test_unsupported_event_gracefully_ignored(self):
        event = {
            "detail": {
                "eventSource": "dynamodb.amazonaws.com",
                "eventName": "CreateTable",
            }
        }
        result = evaluate_handler(event)
        assert result["has_violations"] is False
        assert "does not match" in result["message"]

    def test_audit_log_query_handler_offline_fallback(self):
        response = audit_log_query_handler({"account": "123456789012"})
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["account_id"] == "123456789012"
        assert "findings" in body


class TestStepFunctionsDefinition:
    """Validate Step Functions statemachine.asl.json."""

    def test_asl_json_is_valid_and_contains_expected_states(self):
        asl_path = ROOT_DIR / "ship-it" / "statemachine.asl.json"
        assert asl_path.exists()

        data = json.loads(asl_path.read_text(encoding="utf-8"))
        assert "StartAt" in data
        assert "States" in data

        states = data["States"]
        assert "EvaluateResourceEvent" in states
        assert "CheckForViolations" in states
        assert "CompliantResource" in states
        assert "ProcessViolations" in states
        assert "AuditWorkflowComplete" in states

        # Verify parallel branches for DynamoDB and SNS
        pv = states["ProcessViolations"]
        assert pv["Type"] == "Parallel"
        assert len(pv["Branches"]) == 2

        branch_states_0 = pv["Branches"][0]["States"]
        assert "RecordAllViolationsDynamoDB" in branch_states_0
        # DynamoDB writes now iterate over ALL violations for a resource via
        # a Map state (not just the first), since a single resource can trip
        # more than one rule (e.g. an IAM policy with both wildcard action
        # and wildcard resource) -- see docs/03-architecture.md §2.6.
        map_state = branch_states_0["RecordAllViolationsDynamoDB"]
        assert map_state["Type"] == "Map"
        assert map_state["ItemsPath"] == "$.all_dynamodb_items"
        assert "RecordAuditLogDynamoDB" in map_state["Iterator"]["States"]

        branch_states_1 = pv["Branches"][1]["States"]
        assert "PublishSnsSecurityAlert" in branch_states_1


class TestSamInfrastructureTemplate:
    """Validate CloudFormation / SAM infra.template.yaml."""

    def test_template_yaml_is_valid_and_declares_core_resources(self):
        tmpl_path = ROOT_DIR / "ship-it" / "infra.template.yaml"
        assert tmpl_path.exists()

        try:
            from cfn_flip import load_yaml
            data = load_yaml(tmpl_path.read_text(encoding="utf-8"))
        except ImportError:
            # Fallback if cfn_flip not available
            data = yaml.safe_load(tmpl_path.read_text(encoding="utf-8"))
        assert "Resources" in data
        resources = data["Resources"]

        assert "CedarGuardAlertsTopic" in resources
        assert resources["CedarGuardAlertsTopic"]["Type"] == "AWS::SNS::Topic"

        assert "CedarGuardAuditLogTable" in resources
        assert resources["CedarGuardAuditLogTable"]["Type"] == "AWS::DynamoDB::Table"

        assert "CedarGuardEvaluatorFunction" in resources
        assert resources["CedarGuardEvaluatorFunction"]["Type"] == "AWS::Serverless::Function"

        assert "CedarGuardStateMachine" in resources
        assert resources["CedarGuardStateMachine"]["Type"] == "AWS::StepFunctions::StateMachine"

        assert "CedarGuardCloudTrailRule" in resources
        assert resources["CedarGuardCloudTrailRule"]["Type"] == "AWS::Events::Rule"

    def test_cedar_cli_layer_declared_and_attached_to_evaluator(self):
        """Without this layer, LambdaCedarEngine's default /opt/bin/cedar
        never exists at runtime and every live evaluation fails on the
        Cedar binary lookup -- this is a functional requirement, not a
        nice-to-have. See engine/cedar_engine.py LambdaCedarEngine and
        scripts/fetch_cedar_layer.sh.
        """
        tmpl_path = ROOT_DIR / "ship-it" / "infra.template.yaml"
        try:
            from cfn_flip import load_yaml
            data = load_yaml(tmpl_path.read_text(encoding="utf-8"))
        except ImportError:
            data = yaml.safe_load(tmpl_path.read_text(encoding="utf-8"))
        resources = data["Resources"]

        assert "CedarCliLayer" in resources
        layer = resources["CedarCliLayer"]
        assert layer["Type"] == "AWS::Serverless::LayerVersion"
        assert "python3.11" in layer["Properties"]["CompatibleRuntimes"]

        fn_props = resources["CedarGuardEvaluatorFunction"]["Properties"]
        assert "Layers" in fn_props and len(fn_props["Layers"]) >= 1

    def test_fetch_cedar_layer_script_exists_and_is_executable(self):
        script_path = ROOT_DIR / "scripts" / "fetch_cedar_layer.sh"
        assert script_path.exists()
        assert os.access(script_path, os.X_OK)
