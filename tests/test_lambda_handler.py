"""Unit tests for ship-it/lambda_handler.py, statemachine.asl.json, and infra.template.yaml.

Verifies end-to-end event evaluation, Step Functions state machine schema,
and CloudFormation/SAM infrastructure template validity.
"""

from __future__ import annotations

import json
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
        assert "RecordAuditLogDynamoDB" in branch_states_0

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
