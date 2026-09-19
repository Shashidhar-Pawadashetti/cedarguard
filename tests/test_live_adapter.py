"""Unit tests for ship-it/live_resource_adapter.py.

Verifies that live AWS SDK outputs and EventBridge CloudTrail events are
correctly transformed into IRR Resource objects that evaluate properly
under Cedar policies (R1 through R5).
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "ship-it"))

from live_resource_adapter import (
    cloudtrail_event_to_resource,
    normalize_iam_policy_doc,
    normalize_s3_bucket_from_sdk,
    normalize_s3_event,
    normalize_security_group_event,
    normalize_security_group_from_sdk,
)

from engine.evaluator import evaluate_resource


class TestLiveSecurityGroupAdapter:
    """Tests for live Security Group normalization (R4-SG-OPEN-INGRESS)."""

    def test_open_ingress_port_22_and_5432_triggers_r4(self):
        ip_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ]
        res = normalize_security_group_from_sdk("sg-live-db", ip_permissions)
        assert res.resource_type == "AWS::EC2::SecurityGroup"
        assert res.attributes["openIngressPorts"] == [22, 5432]

        violations = evaluate_resource(res)
        assert len(violations) == 1
        assert violations[0].rule_id == "R4-SG-OPEN-INGRESS"
        assert violations[0].severity == "HIGH"

    def test_restricted_ingress_cidr_is_compliant(self):
        ip_permissions = [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "192.168.1.0/24"}],
            },
        ]
        res = normalize_security_group_from_sdk("sg-live-internal", ip_permissions)
        assert res.attributes["openIngressPorts"] == []

        violations = evaluate_resource(res)
        assert len(violations) == 0

    def test_cloudtrail_authorize_ingress_event(self):
        event_detail = {
            "eventSource": "ec2.amazonaws.com",
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {
                "groupId": "sg-99998888",
                "ipPermissions": {
                    "items": [
                        {
                            "ipProtocol": "tcp",
                            "fromPort": 3389,
                            "toPort": 3389,
                            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                        }
                    ]
                },
            },
        }
        res = normalize_security_group_event(event_detail)
        assert res is not None
        assert res.resource_id == "sg-99998888"
        assert 3389 in res.attributes["openIngressPorts"]

        violations = evaluate_resource(res)
        assert any(v.rule_id == "R4-SG-OPEN-INGRESS" for v in violations)


class TestLiveS3Adapter:
    """Tests for live S3 bucket normalization (R1-S3-PUBLIC)."""

    def test_public_read_acl_grant_triggers_r1(self):
        grants = [
            {
                "Grantee": {
                    "Type": "Group",
                    "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                },
                "Permission": "READ",
            }
        ]
        pab = {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
        }
        res = normalize_s3_bucket_from_sdk("acme-public-bucket", grants, pab)
        assert res.attributes["acl"] == "public-read"
        assert res.attributes["blockPublicAcls"] is False

        violations = evaluate_resource(res)
        assert len(violations) == 1
        assert violations[0].rule_id == "R1-S3-PUBLIC"
        assert violations[0].severity == "CRITICAL"

    def test_private_bucket_with_full_pab_is_compliant(self):
        res = normalize_s3_bucket_from_sdk(
            "acme-secure-bucket",
            acl_grants=[],
            public_access_block={"BlockPublicAcls": True, "BlockPublicPolicy": True},
        )
        assert res.attributes["acl"] == "private"
        assert res.attributes["blockPublicAcls"] is True

        violations = evaluate_resource(res)
        assert len(violations) == 0

    def test_cloudtrail_put_bucket_acl_event(self):
        event_detail = {
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketAcl",
            "requestParameters": {
                "bucketName": "data-lake-prod",
                "x-amz-acl": "public-read",
            },
        }
        res = normalize_s3_event(event_detail)
        assert res is not None
        assert res.resource_id == "data-lake-prod"
        assert res.attributes["acl"] == "public-read"


class TestLiveIamAdapter:
    """Tests for live IAM policy normalization (R2, R3, R5)."""

    def test_wildcard_action_triggers_r2(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::mybucket/*"}
            ],
        }
        res = normalize_iam_policy_doc("SuperAdminPolicy", doc)
        assert res.attributes["hasWildcardAction"] is True
        assert res.attributes["hasWildcardResource"] is False

        violations = evaluate_resource(res)
        assert any(v.rule_id == "R2-IAM-WILDCARD-ACTION" for v in violations)

    def test_wildcard_resource_triggers_r3(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}
            ],
        }
        res = normalize_iam_policy_doc("WildcardResourcePolicy", doc)
        assert res.attributes["hasWildcardResource"] is True
        assert res.attributes["hasWildcardAction"] is False

        violations = evaluate_resource(res)
        assert any(v.rule_id == "R3-IAM-WILDCARD-RESOURCE" for v in violations)

    def test_sensitive_action_without_mfa_triggers_r5(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:CreateUser", "iam:AttachRolePolicy"],
                    "Resource": "arn:aws:iam::123456789012:user/*",
                }
            ],
        }
        res = normalize_iam_policy_doc("SensitiveNoMfaPolicy", doc)
        assert res.attributes["isSensitiveAction"] is True
        assert res.attributes["hasMfaCondition"] is False

        violations = evaluate_resource(res)
        assert any(v.rule_id == "R5-NO-MFA-CONDITION" for v in violations)

    def test_sensitive_action_with_mfa_condition_is_compliant(self):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:CreateUser"],
                    "Resource": "arn:aws:iam::123456789012:user/*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ],
        }
        res = normalize_iam_policy_doc("SensitiveWithMfaPolicy", doc)
        assert res.attributes["isSensitiveAction"] is True
        assert res.attributes["hasMfaCondition"] is True

        violations = evaluate_resource(res)
        assert not any(v.rule_id == "R5-NO-MFA-CONDITION" for v in violations)

    def test_cloudtrail_event_to_resource_dispatcher(self):
        ec2_event = {
            "detail": {
                "eventSource": "ec2.amazonaws.com",
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {
                    "groupId": "sg-auto-dispatch",
                    "cidrIp": "0.0.0.0/0",
                    "fromPort": 22,
                    "toPort": 22,
                },
            }
        }
        res = cloudtrail_event_to_resource(ec2_event)
        assert res is not None
        assert res.resource_id == "sg-auto-dispatch"
