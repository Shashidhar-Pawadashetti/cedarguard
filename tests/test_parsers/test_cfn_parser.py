"""Tests for CFN/SAM parser.

Tests parser against real-world-shaped demo-repo templates (not synthetic minimal
fixtures), per docs/06-engineering-rules.md §6.
"""

from pathlib import Path

from parsers.cfn_sam import parse_cfn_file, parse_directory


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
BROKEN_DIR = ROOT_DIR / "demo-repo" / "broken"
FIXED_DIR = ROOT_DIR / "demo-repo" / "fixed"


class TestStorageParser:
    """Test S3 bucket attribute extraction."""

    def test_parses_public_bucket_from_broken_template(self):
        resources = parse_cfn_file(BROKEN_DIR / "storage.yaml")
        bucket_ids = {r.resource_id for r in resources}
        assert "DataLakeBucket" in bucket_ids

        public_bucket = next(r for r in resources if r.resource_id == "DataLakeBucket")
        assert public_bucket.resource_type == "AWS::S3::Bucket"
        assert public_bucket.attributes["acl"] == "public-read"
        assert public_bucket.attributes["blockPublicAcls"] is False
        assert public_bucket.attributes["blockPublicPolicy"] is False

    def test_parses_private_bucket_from_broken_template(self):
        resources = parse_cfn_file(BROKEN_DIR / "storage.yaml")
        logs_bucket = next(r for r in resources if r.resource_id == "LogsBucket")
        assert logs_bucket.attributes["acl"] == "private"
        assert logs_bucket.attributes["blockPublicAcls"] is True
        assert logs_bucket.attributes["blockPublicPolicy"] is True

    def test_fixed_storage_all_private(self):
        resources = parse_cfn_file(FIXED_DIR / "storage.yaml")
        for r in resources:
            assert r.attributes["acl"] == "private"
            assert r.attributes["blockPublicAcls"] is True


class TestIamParser:
    """Test IAM policy attribute extraction."""

    def test_parses_wildcard_action(self):
        resources = parse_cfn_file(BROKEN_DIR / "iam.yaml")
        admin = next(r for r in resources if r.resource_id == "AdminRolePolicy")
        assert admin.attributes["hasWildcardAction"] is True

    def test_parses_wildcard_resource(self):
        resources = parse_cfn_file(BROKEN_DIR / "iam.yaml")
        pipeline = next(r for r in resources if r.resource_id == "DataPipelinePolicy")
        assert pipeline.attributes["hasWildcardResource"] is True

    def test_parses_sensitive_action_no_mfa(self):
        resources = parse_cfn_file(BROKEN_DIR / "iam.yaml")
        audit = next(r for r in resources if r.resource_id == "SecurityAuditPolicy")
        assert audit.attributes["isSensitiveAction"] is True
        assert audit.attributes["hasMfaCondition"] is False

    def test_fixed_iam_no_wildcards(self):
        resources = parse_cfn_file(FIXED_DIR / "iam.yaml")
        for r in resources:
            assert r.attributes["hasWildcardAction"] is False
            assert r.attributes["hasWildcardResource"] is False


class TestSecurityGroupParser:
    """Test SecurityGroup attribute extraction."""

    def test_parses_open_ingress_ports(self):
        resources = parse_cfn_file(BROKEN_DIR / "network.yaml")
        db_sg = next(r for r in resources if r.resource_id == "DatabaseSecurityGroup")
        assert 22 in db_sg.attributes["openIngressPorts"]
        assert 5432 in db_sg.attributes["openIngressPorts"]

    def test_parses_restricted_ingress_as_empty(self):
        resources = parse_cfn_file(BROKEN_DIR / "network.yaml")
        app_sg = next(r for r in resources if r.resource_id == "AppSecurityGroup")
        assert app_sg.attributes["openIngressPorts"] == []

    def test_fixed_network_no_open_ports(self):
        resources = parse_cfn_file(FIXED_DIR / "network.yaml")
        for r in resources:
            assert r.attributes["openIngressPorts"] == []


class TestDirectoryParser:
    """Test recursive directory parsing."""

    def test_broken_dir_finds_all_resources(self):
        resources = parse_directory(BROKEN_DIR)
        assert len(resources) == 7  # 2 S3 + 3 IAM + 2 SG

    def test_fixed_dir_finds_all_resources(self):
        resources = parse_directory(FIXED_DIR)
        assert len(resources) == 7

    def test_resource_types_are_correct(self):
        resources = parse_directory(BROKEN_DIR)
        types = {r.resource_type for r in resources}
        assert "AWS::S3::Bucket" in types
        assert "AWS::IAM::Policy" in types
        assert "AWS::EC2::SecurityGroup" in types
