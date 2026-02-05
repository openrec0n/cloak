"""Tests for IAM list_roles technique."""

import json

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.iam.list_roles import ListRolesTechnique

# Sample trust policy for creating roles
SAMPLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


class TestListRolesTechnique:
    """Tests for ListRolesTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
        )
        technique = ListRolesTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "list_roles"
        assert metadata.service == "iam"
        assert metadata.full_name == "iam.list_roles"
        assert "iam:ListRoles" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
        )
        technique = ListRolesTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "role" in technique.metadata.description.lower()

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with empty config."""
        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
        )
        technique = ListRolesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
        )
        technique = ListRolesTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "ListRoles" in str(result.actions) or "iam:ListRoles" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert result.regions == ["global"]
        assert "paginated" in result.estimated_api_calls.lower()

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=True,
        )
        technique = ListRolesTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    @mock_aws
    def test_execute_no_roles(self, db_session, aws_credentials):
        """Test execution with no roles (except AWS default roles)."""
        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)

        result = technique.execute()

        # moto may create some default roles, so we just check success
        assert result.success is True

    @mock_aws
    def test_execute_single_role(self, db_session, aws_credentials):
        """Test execution with single role."""
        # Create mock IAM role
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role-single",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count >= 1  # At least our role
        assert "role" in result.summary.lower()

    @mock_aws
    def test_execute_multiple_roles(self, db_session, aws_credentials):
        """Test execution with multiple roles."""
        # Create multiple mock IAM roles
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role-1",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        iam.create_role(
            RoleName="test-role-2",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        iam.create_role(
            RoleName="test-role-3",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count >= 3

    @mock_aws
    def test_execute_roles_with_different_paths(self, db_session, aws_credentials):
        """Test execution with roles in different paths."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="root-role",
            Path="/",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        iam.create_role(
            RoleName="service-role",
            Path="/service-role/",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Should mention path distribution
        assert "/" in result.summary

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role-stored",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) >= 1

        # Find our role
        our_role = next((a for a in assets if a.data.get("RoleName") == "test-role-stored"), None)
        assert our_role is not None
        assert our_role.service == "iam"
        assert our_role.resource_type == "iam_role"
        assert our_role.region == "global"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "iam.list_roles"
        assert execution.service == "iam"
        assert execution.status == "completed"
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_roles(self, db_session, validated_connection):
        """Test summary for zero roles."""
        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
        )
        technique = ListRolesTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No IAM roles" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_has_path_distribution(self, db_session, aws_credentials):
        """Test summary includes path distribution."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="role-1",
            Path="/",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        iam.create_role(
            RoleName="role-2",
            Path="/service-role/",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)
        result = technique.execute()

        # Summary should mention paths
        assert "/" in result.summary
        # Role names should NOT be in summary
        assert "role-1" not in result.summary
        assert "role-2" not in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_no_sensitive_data(self, db_session, aws_credentials):
        """CRITICAL: Test that summary contains NO sensitive data."""
        # Create roles with "sensitive" names
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="production-database-admin",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        iam.create_role(
            RoleName="secret-lambda-execution",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        iam.create_role(
            RoleName="customer-data-processor",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check role names are NOT in summary
        assert "production-database-admin" not in result.summary
        assert "secret-lambda-execution" not in result.summary
        assert "customer-data-processor" not in result.summary

    @mock_aws
    def test_asset_data_contains_required_fields(self, db_session, aws_credentials):
        """Test that asset data contains all required fields."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            Path="/service-role/",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
            Description="Test role description",
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        # Find our role
        asset = next((a for a in assets if a.data.get("RoleName") == "test-role"), None)
        assert asset is not None

        # Check required fields
        assert "RoleName" in asset.data
        assert "RoleId" in asset.data
        assert "Arn" in asset.data
        assert "Path" in asset.data
        assert "CreateDate" in asset.data
        assert "AssumeRolePolicyDocument" in asset.data
        assert asset.data["Path"] == "/service-role/"

    @mock_aws
    def test_asset_data_contains_trust_policy(self, db_session, aws_credentials):
        """Test that asset data contains the trust policy document."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role-with-trust",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        asset = next((a for a in assets if a.data.get("RoleName") == "test-role-with-trust"), None)
        assert asset is not None

        # Trust policy should be stored
        assert "AssumeRolePolicyDocument" in asset.data
        trust_policy = asset.data["AssumeRolePolicyDocument"]
        assert "Statement" in trust_policy

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_roles",
            parameters={},
            dry_run=False,
        )
        technique = ListRolesTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary
