"""Tests for IAM list_users technique."""

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.iam.list_users import ListUsersTechnique


class TestListUsersTechnique:
    """Tests for ListUsersTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
        )
        technique = ListUsersTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "list_users"
        assert metadata.service == "iam"
        assert metadata.full_name == "iam.list_users"
        assert "iam:ListUsers" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
        )
        technique = ListUsersTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "user" in technique.metadata.description.lower()

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with empty config."""
        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
        )
        technique = ListUsersTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
        )
        technique = ListUsersTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "ListUsers" in str(result.actions) or "iam:ListUsers" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert result.regions == ["global"]
        assert "paginated" in result.estimated_api_calls.lower()

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=True,
        )
        technique = ListUsersTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    @mock_aws
    def test_execute_no_users(self, db_session, aws_credentials):
        """Test execution with no users."""
        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 0
        assert result.finding_count == 0
        assert "No IAM users" in result.summary

    @mock_aws
    def test_execute_single_user(self, db_session, aws_credentials):
        """Test execution with single user."""
        # Create mock IAM user
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user-single")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1
        assert "1 user" in result.summary

    @mock_aws
    def test_execute_multiple_users(self, db_session, aws_credentials):
        """Test execution with multiple users."""
        # Create multiple mock IAM users
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user-1")
        iam.create_user(UserName="test-user-2")
        iam.create_user(UserName="test-user-3")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3
        assert "3 user" in result.summary

    @mock_aws
    def test_execute_users_with_different_paths(self, db_session, aws_credentials):
        """Test execution with users in different paths."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="root-user-1", Path="/")
        iam.create_user(UserName="root-user-2", Path="/")
        iam.create_user(UserName="admin-user-1", Path="/admin/")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3
        # Should mention path distribution
        assert "/" in result.summary
        assert "/admin/" in result.summary

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user-stored")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "iam"
        assert asset.resource_type == "iam_user"
        assert asset.region == "global"
        assert asset.data["UserName"] == "test-user-stored"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "iam.list_users"
        assert execution.service == "iam"
        assert execution.status == "completed"
        assert execution.asset_count == 1
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_users(self, db_session, validated_connection):
        """Test summary for zero users."""
        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
        )
        technique = ListUsersTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No IAM users" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_has_path_distribution(self, db_session, aws_credentials):
        """Test summary includes path distribution."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="user-1", Path="/")
        iam.create_user(UserName="user-2", Path="/admin/")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)
        result = technique.execute()

        # Summary should mention paths
        assert "/" in result.summary
        assert "/admin/" in result.summary
        # User names should NOT be in summary
        assert "user-1" not in result.summary
        assert "user-2" not in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_no_sensitive_data(self, db_session, aws_credentials):
        """CRITICAL: Test that summary contains NO sensitive data."""
        # Create users with "sensitive" names
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="admin-john-smith")
        iam.create_user(UserName="developer-jane-doe")
        iam.create_user(UserName="service-account-db")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check user names are NOT in summary
        assert "admin-john-smith" not in result.summary
        assert "developer-jane-doe" not in result.summary
        assert "service-account-db" not in result.summary

        # Should only contain counts and paths
        assert "3 user" in result.summary

    @mock_aws
    def test_asset_data_contains_required_fields(self, db_session, aws_credentials):
        """Test that asset data contains all required fields."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user", Path="/developers/")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        asset = assets[0]

        # Check required fields
        assert "UserName" in asset.data
        assert "UserId" in asset.data
        assert "Arn" in asset.data
        assert "Path" in asset.data
        assert "CreateDate" in asset.data
        assert asset.data["Path"] == "/developers/"

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="test-user")

        config = TechniqueConfig(
            technique_name="iam.list_users",
            parameters={},
            dry_run=False,
        )
        technique = ListUsersTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary
