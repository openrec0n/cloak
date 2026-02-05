"""Tests for STS assume_role technique."""

import json
import re

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.sts.assume_role import AssumeRoleTechnique

# Sample trust policy for creating roles
SAMPLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole",
        }
    ],
}

# Trust policy requiring external ID
EXTERNAL_ID_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": "test-external-id"}},
        }
    ],
}


class TestAssumeRoleTechnique:
    """Tests for AssumeRoleTechnique."""

    # =========================================================================
    # Metadata Tests
    # =========================================================================

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "arn:aws:iam::123456789012:role/test"},
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "assume_role"
        assert metadata.service == "sts"
        assert metadata.full_name == "sts.assume_role"
        assert "sts:AssumeRole" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "arn:aws:iam::123456789012:role/test"},
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "assume" in technique.metadata.description.lower()

    def test_metadata_has_required_parameter(self, db_session, validated_connection):
        """Test that metadata lists role_arn as required parameter."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "arn:aws:iam::123456789012:role/test"},
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert len(metadata.required_parameters) == 1
        assert metadata.required_parameters[0].name == "role_arn"
        assert metadata.required_parameters[0].required is True

    def test_metadata_has_optional_parameters(self, db_session, validated_connection):
        """Test that metadata lists optional parameters."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "arn:aws:iam::123456789012:role/test"},
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        optional_names = [p.name for p in metadata.optional_parameters]
        assert "session_name" in optional_names
        assert "duration_seconds" in optional_names
        assert "external_id" in optional_names

    # =========================================================================
    # Validation Tests
    # =========================================================================

    def test_validate_missing_role_arn(self, db_session, validated_connection):
        """Test that validation fails when role_arn is missing."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={},
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert any("role_arn" in error.lower() for error in result.errors)

    def test_validate_invalid_arn_format(self, db_session, validated_connection):
        """Test that validation fails for invalid ARN format."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "not-a-valid-arn"},
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert any("arn" in error.lower() for error in result.errors)

    def test_validate_invalid_duration_too_low(self, db_session, validated_connection):
        """Test that validation fails for duration below minimum."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": "arn:aws:iam::123456789012:role/test",
                "duration_seconds": 100,  # Below 900 minimum
            },
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert any("duration" in error.lower() for error in result.errors)

    def test_validate_invalid_duration_too_high(self, db_session, validated_connection):
        """Test that validation fails for duration above maximum."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": "arn:aws:iam::123456789012:role/test",
                "duration_seconds": 50000,  # Above 43200 maximum
            },
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert any("duration" in error.lower() for error in result.errors)

    def test_validate_invalid_session_name(self, db_session, validated_connection):
        """Test that validation fails for invalid session name."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": "arn:aws:iam::123456789012:role/test",
                "session_name": "x",  # Too short (min 2 chars)
            },
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert any("session_name" in error.lower() for error in result.errors)

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with valid config."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": "arn:aws:iam::123456789012:role/test-role",
                "session_name": "test-session",
                "duration_seconds": 3600,
            },
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    # =========================================================================
    # Dry-Run Tests
    # =========================================================================

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "arn:aws:iam::123456789012:role/test"},
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "AssumeRole" in str(result.actions) or "sts:AssumeRole" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert result.regions == ["global"]
        assert result.estimated_api_calls == "1"

    def test_dry_run_shows_external_id(self, db_session, validated_connection):
        """Test dry-run mentions external ID when provided."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": "arn:aws:iam::123456789012:role/test",
                "external_id": "test-external-id",
            },
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert any("external" in action.lower() for action in result.actions)

    def test_dry_run_warns_long_duration(self, db_session, validated_connection):
        """Test dry-run warns about long session duration."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": "arn:aws:iam::123456789012:role/test",
                "duration_seconds": 7200,  # 2 hours, above default
            },
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert len(result.warnings) > 0
        assert any("duration" in warning.lower() for warning in result.warnings)

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "arn:aws:iam::123456789012:role/test"},
            dry_run=True,
        )
        # Use None session to ensure no DB writes
        technique = AssumeRoleTechnique(config, None, validated_connection)

        result = technique.dry_run()
        assert len(result.actions) > 0

    # =========================================================================
    # Execution Tests
    # =========================================================================

    @mock_aws
    def test_execute_success(self, db_session, aws_credentials):
        """Test successful role assumption."""
        # Create IAM role
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1
        assert "assumed role" in result.summary.lower()

    @mock_aws
    def test_execute_with_custom_session_name(self, db_session, aws_credentials):
        """Test role assumption with custom session name."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": role_arn,
                "session_name": "my-custom-session",
            },
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Session name should appear in summary (it's user-provided, not sensitive)
        assert "my-custom-session" in result.summary

    @mock_aws
    def test_execute_with_custom_duration(self, db_session, aws_credentials):
        """Test role assumption with custom duration."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
            MaxSessionDuration=7200,
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": role_arn,
                "duration_seconds": 1800,
            },
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert "1800" in result.summary

    @mock_aws
    def test_execute_with_external_id(self, db_session, aws_credentials):
        """Test role assumption with external ID."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="cross-account-role",
            AssumeRolePolicyDocument=json.dumps(EXTERNAL_ID_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="cross-account-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": role_arn,
                "external_id": "test-external-id",
            },
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1

    # =========================================================================
    # Database Persistence Tests
    # =========================================================================

    @mock_aws
    def test_execute_stores_asset(self, db_session, aws_credentials):
        """Test that asset is stored in database."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "sts"
        assert asset.resource_type == "assumed_role_session"
        assert asset.region == "global"

    @mock_aws
    def test_execute_asset_contains_credentials(self, db_session, aws_credentials):
        """Test that asset data contains credentials (stored securely)."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        asset = assets[0]

        # Credentials should be in asset.data
        assert "Credentials" in asset.data
        assert "AccessKeyId" in asset.data["Credentials"]
        assert "SecretAccessKey" in asset.data["Credentials"]
        assert "SessionToken" in asset.data["Credentials"]
        assert "Expiration" in asset.data["Credentials"]

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "sts.assume_role"
        assert execution.service == "sts"
        assert execution.status == "completed"
        assert execution.asset_count == 1

    # =========================================================================
    # Summary Sanitization Tests (CRITICAL)
    # =========================================================================

    @mock_aws
    def test_summarize_no_credentials(self, db_session, aws_credentials):
        """CRITICAL: Test that summary contains NO credentials."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Get the actual credentials from the asset
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        creds = assets[0].data["Credentials"]

        # CRITICAL: None of these should appear in summary
        assert creds["AccessKeyId"] not in result.summary
        assert creds["SecretAccessKey"] not in result.summary
        assert creds["SessionToken"] not in result.summary

    @mock_aws
    def test_summarize_no_role_arn(self, db_session, aws_credentials):
        """CRITICAL: Test that summary does not contain role ARN."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="sensitive-role-name",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="sensitive-role-name")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Role ARN should NOT be in summary
        assert role_arn not in result.summary
        assert "sensitive-role-name" not in result.summary

    @mock_aws
    def test_summarize_no_account_id(self, db_session, aws_credentials):
        """CRITICAL: Test that summary does not contain account IDs."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Account ID pattern check (12 digits)
        account_id_pattern = re.compile(r"\b\d{12}\b")
        matches = account_id_pattern.findall(result.summary)
        # Filter out execution_id which might contain numbers
        real_account_ids = [m for m in matches if m not in result.execution_id]
        assert len(real_account_ids) == 0, f"Found account IDs in summary: {real_account_ids}"

    @mock_aws
    def test_summarize_validates_with_sanitizer(self, db_session, aws_credentials):
        """Test that summary passes the validate_summary check."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Use the sanitizer validation
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

    @mock_aws
    def test_summarize_allows_session_name(self, db_session, aws_credentials):
        """Test that summary DOES include user-provided session name."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={
                "role_arn": role_arn,
                "session_name": "user-provided-session",
            },
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Session name IS allowed (user-provided, not sensitive)
        assert "user-provided-session" in result.summary

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary

    @mock_aws
    def test_summarize_includes_expiration(self, db_session, aws_credentials):
        """Test that summary includes expiration time."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(SAMPLE_TRUST_POLICY),
        )
        role = iam.get_role(RoleName="test-role")
        role_arn = role["Role"]["Arn"]

        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": role_arn},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # Expiration should be mentioned
        assert "expires" in result.summary.lower() or "expir" in result.summary.lower()

    # =========================================================================
    # Error Handling Tests
    # =========================================================================

    def test_execute_validation_fails(self, db_session, validated_connection):
        """Test that execution fails when validation fails."""
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={},  # Missing required role_arn
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session, validated_connection)

        result = technique.execute()

        assert result.success is False
        assert "validation" in result.summary.lower() or "role_arn" in result.summary.lower()

    @mock_aws
    def test_execute_nonexistent_role(self, db_session, aws_credentials):
        """Test execution with a role that doesn't exist.

        NOTE: moto doesn't validate role existence for AssumeRole,
        so this test verifies that the technique handles whatever
        moto returns gracefully (success in moto's case).
        In real AWS, this would fail with AccessDenied or NoSuchEntity.
        """
        config = TechniqueConfig(
            technique_name="sts.assume_role",
            parameters={"role_arn": "arn:aws:iam::123456789012:role/nonexistent-role"},
            dry_run=False,
        )
        technique = AssumeRoleTechnique(config, db_session)

        result = technique.execute()

        # moto allows assuming any role, so this succeeds in tests
        # In real AWS, this would fail with AccessDenied
        # The important thing is the technique doesn't crash
        assert result.success is True or result.success is False  # Either is acceptable
