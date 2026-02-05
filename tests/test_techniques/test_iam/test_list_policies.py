"""Tests for IAM list_policies technique."""

import json

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.iam.list_policies import ListPoliciesTechnique

# Sample policy document
SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
}


class TestListPoliciesTechnique:
    """Tests for ListPoliciesTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "list_policies"
        assert metadata.service == "iam"
        assert metadata.full_name == "iam.list_policies"
        assert "iam:ListPolicies" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "polic" in technique.metadata.description.lower()

    def test_metadata_has_scope_parameter(self, db_session, validated_connection):
        """Test that metadata defines the scope parameter."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        # Should have required parameter for scope
        assert len(technique.metadata.required_parameters) == 1
        scope_param = technique.metadata.required_parameters[0]
        assert scope_param.name == "scope"
        assert scope_param.choices == ["Local", "AWS", "All"]

    def test_validate_success_local(self, db_session, validated_connection):
        """Test that validation passes with scope=Local."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_success_aws(self, db_session, validated_connection):
        """Test that validation passes with scope=AWS."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "AWS"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_success_all(self, db_session, validated_connection):
        """Test that validation passes with scope=All."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "All"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_missing_scope(self, db_session, validated_connection):
        """Test that validation fails when scope is missing."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert "scope parameter is required" in result.errors[0]

    def test_validate_invalid_scope(self, db_session, validated_connection):
        """Test that validation fails with invalid scope value."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Invalid"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert "Local" in result.errors[0]
        assert "AWS" in result.errors[0]
        assert "All" in result.errors[0]

    def test_validate_wrong_type(self, db_session, validated_connection):
        """Test that validation fails when scope is wrong type."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": 123},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert "must be a string" in result.errors[0]

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "ListPolicies" in str(result.actions) or "iam:ListPolicies" in str(result.actions)
        assert "Local" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert result.regions == ["global"]

    def test_dry_run_shows_scope(self, db_session, validated_connection):
        """Test dry-run includes the scope parameter."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "AWS"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "AWS" in str(result.actions)

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=True,
        )
        technique = ListPoliciesTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    @mock_aws
    def test_execute_no_policies_local(self, db_session, aws_credentials):
        """Test execution with no customer-managed policies."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 0
        assert "No IAM policies" in result.summary
        assert "Local" in result.summary

    @mock_aws
    def test_execute_single_policy(self, db_session, aws_credentials):
        """Test execution with single customer-managed policy."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="test-policy-single",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1
        assert "1 policy" in result.summary

    @mock_aws
    def test_execute_multiple_policies(self, db_session, aws_credentials):
        """Test execution with multiple policies."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="test-policy-1",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )
        iam.create_policy(
            PolicyName="test-policy-2",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )
        iam.create_policy(
            PolicyName="test-policy-3",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3
        assert "3 policy" in result.summary

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="test-policy-stored",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "iam"
        assert asset.resource_type == "iam_policy"
        assert asset.region == "global"
        assert asset.data["PolicyName"] == "test-policy-stored"
        assert asset.data["Scope"] == "Local"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="test-policy",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "iam.list_policies"
        assert execution.service == "iam"
        assert execution.status == "completed"
        assert execution.asset_count == 1
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_policies(self, db_session, validated_connection):
        """Test summary for zero policies."""
        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
        )
        technique = ListPoliciesTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No IAM policies" in summary
        assert "Local" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_shows_attachment_status(self, db_session, aws_credentials):
        """Test summary shows attachment status counts."""
        iam = boto3.client("iam", region_name="us-east-1")
        # Create policies (some attached, some not)
        iam.create_policy(
            PolicyName="attached-policy",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )
        iam.create_policy(
            PolicyName="unattached-policy",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)
        result = technique.execute()

        # Summary should mention attachment status
        assert "Attached" in result.summary
        assert "Unattached" in result.summary
        # Policy names should NOT be in summary
        assert "attached-policy" not in result.summary
        assert "unattached-policy" not in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_no_sensitive_data(self, db_session, aws_credentials):
        """CRITICAL: Test that summary contains NO sensitive data."""
        # Create policies with "sensitive" names
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="production-database-access",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )
        iam.create_policy(
            PolicyName="secret-api-keys-policy",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )
        iam.create_policy(
            PolicyName="customer-pii-access",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check policy names are NOT in summary
        assert "production-database-access" not in result.summary
        assert "secret-api-keys-policy" not in result.summary
        assert "customer-pii-access" not in result.summary

        # Should only contain counts
        assert "3 policy" in result.summary

    @mock_aws
    def test_asset_data_contains_required_fields(self, db_session, aws_credentials):
        """Test that asset data contains all required fields."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="test-policy",
            Path="/custom/",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        asset = assets[0]

        # Check required fields
        assert "PolicyName" in asset.data
        assert "PolicyId" in asset.data
        assert "Arn" in asset.data
        assert "Path" in asset.data
        assert "CreateDate" in asset.data
        assert "AttachmentCount" in asset.data
        assert "IsAttachable" in asset.data
        assert "Scope" in asset.data
        assert asset.data["Path"] == "/custom/"

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="test-policy",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary

    @mock_aws
    def test_summary_includes_scope(self, db_session, aws_credentials):
        """Test that summary includes the scope that was used."""
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="test-policy",
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )

        config = TechniqueConfig(
            technique_name="iam.list_policies",
            parameters={"scope": "Local"},
            dry_run=False,
        )
        technique = ListPoliciesTechnique(config, db_session)
        result = technique.execute()

        assert "Local" in result.summary
