"""Tests for S3 get_bucket_acl technique."""

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.s3.get_bucket_acl import GetBucketAclTechnique


class TestGetBucketAclTechnique:
    """Tests for GetBucketAclTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket"},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "get_bucket_acl"
        assert metadata.service == "s3"
        assert metadata.full_name == "s3.get_bucket_acl"
        assert "s3:GetBucketAcl" in metadata.required_permissions
        assert "s3:ListAllMyBuckets" in metadata.required_permissions
        assert len(metadata.required_parameters) == 1
        assert metadata.required_parameters[0].name == "bucket_name"

    def test_validate_missing_bucket_name(self, db_session, validated_connection):
        """Test that validation fails when bucket_name is missing."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert len(result.errors) > 0
        assert "bucket_name" in str(result.errors[0]).lower()

    def test_validate_empty_bucket_name(self, db_session, validated_connection):
        """Test that validation fails when bucket_name is empty."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": ""},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert len(result.errors) > 0

    def test_validate_invalid_bucket_name_type(self, db_session, validated_connection):
        """Test that validation fails when bucket_name is not a string."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": 123},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert len(result.errors) > 0

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with valid bucket_name."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket"},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run_single_bucket(self, db_session, validated_connection):
        """Test dry-run shows correct actions for single bucket."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket"},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "GetBucketAcl" in str(result.actions) or "s3:GetBucketAcl" in str(result.actions)
        assert "test-bucket" in str(result.actions)
        assert len(result.required_permissions) == 2
        assert result.regions == ["global"]
        assert "1" in result.estimated_api_calls

    def test_dry_run_all_buckets(self, db_session, validated_connection):
        """Test dry-run shows correct actions for all buckets."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "all"},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "ListAllMyBuckets" in str(result.actions) or "s3:ListAllMyBuckets" in str(
            result.actions
        )
        assert "GetBucketAcl" in str(result.actions) or "s3:GetBucketAcl" in str(result.actions)
        assert "1 + N" in result.estimated_api_calls

    @mock_aws
    def test_execute_single_bucket(self, db_session, aws_credentials):
        """Test execution with single bucket."""
        # Create mock S3 bucket
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-acl")

        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket-acl"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1
        assert result.finding_count == 0

    @mock_aws
    def test_execute_all_buckets(self, db_session, aws_credentials):
        """Test execution with all buckets."""
        # Create multiple mock S3 buckets
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-1")
        s3.create_bucket(Bucket="test-bucket-2")

        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "all"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 2
        assert result.finding_count == 0

    @mock_aws
    def test_execute_no_buckets(self, db_session, aws_credentials):
        """Test execution with no buckets when using 'all'."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "all"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 0
        assert "No S3 bucket ACLs" in result.summary

    @mock_aws
    def test_execute_nonexistent_bucket(self, db_session, aws_credentials):
        """Test execution with non-existent bucket."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "nonexistent-bucket"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)

        result = technique.execute()

        # Should succeed but return no assets (bucket not found is handled gracefully)
        assert result.success is True
        assert result.asset_count == 0

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        # Create mock S3 bucket
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-stored")

        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket-stored"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "s3"
        assert asset.resource_type == "s3_bucket_acl"
        assert asset.resource_id == "test-bucket-stored"
        assert asset.region == "us-east-1"
        assert asset.data is not None
        assert "Owner" in asset.data
        assert "Grants" in asset.data

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "s3.get_bucket_acl"
        assert execution.service == "s3"
        assert execution.status == "completed"
        assert execution.asset_count == 1
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_buckets(self, db_session, validated_connection):
        """Test summary for zero buckets."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "all"},
        )
        technique = GetBucketAclTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No S3 bucket ACLs" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_single_bucket(self, db_session, aws_credentials):
        """Test summary for single bucket."""
        # Create bucket and get ACL
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-summary")

        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket-summary"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)
        result = technique.execute()

        # Validate summary
        assert "1 bucket" in result.summary or "Retrieved ACLs" in result.summary
        # Bucket name should NOT be in summary
        assert "test-bucket-summary" not in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_multiple_buckets(self, db_session, aws_credentials):
        """Test summary for multiple buckets."""
        # Create buckets in different regions
        s3_east = boto3.client("s3", region_name="us-east-1")
        s3_east.create_bucket(Bucket="bucket-east-1")
        s3_east.create_bucket(Bucket="bucket-east-2")

        s3_west = boto3.client("s3", region_name="us-west-2")
        s3_west.create_bucket(
            Bucket="bucket-west-1", CreateBucketConfiguration={"LocationConstraint": "us-west-2"}
        )

        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "all"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)
        result = technique.execute()

        # Validate summary
        assert "3 bucket" in result.summary or "Retrieved ACLs" in result.summary
        # Bucket names should NOT be in summary
        assert "bucket-east" not in result.summary
        assert "bucket-west" not in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_no_sensitive_data(self, db_session, aws_credentials):
        """CRITICAL: Test that summary contains NO sensitive data."""
        # Create bucket with "sensitive" name
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="my-secret-production-bucket")

        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "my-secret-production-bucket"},
            dry_run=False,
        )
        technique = GetBucketAclTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check bucket name is NOT in summary
        assert "my-secret-production-bucket" not in result.summary

        # Should only contain counts and regions
        assert "1 bucket" in result.summary or "Retrieved ACLs" in result.summary

    @mock_aws
    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="s3.get_bucket_acl",
            parameters={"bucket_name": "test-bucket"},
            dry_run=True,
        )
        technique = GetBucketAclTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0
