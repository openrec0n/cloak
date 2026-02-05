"""Tests for S3 list_buckets technique."""

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.s3.list_buckets import ListBucketsTechnique


class TestListBucketsTechnique:
    """Tests for ListBucketsTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
        )
        technique = ListBucketsTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "list_buckets"
        assert metadata.service == "s3"
        assert metadata.full_name == "s3.list_buckets"
        assert "s3:ListAllMyBuckets" in metadata.required_permissions
        assert "s3:GetBucketLocation" in metadata.required_permissions

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with empty config."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
        )
        technique = ListBucketsTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
        )
        technique = ListBucketsTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "ListAllMyBuckets" in str(result.actions) or "s3:ListAllMyBuckets" in str(
            result.actions
        )
        assert "GetBucketLocation" in str(result.actions) or "s3:GetBucketLocation" in str(
            result.actions
        )
        assert len(result.required_permissions) == 2
        assert result.regions == ["global"]
        assert "1 + N" in result.estimated_api_calls

    @mock_aws
    def test_execute_no_buckets(self, db_session, aws_credentials):
        """Test execution with no buckets."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 0
        assert result.finding_count == 0
        assert "No S3 buckets" in result.summary

    @mock_aws
    def test_execute_single_bucket(self, db_session, aws_credentials):
        """Test execution with single bucket."""
        # Create mock S3 bucket
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-single")

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1
        assert "1 bucket" in result.summary

    @mock_aws
    def test_execute_multiple_buckets(self, db_session, aws_credentials):
        """Test execution with multiple buckets."""
        # Create multiple mock S3 buckets
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-1")
        s3.create_bucket(Bucket="test-bucket-2")
        s3.create_bucket(Bucket="test-bucket-3")

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3
        assert "3 bucket" in result.summary

    @mock_aws
    def test_execute_multiple_regions(self, db_session, aws_credentials):
        """Test execution with buckets in different regions."""
        # Create buckets in multiple regions
        s3_us_east = boto3.client("s3", region_name="us-east-1")
        s3_us_east.create_bucket(Bucket="test-bucket-us-east-1")
        s3_us_east.create_bucket(Bucket="test-bucket-us-east-2")

        s3_us_west = boto3.client("s3", region_name="us-west-2")
        s3_us_west.create_bucket(
            Bucket="test-bucket-us-west-1",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3
        # Should mention multiple regions
        assert "region" in result.summary.lower()

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        # Create mock S3 buckets
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-stored")

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "s3"
        assert asset.resource_type == "s3_bucket"
        assert asset.resource_id == "test-bucket-stored"
        assert asset.region == "us-east-1"
        assert asset.data["Name"] == "test-bucket-stored"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "s3.list_buckets"
        assert execution.service == "s3"
        assert execution.status == "completed"
        assert execution.asset_count == 1
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_buckets(self, db_session, validated_connection):
        """Test summary for zero buckets."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
        )
        technique = ListBucketsTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No S3 buckets" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_single_region(self, db_session, aws_credentials):
        """Test summary for buckets in single region."""
        # Create buckets
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="bucket-1")
        s3.create_bucket(Bucket="bucket-2")

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)
        result = technique.execute()

        # Validate summary
        assert "2 bucket" in result.summary
        assert "us-east-1" in result.summary
        # Bucket names should NOT be in summary
        assert "bucket-1" not in result.summary
        assert "bucket-2" not in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_multiple_regions(self, db_session, aws_credentials):
        """Test summary for buckets in multiple regions."""
        # Create buckets in different regions
        s3_east = boto3.client("s3", region_name="us-east-1")
        s3_east.create_bucket(Bucket="bucket-east-1")
        s3_east.create_bucket(Bucket="bucket-east-2")

        s3_west = boto3.client("s3", region_name="us-west-2")
        s3_west.create_bucket(
            Bucket="bucket-west-1", CreateBucketConfiguration={"LocationConstraint": "us-west-2"}
        )

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)
        result = technique.execute()

        # Validate summary
        assert "3 bucket" in result.summary
        assert "us-east-1" in result.summary
        assert "us-west-2" in result.summary or "2 region" in result.summary
        # Bucket names should NOT be in summary
        assert "bucket-east" not in result.summary
        assert "bucket-west" not in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_no_sensitive_data(self, db_session, aws_credentials):
        """CRITICAL: Test that summary contains NO sensitive data."""
        # Create buckets with "sensitive" names
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="my-secret-production-bucket")
        s3.create_bucket(Bucket="customer-data-backup-2024")
        s3.create_bucket(Bucket="internal-company-files")

        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )
        technique = ListBucketsTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check bucket names are NOT in summary
        assert "my-secret-production-bucket" not in result.summary
        assert "customer-data-backup-2024" not in result.summary
        assert "internal-company-files" not in result.summary

        # Should only contain counts and regions
        assert "3 bucket" in result.summary
        assert "us-east-1" in result.summary

    @mock_aws
    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=True,
        )
        technique = ListBucketsTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0
