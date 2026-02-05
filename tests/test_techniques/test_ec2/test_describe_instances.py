"""Tests for EC2 describe_instances technique."""

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.ec2.describe_instances import DescribeInstancesTechnique


class TestDescribeInstancesTechnique:
    """Tests for DescribeInstancesTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
        )
        technique = DescribeInstancesTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "describe_instances"
        assert metadata.service == "ec2"
        assert metadata.full_name == "ec2.describe_instances"
        assert "ec2:DescribeInstances" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
        )
        technique = DescribeInstancesTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "instance" in technique.metadata.description.lower()

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with empty config."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
        )
        technique = DescribeInstancesTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
        )
        technique = DescribeInstancesTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "DescribeInstances" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert "us-east-1" in result.regions
        assert "paginated" in result.estimated_api_calls.lower()

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=True,
        )
        technique = DescribeInstancesTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    def test_dry_run_shows_regions(self, db_session, validated_connection):
        """Test that dry-run includes region information."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            regions=["us-east-1", "us-west-2"],
        )
        technique = DescribeInstancesTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert len(result.regions) == 2
        assert "us-east-1" in result.regions
        assert "us-west-2" in result.regions

    @mock_aws
    def test_execute_no_instances(self, db_session, aws_credentials):
        """Test execution with no instances."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 0
        assert result.finding_count == 0

    @mock_aws
    def test_execute_single_instance(self, db_session, aws_credentials):
        """Test execution with single instance."""
        # Create mock EC2 instance
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1
        assert "instance" in result.summary.lower()

    @mock_aws
    def test_execute_multiple_instances(self, db_session, aws_credentials):
        """Test execution with multiple instances."""
        # Create multiple mock EC2 instances
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=3,
            MaxCount=3,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3

    @mock_aws
    def test_execute_instances_multiple_regions(self, db_session, aws_credentials):
        """Test execution with instances in multiple regions."""
        # Create instances in two regions
        ec2_east = boto3.client("ec2", region_name="us-east-1")
        ec2_west = boto3.client("ec2", region_name="us-west-2")

        ec2_east.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=2,
            MaxCount=2,
        )
        ec2_west.run_instances(
            ImageId="ami-87654321",
            InstanceType="t2.small",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            regions=["us-east-1", "us-west-2"],
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3
        # Summary should mention both regions
        assert "us-east-1" in result.summary
        assert "us-west-2" in result.summary

    @mock_aws
    def test_execute_instances_different_types(self, db_session, aws_credentials):
        """Test execution with instances of different types."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=2,
            MaxCount=2,
        )
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.small",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3
        # Summary should mention instance types
        assert "t2.micro" in result.summary or "t2.small" in result.summary

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "ec2"
        assert asset.resource_type == "ec2_instance"
        assert asset.region == "us-east-1"
        assert asset.resource_id.startswith("i-")

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "ec2.describe_instances"
        assert execution.service == "ec2"
        assert execution.status == "completed"
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_instances(self, db_session, validated_connection):
        """Test summary for zero instances."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
        )
        technique = DescribeInstancesTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No EC2 instances" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_has_region_distribution(self, db_session, aws_credentials):
        """Test summary includes region distribution."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)
        result = technique.execute()

        # Region name is safe to include
        assert "us-east-1" in result.summary
        assert "Region distribution" in result.summary

        # Validate no sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_no_sensitive_data(self, db_session, aws_credentials):
        """CRITICAL: Test that summary contains NO sensitive data."""
        # Create instances with tags
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": "production-database-server"}],
                }
            ],
        )
        instance_id = response["Instances"][0]["InstanceId"]

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check instance IDs and names are NOT in summary
        assert instance_id not in result.summary
        assert "production-database-server" not in result.summary
        assert "i-" not in result.summary  # Instance ID prefix

    @mock_aws
    def test_asset_data_contains_required_fields(self, db_session, aws_credentials):
        """Test that asset data contains all required fields."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1
        asset = assets[0]

        # Check required fields in data
        assert "InstanceId" in asset.data
        assert "InstanceType" in asset.data
        assert "State" in asset.data
        assert "ImageId" in asset.data
        assert asset.data["InstanceType"] == "t2.micro"

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary

    @mock_aws
    def test_summarize_has_state_distribution(self, db_session, aws_credentials):
        """Test that summary includes state distribution."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            dry_run=False,
        )
        technique = DescribeInstancesTechnique(config, db_session)
        result = technique.execute()

        # Summary should mention state distribution
        assert "State distribution" in result.summary
        # Moto instances are typically in "running" state
        assert "running" in result.summary.lower()
