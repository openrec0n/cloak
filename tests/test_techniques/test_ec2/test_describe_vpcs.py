"""Tests for EC2 describe_vpcs technique."""

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.ec2.describe_vpcs import DescribeVpcsTechnique


class TestDescribeVpcsTechnique:
    """Tests for DescribeVpcsTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
        )
        technique = DescribeVpcsTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "describe_vpcs"
        assert metadata.service == "ec2"
        assert metadata.full_name == "ec2.describe_vpcs"
        assert "ec2:DescribeVpcs" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
        )
        technique = DescribeVpcsTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "vpc" in technique.metadata.description.lower()

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with empty config."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
        )
        technique = DescribeVpcsTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
        )
        technique = DescribeVpcsTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "DescribeVpcs" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert "us-east-1" in result.regions
        # VPCs is not paginated - 1 call per region
        assert "1" in result.estimated_api_calls

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=True,
        )
        technique = DescribeVpcsTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    def test_dry_run_shows_regions(self, db_session, validated_connection):
        """Test that dry-run includes region information."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            regions=["us-east-1", "us-west-2"],
        )
        technique = DescribeVpcsTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert len(result.regions) == 2
        assert "us-east-1" in result.regions
        assert "us-west-2" in result.regions

    @mock_aws
    def test_execute_default_vpc(self, db_session, aws_credentials):
        """Test execution finds default VPC."""
        # Moto creates a default VPC
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)

        result = technique.execute()

        # Should find at least the default VPC
        assert result.success is True
        assert result.asset_count >= 1

    @mock_aws
    def test_execute_custom_vpc(self, db_session, aws_credentials):
        """Test execution with custom VPC."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.create_vpc(CidrBlock="10.0.0.0/16")

        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Should find default + custom VPC
        assert result.asset_count >= 2
        assert "vpc" in result.summary.lower()

    @mock_aws
    def test_execute_multiple_vpcs(self, db_session, aws_credentials):
        """Test execution with multiple VPCs."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.create_vpc(CidrBlock="10.0.0.0/16")
        ec2.create_vpc(CidrBlock="10.1.0.0/16")

        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # default + 2 custom
        assert result.asset_count >= 3

    @mock_aws
    def test_execute_vpcs_multiple_regions(self, db_session, aws_credentials):
        """Test execution with VPCs in multiple regions."""
        ec2_east = boto3.client("ec2", region_name="us-east-1")
        ec2_west = boto3.client("ec2", region_name="us-west-2")

        ec2_east.create_vpc(CidrBlock="10.0.0.0/16")
        ec2_west.create_vpc(CidrBlock="10.1.0.0/16")

        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            regions=["us-east-1", "us-west-2"],
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Summary should mention both regions
        assert "us-east-1" in result.summary
        assert "us-west-2" in result.summary

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = response["Vpc"]["VpcId"]

        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) >= 1

        # Find our VPC
        our_vpc = next((a for a in assets if a.data.get("VpcId") == vpc_id), None)
        assert our_vpc is not None
        assert our_vpc.service == "ec2"
        assert our_vpc.resource_type == "ec2_vpc"
        assert our_vpc.region == "us-east-1"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "ec2.describe_vpcs"
        assert execution.service == "ec2"
        assert execution.status == "completed"
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_vpcs(self, db_session, validated_connection):
        """Test summary for zero VPCs."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
        )
        technique = DescribeVpcsTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No VPCs" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_has_region_distribution(self, db_session, aws_credentials):
        """Test summary includes region distribution."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)
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
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = response["Vpc"]["VpcId"]

        # Add a name tag
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=[{"Key": "Name", "Value": "production-network"}],
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check VPC IDs and names are NOT in summary
        assert vpc_id not in result.summary
        assert "production-network" not in result.summary
        assert "vpc-" not in result.summary  # VPC ID prefix
        # CIDR blocks should not be in summary
        assert "10.0.0.0/16" not in result.summary

    @mock_aws
    def test_asset_data_contains_required_fields(self, db_session, aws_credentials):
        """Test that asset data contains all required fields."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = response["Vpc"]["VpcId"]

        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        # Find our VPC
        asset = next((a for a in assets if a.data.get("VpcId") == vpc_id), None)
        assert asset is not None

        # Check required fields in data
        assert "VpcId" in asset.data
        assert "CidrBlock" in asset.data
        assert "State" in asset.data
        assert "IsDefault" in asset.data
        assert asset.data["CidrBlock"] == "10.0.0.0/16"

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary

    @mock_aws
    def test_summarize_shows_default_vs_custom(self, db_session, aws_credentials):
        """Test that summary shows default vs custom VPC counts."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.create_vpc(CidrBlock="10.0.0.0/16")

        config = TechniqueConfig(
            technique_name="ec2.describe_vpcs",
            parameters={},
            dry_run=False,
        )
        technique = DescribeVpcsTechnique(config, db_session)
        result = technique.execute()

        # Summary should mention default and custom VPCs
        assert "Default VPCs" in result.summary
        assert "Custom VPCs" in result.summary
