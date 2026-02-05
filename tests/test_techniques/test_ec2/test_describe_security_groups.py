"""Tests for EC2 describe_security_groups technique."""

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.ec2.describe_security_groups import DescribeSecurityGroupsTechnique


class TestDescribeSecurityGroupsTechnique:
    """Tests for DescribeSecurityGroupsTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "describe_security_groups"
        assert metadata.service == "ec2"
        assert metadata.full_name == "ec2.describe_security_groups"
        assert "ec2:DescribeSecurityGroups" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "security group" in technique.metadata.description.lower()

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with empty config."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "DescribeSecurityGroups" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert "us-east-1" in result.regions
        assert "paginated" in result.estimated_api_calls.lower()

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=True,
        )
        technique = DescribeSecurityGroupsTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    def test_dry_run_shows_regions(self, db_session, validated_connection):
        """Test that dry-run includes region information."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            regions=["us-east-1", "us-west-2"],
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert len(result.regions) == 2
        assert "us-east-1" in result.regions
        assert "us-west-2" in result.regions

    @mock_aws
    def test_execute_default_security_groups(self, db_session, aws_credentials):
        """Test execution finds default security groups."""
        # Moto creates default VPC with default security group
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)

        result = technique.execute()

        # Should find at least the default security group
        assert result.success is True
        assert result.asset_count >= 1

    @mock_aws
    def test_execute_custom_security_group(self, db_session, aws_credentials):
        """Test execution with custom security group."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.create_security_group(
            GroupName="test-sg-custom",
            Description="Test security group",
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Should find default + custom security group
        assert result.asset_count >= 2
        assert "security group" in result.summary.lower()

    @mock_aws
    def test_execute_multiple_security_groups(self, db_session, aws_credentials):
        """Test execution with multiple security groups."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        ec2.create_security_group(
            GroupName="test-sg-1",
            Description="Test security group 1",
        )
        ec2.create_security_group(
            GroupName="test-sg-2",
            Description="Test security group 2",
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # default + 2 custom
        assert result.asset_count >= 3

    @mock_aws
    def test_execute_security_groups_multiple_regions(self, db_session, aws_credentials):
        """Test execution with security groups in multiple regions."""
        ec2_east = boto3.client("ec2", region_name="us-east-1")
        ec2_west = boto3.client("ec2", region_name="us-west-2")

        ec2_east.create_security_group(
            GroupName="test-sg-east",
            Description="Test security group east",
        )
        ec2_west.create_security_group(
            GroupName="test-sg-west",
            Description="Test security group west",
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            regions=["us-east-1", "us-west-2"],
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Summary should mention both regions
        assert "us-east-1" in result.summary
        assert "us-west-2" in result.summary

    @mock_aws
    def test_execute_security_group_with_rules(self, db_session, aws_credentials):
        """Test execution with security group with rules."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.create_security_group(
            GroupName="test-sg-with-rules",
            Description="Test security group with rules",
        )
        sg_id = response["GroupId"]

        # Add inbound rule
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        )

        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Check that inbound rules are counted
        assert "inbound rules" in result.summary.lower()

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.create_security_group(
            GroupName="test-sg-stored",
            Description="Test security group for storage",
        )
        sg_id = response["GroupId"]

        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) >= 1

        # Find our security group
        our_sg = next((a for a in assets if a.data.get("GroupId") == sg_id), None)
        assert our_sg is not None
        assert our_sg.service == "ec2"
        assert our_sg.resource_type == "ec2_security_group"
        assert our_sg.region == "us-east-1"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "ec2.describe_security_groups"
        assert execution.service == "ec2"
        assert execution.status == "completed"
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_security_groups(self, db_session, validated_connection):
        """Test summary for zero security groups."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No security groups" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_has_region_distribution(self, db_session, aws_credentials):
        """Test summary includes region distribution."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)
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
        response = ec2.create_security_group(
            GroupName="production-database-sg",
            Description="Production database security group",
        )
        sg_id = response["GroupId"]

        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check security group IDs and names are NOT in summary
        assert sg_id not in result.summary
        assert "production-database-sg" not in result.summary
        assert "sg-" not in result.summary  # Security group ID prefix

    @mock_aws
    def test_asset_data_contains_required_fields(self, db_session, aws_credentials):
        """Test that asset data contains all required fields."""
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.create_security_group(
            GroupName="test-sg-fields",
            Description="Test security group for fields",
        )
        sg_id = response["GroupId"]

        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        # Find our security group
        asset = next((a for a in assets if a.data.get("GroupId") == sg_id), None)
        assert asset is not None

        # Check required fields in data
        assert "GroupId" in asset.data
        assert "GroupName" in asset.data
        assert "Description" in asset.data
        assert "IpPermissions" in asset.data
        assert "IpPermissionsEgress" in asset.data
        assert asset.data["GroupName"] == "test-sg-fields"

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        config = TechniqueConfig(
            technique_name="ec2.describe_security_groups",
            parameters={},
            dry_run=False,
        )
        technique = DescribeSecurityGroupsTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary
