"""End-to-end workflow integration tests."""

from unittest.mock import patch

import boto3
from moto import mock_aws

from cloak.cli.runner import main
from cloak.core.database import session_scope
from cloak.core.models import Asset, Execution


class TestEndToEndWorkflow:
    """Integration tests for complete workflows."""

    @mock_aws
    def test_e2e_dry_run_workflow(self, aws_credentials, capsys):
        """Test complete dry-run workflow: CLI → dry-run → output."""
        with patch("sys.argv", ["cloak", "--technique", "s3.list_buckets"]):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        # Should show planned actions
        assert "ListAllMyBuckets" in captured.out or "s3:ListAllMyBuckets" in captured.out
        # Should not create any database records in dry-run
        # (we can't easily verify this without passing config, but exit code 0 is good)

    @mock_aws
    def test_e2e_execution_workflow(self, aws_credentials, test_config, capsys):
        """Test complete execution workflow: CLI → execution → database → summary."""
        # Create mock S3 buckets
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket-1")
        s3.create_bucket(Bucket="test-bucket-2")

        # Execute technique
        with patch("sys.argv", ["cloak", "--technique", "s3.list_buckets", "--execute"]):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()

        # Verify output contains success indicators
        assert "success" in captured.out.lower() or "completed" in captured.out.lower()

        # Verify database records were created
        with session_scope(test_config) as session:
            executions = session.query(Execution).filter_by(technique_name="s3.list_buckets").all()
            assert len(executions) > 0

            execution = executions[-1]  # Get most recent
            assert execution.status == "completed"
            assert execution.asset_count == 2
            assert execution.finding_count == 0

            # Verify assets were stored
            assets = session.query(Asset).filter_by(execution_id=execution.id).all()
            assert len(assets) == 2
            assert all(asset.service == "s3" for asset in assets)
            assert all(asset.resource_type == "s3_bucket" for asset in assets)

        # Verify output contains summary information
        # Note: Debug logs may contain bucket names, but the summary shouldn't
        # Just verify counts are present (detailed test in list_buckets tests)
        assert "2 bucket" in captured.out

    @mock_aws
    def test_e2e_invalid_technique(self, capsys):
        """Test error handling for invalid technique."""
        with patch("sys.argv", ["cloak", "--technique", "invalid.technique"]):
            exit_code = main()

        assert exit_code == 1  # Validation error
        captured = capsys.readouterr()
        assert "Error:" in captured.err or "error" in captured.err.lower()

    @mock_aws
    def test_e2e_connection_validation(self, aws_credentials, capsys):
        """Test connection validation workflow."""
        with patch("sys.argv", ["cloak", "--validate-connection"]):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        # Should show account information
        assert "123456789012" in captured.out or "account" in captured.out.lower()

    @mock_aws
    def test_e2e_zero_resources(self, aws_credentials, test_config, capsys):
        """Test execution with zero resources found."""
        # Don't create any S3 buckets

        with patch("sys.argv", ["cloak", "--technique", "s3.list_buckets", "--execute"]):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()

        # Should still succeed with 0 resources
        assert "success" in captured.out.lower() or "completed" in captured.out.lower()
        assert "0 bucket" in captured.out.lower() or "no s3 buckets" in captured.out.lower()
