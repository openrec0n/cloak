"""Tests for base technique functionality."""

from unittest.mock import patch

from moto import mock_aws

from cloak.core.config import CloakConfig, TechniqueConfig
from cloak.core.database import init_database, session_scope
from cloak.core.models import Execution
from cloak.techniques.base import (
    DryRunResult,
    ExecutionResult,
)


class TestExecutionResultFromError:
    """Tests for ExecutionResult.from_error class method."""

    def test_creates_failed_result_with_summary(self):
        """Test that from_error creates a result with summary."""
        result = ExecutionResult.from_error(
            execution_id="test-123", error_message="Test error message"
        )

        assert result.success is False
        assert result.execution_id == "test-123"
        assert result.error_message == "Test error message"
        assert result.summary == "Execution failed: Test error message"
        assert result.summary is not None


class TestFailedExecutionSummary:
    """Tests for failed execution summary handling."""

    @mock_aws
    def test_failed_execution_has_summary_in_database(self, aws_credentials, test_config):
        """Test that failed executions store a summary in the database."""
        from cloak.techniques.s3.list_buckets import ListBucketsTechnique

        config = CloakConfig.default()
        init_database(config)

        technique_config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )

        with session_scope(config) as session:
            # Create technique with a mock that will fail
            technique = ListBucketsTechnique(technique_config, session)

            # Mock the _execute_impl to raise an exception
            with patch.object(technique, "_execute_impl", side_effect=Exception("Test AWS error")):
                result = technique.execute()

            # Verify result has summary
            assert result.success is False
            assert result.summary is not None
            assert "Execution failed:" in result.summary

            # Verify database has summary
            execution = session.query(Execution).filter_by(id=result.execution_id).first()
            assert execution is not None
            assert execution.summary is not None
            assert "Execution failed:" in execution.summary

    @mock_aws
    def test_failed_execution_sanitizes_arn_in_summary(self, aws_credentials, test_config):
        """Test that failed execution summaries have ARNs sanitized."""
        from cloak.techniques.s3.list_buckets import ListBucketsTechnique

        config = CloakConfig.default()
        init_database(config)

        technique_config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )

        # Error message that contains sensitive ARN
        error_with_arn = "User: arn:aws:iam::123456789012:user/test-user is not authorized"

        with session_scope(config) as session:
            technique = ListBucketsTechnique(technique_config, session)

            # Mock the _execute_impl to raise an exception with ARN
            with patch.object(technique, "_execute_impl", side_effect=Exception(error_with_arn)):
                result = technique.execute()

            # Verify summary does NOT contain the ARN
            assert result.success is False
            assert "arn:aws:iam" not in result.summary
            assert "123456789012" not in result.summary
            assert "[REDACTED]" in result.summary

            # Verify full error is still in error_message (for debugging)
            assert "arn:aws:iam" in result.error_message

    @mock_aws
    def test_failed_execution_truncates_long_errors(self, aws_credentials, test_config):
        """Test that failed execution summaries truncate very long errors."""
        from cloak.techniques.s3.list_buckets import ListBucketsTechnique

        config = CloakConfig.default()
        init_database(config)

        technique_config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )

        # Very long error message (>200 chars)
        long_error = "A" * 500

        with session_scope(config) as session:
            technique = ListBucketsTechnique(technique_config, session)

            with patch.object(technique, "_execute_impl", side_effect=Exception(long_error)):
                result = technique.execute()

            # Summary should be truncated
            assert result.success is False
            # Summary is "Execution failed: " (18 chars) + up to 200 chars of error
            assert len(result.summary) < 250


class TestDryRunResultToSummary:
    """Tests for DryRunResult.to_summary method."""

    def test_to_summary_includes_example_with_technique_name(self):
        """Test that to_summary includes example command when technique name provided."""
        result = DryRunResult(
            actions=["Test action"],
            estimated_api_calls="1",
            regions=["us-east-1"],
            required_permissions=["test:Permission"],
        )

        summary = result.to_summary(technique_name="s3.list_buckets")

        assert "To execute, run:" in summary
        assert "--technique s3.list_buckets" in summary
        assert "--execute" in summary

    def test_to_summary_includes_config_in_example(self):
        """Test that to_summary includes config in example command."""
        result = DryRunResult(
            actions=["Test action"],
            estimated_api_calls="1",
            regions=["us-east-1"],
            required_permissions=["test:Permission"],
        )

        summary = result.to_summary(
            technique_name="s3.get_bucket_acl", config={"bucket_name": "test-bucket"}
        )

        assert "--config" in summary
        assert "bucket_name" in summary

    def test_to_summary_no_example_without_technique_name(self):
        """Test that to_summary excludes example command without technique name."""
        result = DryRunResult(
            actions=["Test action"],
            estimated_api_calls="1",
            regions=["us-east-1"],
            required_permissions=["test:Permission"],
        )

        summary = result.to_summary()  # No technique_name

        assert "To execute, run:" not in summary
