"""Tests for output formatting."""

import json

from cloak.output.formatters import (
    format_dry_run_output,
    format_json_output,
    format_text_output,
)
from cloak.techniques.base import DryRunResult, ExecutionResult


class TestFormatJsonOutput:
    """Tests for format_json_output function."""

    def test_formats_successful_result(self):
        """Test formatting of successful execution result."""
        result = ExecutionResult(
            execution_id="test-123",
            success=True,
            summary="Test summary",
            asset_count=10,
            finding_count=3,
            duration_seconds=2.5,
        )

        output = format_json_output(result)
        data = json.loads(output)

        assert data["execution_id"] == "test-123"
        assert data["success"] is True
        assert data["summary"] == "Test summary"
        assert data["asset_count"] == 10
        assert data["finding_count"] == 3
        assert data["duration_seconds"] == 2.5
        assert data["error_message"] is None

    def test_formats_failed_result(self):
        """Test formatting of failed execution result."""
        result = ExecutionResult(
            execution_id="test-456",
            success=False,
            summary="",
            error_message="AWS API error",
        )

        output = format_json_output(result)
        data = json.loads(output)

        assert data["execution_id"] == "test-456"
        assert data["success"] is False
        assert data["error_message"] == "AWS API error"

    def test_output_is_valid_json(self):
        """Test that output is valid JSON."""
        result = ExecutionResult(
            execution_id="test-789",
            success=True,
            summary="Valid JSON test",
        )

        output = format_json_output(result)
        # Should not raise JSONDecodeError
        json.loads(output)

    def test_includes_all_fields(self):
        """Test that all result fields are included."""
        result = ExecutionResult(
            execution_id="complete-test",
            success=True,
            summary="Complete test",
            asset_count=5,
            finding_count=2,
            duration_seconds=1.23,
            error_message=None,
        )

        output = format_json_output(result)
        data = json.loads(output)

        # Verify all expected keys are present
        expected_keys = {
            "execution_id",
            "success",
            "summary",
            "asset_count",
            "finding_count",
            "duration_seconds",
            "error_message",
        }
        assert set(data.keys()) == expected_keys


class TestFormatTextOutput:
    """Tests for format_text_output function."""

    def test_formats_successful_result(self):
        """Test text formatting of successful result."""
        result = ExecutionResult(
            execution_id="text-123",
            success=True,
            summary="Enumeration successful",
            asset_count=15,
            finding_count=4,
            duration_seconds=3.14,
        )

        output = format_text_output(result)

        assert "Execution ID: text-123" in output
        assert "Status: success" in output
        assert "Duration: 3.14s" in output
        assert "Assets: 15" in output
        assert "Findings: 4" in output
        assert "Summary:" in output
        assert "Enumeration successful" in output

    def test_formats_failed_result(self):
        """Test text formatting of failed result."""
        result = ExecutionResult(
            execution_id="text-456",
            success=False,
            summary="",
            error_message="Connection timeout",
        )

        output = format_text_output(result)

        assert "Execution ID: text-456" in output
        assert "Status: failed" in output
        assert "Error: Connection timeout" in output
        # Should not include asset/finding counts for failed execution
        assert "Assets:" not in output
        assert "Summary:" not in output

    def test_formats_multiline_summary(self):
        """Test formatting of multi-line summary."""
        result = ExecutionResult(
            execution_id="multiline-123",
            success=True,
            summary="Line 1\nLine 2\nLine 3",
            asset_count=1,
            finding_count=0,
            duration_seconds=1.0,
        )

        output = format_text_output(result)

        assert "Line 1" in output
        assert "Line 2" in output
        assert "Line 3" in output

    def test_output_is_readable(self):
        """Test that output is human-readable."""
        result = ExecutionResult(
            execution_id="readable-test",
            success=True,
            summary="Human readable test",
            asset_count=10,
            finding_count=5,
            duration_seconds=2.0,
        )

        output = format_text_output(result)

        # Should have newlines for readability
        assert "\n" in output
        # Should have key-value format
        assert ":" in output


class TestFormatDryRunOutput:
    """Tests for format_dry_run_output function."""

    def test_formats_dry_run_result(self):
        """Test formatting of dry-run result."""
        result = DryRunResult(
            actions=["Call s3:ListAllMyBuckets", "Call s3:GetBucketLocation"],
            estimated_api_calls="1 + N buckets",
            regions=["global"],
            required_permissions=["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
        )

        output = format_dry_run_output(result)

        # Should contain the planned actions
        assert "s3:ListAllMyBuckets" in output or "ListAllMyBuckets" in output

    def test_calls_to_summary_method(self):
        """Test that it calls the DryRunResult.to_summary() method."""
        result = DryRunResult(
            actions=["Test action"],
            estimated_api_calls="1",
            regions=["us-east-1"],
            required_permissions=["test:Permission"],
        )

        # This should not raise an error
        output = format_dry_run_output(result)
        assert isinstance(output, str)
        assert len(output) > 0

    def test_includes_example_command_with_technique_name(self):
        """Test that output includes example execution command when technique name provided."""
        result = DryRunResult(
            actions=["Call s3:ListAllMyBuckets"],
            estimated_api_calls="1",
            regions=["global"],
            required_permissions=["s3:ListAllMyBuckets"],
        )

        output = format_dry_run_output(result, technique_name="s3.list_buckets")

        assert "To execute, run:" in output
        assert "python -m cloak.cli --technique s3.list_buckets --execute" in output

    def test_includes_example_command_with_config(self):
        """Test that output includes example command with config when provided."""
        result = DryRunResult(
            actions=["Call s3:GetBucketAcl"],
            estimated_api_calls="1",
            regions=["global"],
            required_permissions=["s3:GetBucketAcl"],
        )

        output = format_dry_run_output(
            result, technique_name="s3.get_bucket_acl", config={"bucket_name": "all"}
        )

        assert "To execute, run:" in output
        assert "--technique s3.get_bucket_acl" in output
        assert "--config" in output
        assert "bucket_name" in output
        assert "--execute" in output

    def test_no_example_command_without_technique_name(self):
        """Test that no example command is shown when technique name not provided."""
        result = DryRunResult(
            actions=["Test action"],
            estimated_api_calls="1",
            regions=["us-east-1"],
            required_permissions=["test:Permission"],
        )

        output = format_dry_run_output(result)  # No technique_name

        assert "To execute, run:" not in output
