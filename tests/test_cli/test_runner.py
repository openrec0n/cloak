"""Tests for CLI runner."""

import json
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from cloak.cli.runner import (
    execution_info,
    list_techniques,
    load_technique_class,
    main,
    run_technique,
    technique_info,
    validate_connection,
)
from cloak.core.config import CloakConfig
from cloak.core.database import init_database, session_scope
from cloak.core.models import Asset, Execution
from cloak.techniques.lambda_.list_functions import ListFunctionsTechnique
from cloak.techniques.s3.list_buckets import ListBucketsTechnique


class TestLoadTechniqueClass:
    """Tests for load_technique_class function."""

    def test_load_s3_technique(self):
        """Test loading S3 technique."""
        technique_class = load_technique_class("s3.list_buckets")
        assert technique_class == ListBucketsTechnique

    def test_invalid_format_single_part(self):
        """Test that single-part name is rejected."""
        with pytest.raises(ValueError) as exc_info:
            load_technique_class("invalid")
        assert "Expected format: service.technique" in str(exc_info.value)

    def test_invalid_format_too_many_parts(self):
        """Test that three-part name is rejected."""
        with pytest.raises(ValueError) as exc_info:
            load_technique_class("s3.list.buckets")
        assert "Expected format: service.technique" in str(exc_info.value)

    def test_unknown_service(self):
        """Test that unknown service is rejected."""
        with pytest.raises(ValueError) as exc_info:
            load_technique_class("unknown_service.some_technique")
        assert "Unknown service 'unknown_service'" in str(exc_info.value)

    def test_unknown_technique(self):
        """Test that unknown technique is rejected."""
        with pytest.raises(ValueError) as exc_info:
            load_technique_class("s3.unknown_technique")
        assert "Unknown technique 'unknown_technique'" in str(exc_info.value)
        assert "Available:" in str(exc_info.value)

    def test_load_lambda_technique_with_lambda_name(self):
        """Test loading Lambda technique using 'lambda' (public API name)."""
        technique_class = load_technique_class("lambda.list_functions")
        assert technique_class == ListFunctionsTechnique

    def test_load_lambda_technique_with_lambda_underscore(self):
        """Test backward compatibility with 'lambda_' (internal module name)."""
        technique_class = load_technique_class("lambda_.list_functions")
        assert technique_class == ListFunctionsTechnique

    def test_unknown_service_error_shows_suggestions(self):
        """Test that unknown service error includes available services."""
        with pytest.raises(ValueError) as exc_info:
            load_technique_class("invalid_service.some_technique")
        error_msg = str(exc_info.value)
        assert "Unknown service 'invalid_service'" in error_msg
        assert "Available services:" in error_msg
        assert "s3" in error_msg
        assert "iam" in error_msg
        assert "ec2" in error_msg
        assert "lambda" in error_msg
        assert "--list-services" in error_msg


class TestValidateConnection:
    """Tests for validate_connection function."""

    @mock_aws
    def test_validate_connection_success(self, aws_credentials):
        """Test successful connection validation."""
        exit_code = validate_connection()
        assert exit_code == 0

    def test_validate_connection_failure(self):
        """Test connection validation failure."""
        from unittest.mock import patch

        # Mock validate_aws_connection to raise RuntimeError
        with patch("cloak.cli.runner.validate_aws_connection") as mock_validate:
            mock_validate.side_effect = RuntimeError("AWS connection failed: Invalid credentials")

            exit_code = validate_connection()
            assert exit_code == 1


class TestRunTechnique:
    """Tests for run_technique function."""

    @mock_aws
    def test_run_technique_dry_run(self, aws_credentials, test_config, tmp_path, capsys):
        """Test running technique in dry-run mode."""
        exit_code = run_technique(
            technique_name="s3.list_buckets",
            config_json=None,
            dry_run=True,
            output_format="json",
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        # Dry-run output should mention planned actions
        assert "ListAllMyBuckets" in captured.out or "s3:ListAllMyBuckets" in captured.out

    @mock_aws
    def test_run_technique_execute(self, aws_credentials, test_config, tmp_path, capsys):
        """Test running technique in execution mode."""
        # Create mock S3 bucket
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        exit_code = run_technique(
            technique_name="s3.list_buckets",
            config_json=None,
            dry_run=False,
            output_format="json",
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        # Check that we got some output
        assert len(captured.out) > 0
        # Should contain success indicators
        assert "success" in captured.out.lower() or "completed" in captured.out.lower()

    @mock_aws
    def test_run_technique_text_output(self, aws_credentials, test_config, tmp_path, capsys):
        """Test running technique with text output format."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        exit_code = run_technique(
            technique_name="s3.list_buckets",
            config_json=None,
            dry_run=False,
            output_format="text",
        )

        assert exit_code == 0
        captured = capsys.readouterr()
        # Text output should be human-readable
        assert "Execution ID:" in captured.out
        assert "Status:" in captured.out
        assert "Assets:" in captured.out

    def test_run_technique_invalid_technique_name(self, test_config, capsys):
        """Test running with invalid technique name."""
        exit_code = run_technique(
            technique_name="invalid_technique",
            config_json=None,
            dry_run=True,
            output_format="json",
        )

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

    def test_run_technique_invalid_json_config(self, test_config, capsys):
        """Test running with invalid JSON config."""
        exit_code = run_technique(
            technique_name="s3.list_buckets",
            config_json="{invalid json}",
            dry_run=True,
            output_format="json",
        )

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Invalid JSON config" in captured.err

    @mock_aws
    def test_run_technique_with_valid_config(self, aws_credentials, test_config, capsys):
        """Test running with valid JSON config."""
        config_dict = {"some_param": "value"}
        config_json = json.dumps(config_dict)

        exit_code = run_technique(
            technique_name="s3.list_buckets",
            config_json=config_json,
            dry_run=True,
            output_format="json",
        )

        # Should succeed (list_buckets doesn't use parameters, but should accept them)
        assert exit_code == 0


class TestMain:
    """Tests for main CLI entry point."""

    @mock_aws
    def test_main_validate_connection(self, aws_credentials, capsys):
        """Test main with --validate-connection."""
        with patch("sys.argv", ["cloak", "--validate-connection"]):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        # Check for account ID in output
        assert "123456789012" in captured.out or "account" in captured.out.lower()

    @mock_aws
    def test_main_dry_run(self, aws_credentials, test_config, capsys):
        """Test main with technique in dry-run mode."""
        with patch("sys.argv", ["cloak", "--technique", "s3.list_buckets"]):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        # Default is dry-run
        assert "ListAllMyBuckets" in captured.out or "s3:ListAllMyBuckets" in captured.out

    @mock_aws
    def test_main_execute(self, aws_credentials, test_config, capsys):
        """Test main with --execute flag."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        with patch("sys.argv", ["cloak", "--technique", "s3.list_buckets", "--execute"]):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        # Check that we got output
        assert len(captured.out) > 0
        # Should contain success indicators
        assert "success" in captured.out.lower() or "completed" in captured.out.lower()

    def test_main_missing_technique(self, capsys):
        """Test main with missing technique argument."""
        with patch("sys.argv", ["cloak"]):
            exit_code = main()

        assert exit_code == 1
        captured = capsys.readouterr()
        assert "--technique is required" in captured.err

    @mock_aws
    def test_main_with_config(self, aws_credentials, test_config, capsys):
        """Test main with --config argument."""
        config_json = json.dumps({"param": "value"})

        with patch(
            "sys.argv", ["cloak", "--technique", "s3.list_buckets", "--config", config_json]
        ):
            exit_code = main()

        assert exit_code == 0

    @mock_aws
    def test_main_text_output(self, aws_credentials, test_config, capsys):
        """Test main with --output text."""
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")

        with patch(
            "sys.argv", ["cloak", "--technique", "s3.list_buckets", "--execute", "--output", "text"]
        ):
            exit_code = main()

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Execution ID:" in captured.out
        assert "Status:" in captured.out


class TestListTechniques:
    """Tests for list_techniques function."""

    def test_list_techniques_brief_mode_json(self, capsys):
        """Test list_techniques with --brief flag outputs minimal data."""
        exit_code = list_techniques(service=None, output_format="json", brief=True)
        assert exit_code == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "techniques" in output

        # Brief mode should only have id and description
        for tech in output["techniques"]:
            assert "id" in tech
            assert "description" in tech
            assert "permissions" not in tech
            assert "required_params" not in tech
            assert "optional_params" not in tech

    def test_list_techniques_full_mode_json(self, capsys):
        """Test list_techniques without --brief flag outputs full data."""
        exit_code = list_techniques(service=None, output_format="json", brief=False)
        assert exit_code == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "techniques" in output

        # Full mode should have permissions
        for tech in output["techniques"]:
            assert "id" in tech
            assert "description" in tech
            assert "permissions" in tech

    def test_list_techniques_invalid_service_shows_suggestions(self, capsys):
        """Test that invalid service shows available services."""
        exit_code = list_techniques(service="invalid_service", output_format="json", brief=False)
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "No techniques found for service: invalid_service" in captured.err
        assert "Available services:" in captured.err
        assert "--list-services" in captured.err


class TestTechniqueInfo:
    """Tests for technique_info function."""

    def test_technique_info_unknown_shows_suggestions(self, capsys):
        """Test that unknown technique shows available techniques for that service."""
        exit_code = technique_info("s3.unknown_technique", output_format="json")
        assert exit_code == 1

        captured = capsys.readouterr()
        assert "Unknown technique 's3.unknown_technique'" in captured.err
        assert "Available s3 techniques:" in captured.err
        assert "s3.list_buckets" in captured.err
        assert "--list-techniques" in captured.err


class TestExecutionInfo:
    """Tests for execution_info function."""

    @mock_aws
    def test_execution_info_with_uuid(self, aws_credentials, test_config, tmp_path, capsys):
        """Test execution_info accepts UUID strings."""
        # Setup: Create execution with UUID
        config = CloakConfig.default()
        init_database(config)

        with session_scope(config) as session:
            execution = Execution(
                technique_name="s3.list_buckets",
                service="s3",
                aws_account_id="123456789012",
                aws_identity_arn="arn:aws:iam::123456789012:user/test",
            )
            session.add(execution)
            session.commit()
            exec_id = execution.id  # UUID string

        # Test: Call execution_info with UUID
        exit_code = execution_info(exec_id, output_format="json")
        assert exit_code == 0

        # Verify output contains execution data
        captured = capsys.readouterr()
        output_data = json.loads(captured.out)
        assert output_data["id"] == exec_id
        assert output_data["technique_name"] == "s3.list_buckets"

    @mock_aws
    def test_execution_info_not_found(self, aws_credentials, test_config, tmp_path, capsys):
        """Test execution_info handles non-existent UUID."""
        config = CloakConfig.default()
        init_database(config)

        # Test with random UUID
        exit_code = execution_info("00000000-0000-0000-0000-000000000000", output_format="json")
        assert exit_code == 1

        # Verify error message
        captured = capsys.readouterr()
        assert "not found" in captured.err

    @mock_aws
    def test_execution_info_includes_assets_and_findings(
        self, aws_credentials, test_config, tmp_path, capsys
    ):
        """Test execution_info returns complete data including assets."""
        config = CloakConfig.default()
        init_database(config)

        with session_scope(config) as session:
            execution = Execution(
                technique_name="s3.list_buckets",
                service="s3",
                aws_account_id="123456789012",
                aws_identity_arn="arn:aws:iam::123456789012:user/test",
            )
            session.add(execution)
            session.flush()

            # Add asset
            asset = Asset(
                execution_id=execution.id,
                service="s3",
                resource_type="s3_bucket",
                resource_id="test-bucket",
                account_id="123456789012",
            )
            session.add(asset)
            session.commit()
            exec_id = execution.id

        # Test: Call execution_info
        exit_code = execution_info(exec_id, output_format="json")
        assert exit_code == 0

        # Verify output includes assets
        captured = capsys.readouterr()
        output_data = json.loads(captured.out)
        assert "assets" in output_data
        assert len(output_data["assets"]) == 1
        assert output_data["assets"][0]["resource_id"] == "test-bucket"
