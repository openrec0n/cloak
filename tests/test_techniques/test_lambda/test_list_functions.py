"""Tests for Lambda list_functions technique."""

import io
import zipfile

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.lambda_.list_functions import ListFunctionsTechnique


def get_lambda_zip():
    """Create a simple lambda zip file for moto."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", "def handler(event, context): return 'Hello'")
    zip_buffer.seek(0)
    return zip_buffer.read()


def get_lambda_role_arn(iam_client):
    """Create an IAM role for Lambda and return its ARN."""
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    import json

    response = iam_client.create_role(
        RoleName="test-lambda-role",
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    return response["Role"]["Arn"]


class TestListFunctionsTechnique:
    """Tests for ListFunctionsTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
        )
        technique = ListFunctionsTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "list_functions"
        assert metadata.service == "lambda"
        assert metadata.full_name == "lambda.list_functions"
        assert "lambda:ListFunctions" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
        )
        technique = ListFunctionsTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "function" in technique.metadata.description.lower()

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with empty config."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
        )
        technique = ListFunctionsTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_dry_run(self, db_session, validated_connection):
        """Test dry-run shows correct actions."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
        )
        technique = ListFunctionsTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "ListFunctions" in str(result.actions)
        assert len(result.required_permissions) == 1
        assert "us-east-1" in result.regions
        assert "paginated" in result.estimated_api_calls.lower()

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=True,
        )
        technique = ListFunctionsTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    def test_dry_run_shows_regions(self, db_session, validated_connection):
        """Test that dry-run includes region information."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            regions=["us-east-1", "us-west-2"],
        )
        technique = ListFunctionsTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert len(result.regions) == 2
        assert "us-east-1" in result.regions
        assert "us-west-2" in result.regions

    @mock_aws
    def test_execute_no_functions(self, db_session, aws_credentials):
        """Test execution with no functions."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 0
        assert result.finding_count == 0

    @mock_aws
    def test_execute_single_function(self, db_session, aws_credentials):
        """Test execution with single function."""
        # Create mock Lambda function
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1
        assert "function" in result.summary.lower()

    @mock_aws
    def test_execute_multiple_functions(self, db_session, aws_credentials):
        """Test execution with multiple functions."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        for i in range(3):
            lambda_client.create_function(
                FunctionName=f"test-function-{i}",
                Runtime="python3.9",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": get_lambda_zip()},
            )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 3

    @mock_aws
    def test_execute_functions_multiple_regions(self, db_session, aws_credentials):
        """Test execution with functions in multiple regions."""
        # Create role for both regions
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_east = boto3.client("lambda", region_name="us-east-1")
        lambda_west = boto3.client("lambda", region_name="us-west-2")

        lambda_east.create_function(
            FunctionName="test-function-east",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )
        lambda_west.create_function(
            FunctionName="test-function-west",
            Runtime="python3.11",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            regions=["us-east-1", "us-west-2"],
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 2
        # Summary should mention both regions
        assert "us-east-1" in result.summary
        assert "us-west-2" in result.summary

    @mock_aws
    def test_execute_functions_different_runtimes(self, db_session, aws_credentials):
        """Test execution with functions of different runtimes."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function-py39",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )
        lambda_client.create_function(
            FunctionName="test-function-py311",
            Runtime="python3.11",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 2
        # Summary should mention runtime distribution
        assert "Runtime distribution" in result.summary

    @mock_aws
    def test_execute_stores_assets(self, db_session, aws_credentials):
        """Test that assets are stored in database."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function-stored",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "lambda"
        assert asset.resource_type == "lambda_function"
        assert asset.region == "us-east-1"
        assert asset.resource_id == "test-function-stored"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "lambda.list_functions"
        assert execution.service == "lambda"
        assert execution.status == "completed"
        assert execution.finding_count == 0

    @mock_aws
    def test_summarize_no_functions(self, db_session, validated_connection):
        """Test summary for zero functions."""
        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
        )
        technique = ListFunctionsTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No Lambda functions" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_has_region_distribution(self, db_session, aws_credentials):
        """Test summary includes region distribution."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)
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
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="production-payment-processor",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check function names are NOT in summary
        assert "production-payment-processor" not in result.summary
        assert "arn:aws:lambda" not in result.summary

    @mock_aws
    def test_asset_data_contains_required_fields(self, db_session, aws_credentials):
        """Test that asset data contains all required fields."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
            MemorySize=256,
            Timeout=30,
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1
        asset = assets[0]

        # Check required fields in data
        assert "FunctionName" in asset.data
        assert "FunctionArn" in asset.data
        assert "Runtime" in asset.data
        assert "Handler" in asset.data
        assert "MemorySize" in asset.data
        assert "Timeout" in asset.data
        assert asset.data["Runtime"] == "python3.9"

    @mock_aws
    def test_summarize_includes_execution_id(self, db_session, aws_credentials):
        """Test that summary includes execution ID for database lookup."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary

    @mock_aws
    def test_summarize_has_code_size(self, db_session, aws_credentials):
        """Test that summary includes total code size."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.list_functions",
            parameters={},
            dry_run=False,
        )
        technique = ListFunctionsTechnique(config, db_session)
        result = technique.execute()

        assert "Total code size" in result.summary
        assert "MB" in result.summary
