"""Tests for Lambda get_function_policy technique."""

import io
import json
import zipfile

import boto3
from moto import mock_aws

from cloak.core.config import TechniqueConfig
from cloak.core.models import Asset, Execution
from cloak.output.sanitizers import validate_summary
from cloak.techniques.lambda_.get_function_policy import GetFunctionPolicyTechnique


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
    response = iam_client.create_role(
        RoleName="test-lambda-role",
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )
    return response["Role"]["Arn"]


class TestGetFunctionPolicyTechnique:
    """Tests for GetFunctionPolicyTechnique."""

    def test_metadata(self, db_session, validated_connection):
        """Test that metadata is correct."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        metadata = technique.metadata
        assert metadata.name == "get_function_policy"
        assert metadata.service == "lambda"
        assert metadata.full_name == "lambda.get_function_policy"
        assert "lambda:GetPolicy" in metadata.required_permissions
        assert "lambda:ListFunctions" in metadata.required_permissions

    def test_metadata_has_description(self, db_session, validated_connection):
        """Test that metadata has a meaningful description."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        assert technique.metadata.description
        assert "polic" in technique.metadata.description.lower()  # matches policy/policies

    def test_metadata_has_required_parameter(self, db_session, validated_connection):
        """Test that metadata specifies function_name as required."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        assert len(technique.metadata.required_parameters) == 1
        param = technique.metadata.required_parameters[0]
        assert param.name == "function_name"
        assert param.required is True

    def test_validate_success(self, db_session, validated_connection):
        """Test that validation passes with valid function_name."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "my-function"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_success_all_mode(self, db_session, validated_connection):
        """Test that validation passes with 'all' function_name."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_missing_parameter(self, db_session, validated_connection):
        """Test validation fails with missing function_name."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert "function_name parameter is required" in result.errors[0]

    def test_validate_empty_parameter(self, db_session, validated_connection):
        """Test validation fails with empty function_name."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": ""},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        # Empty string is falsy, so caught by "is required" check
        assert "function_name" in result.errors[0]

    def test_validate_invalid_type(self, db_session, validated_connection):
        """Test validation fails with wrong parameter type."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": 123},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        result = technique.validate()
        assert result.valid is False
        assert "must be a string" in result.errors[0]

    def test_dry_run_specific_function(self, db_session, validated_connection):
        """Test dry-run shows correct actions for specific function."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "my-function"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "GetPolicy" in str(result.actions)
        assert "my-function" in str(result.actions)
        assert len(result.required_permissions) == 2

    def test_dry_run_all_mode(self, db_session, validated_connection):
        """Test dry-run shows correct actions for 'all' mode."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        result = technique.dry_run()
        assert "ListFunctions" in str(result.actions)
        assert "GetPolicy" in str(result.actions)
        assert "each function" in str(result.actions).lower()

    def test_dry_run_no_database_writes(self, db_session, validated_connection):
        """Test that dry-run does not write to database."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test"},
            dry_run=True,
        )
        technique = GetFunctionPolicyTechnique(config, None, validated_connection)

        # Should not fail with None session
        result = technique.dry_run()
        assert len(result.actions) > 0

    @mock_aws
    def test_execute_function_no_policy(self, db_session, aws_credentials):
        """Test execution with function that has no policy."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function-no-policy",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test-function-no-policy"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)

        result = technique.execute()

        # Should succeed but find no policy
        assert result.success is True
        assert result.asset_count == 0

    @mock_aws
    def test_execute_function_with_policy(self, db_session, aws_credentials):
        """Test execution with function that has a policy."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")
        lambda_client.create_function(
            FunctionName="test-function-with-policy",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        # Add a resource-based policy
        lambda_client.add_permission(
            FunctionName="test-function-with-policy",
            StatementId="allow-s3",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            SourceArn="arn:aws:s3:::test-bucket",
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test-function-with-policy"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 1

    @mock_aws
    def test_execute_all_mode_no_functions(self, db_session, aws_credentials):
        """Test execution in 'all' mode with no functions."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        assert result.asset_count == 0

    @mock_aws
    def test_execute_all_mode_multiple_functions(self, db_session, aws_credentials):
        """Test execution in 'all' mode with multiple functions."""
        iam = boto3.client("iam", region_name="us-east-1")
        role_arn = get_lambda_role_arn(iam)

        lambda_client = boto3.client("lambda", region_name="us-east-1")

        # Create functions with policies
        for i in range(2):
            lambda_client.create_function(
                FunctionName=f"test-function-{i}",
                Runtime="python3.9",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": get_lambda_zip()},
            )
            lambda_client.add_permission(
                FunctionName=f"test-function-{i}",
                StatementId="allow-invoke",
                Action="lambda:InvokeFunction",
                Principal="s3.amazonaws.com",
            )

        # Create one function without policy
        lambda_client.create_function(
            FunctionName="test-function-no-policy",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)

        result = technique.execute()

        assert result.success is True
        # Only 2 functions have policies
        assert result.asset_count == 2

    @mock_aws
    def test_execute_nonexistent_function(self, db_session, aws_credentials):
        """Test execution with nonexistent function."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "nonexistent-function"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)

        result = technique.execute()

        # Should succeed but find nothing
        assert result.success is True
        assert result.asset_count == 0

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
        lambda_client.add_permission(
            FunctionName="test-function-stored",
            StatementId="allow-s3",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test-function-stored"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)

        result = technique.execute()

        # Query database for stored assets
        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1

        asset = assets[0]
        assert asset.service == "lambda"
        assert asset.resource_type == "lambda_function_policy"
        assert asset.region == "us-east-1"
        assert asset.resource_id == "test-function-stored"

    @mock_aws
    def test_execute_creates_execution_record(self, db_session, aws_credentials):
        """Test that execution record is created."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)

        result = technique.execute()

        # Query execution record
        execution = db_session.query(Execution).filter_by(id=result.execution_id).first()
        assert execution is not None
        assert execution.technique_name == "lambda.get_function_policy"
        assert execution.service == "lambda"
        assert execution.status == "completed"

    @mock_aws
    def test_summarize_no_policies(self, db_session, validated_connection):
        """Test summary for zero policies with all mode."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No Lambda functions with resource-based policies" in summary
        # Validate no sensitive data
        is_safe, violations = validate_summary(summary)
        assert is_safe, f"Summary leaked data: {violations}"

    @mock_aws
    def test_summarize_specific_function_no_policy(self, db_session, validated_connection):
        """Test summary for specific function with no policy."""
        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "specific-function"},
        )
        technique = GetFunctionPolicyTechnique(config, db_session, validated_connection)

        summary = technique.summarize([], [])

        assert "No resource-based policy found" in summary
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
        lambda_client.add_permission(
            FunctionName="test-function",
            StatementId="allow-invoke",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)
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
            FunctionName="production-payment-api",
            Runtime="python3.9",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": get_lambda_zip()},
        )
        lambda_client.add_permission(
            FunctionName="production-payment-api",
            StatementId="allow-api-gw",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)
        result = technique.execute()

        # CRITICAL: Validate summary has NO sensitive data
        is_safe, violations = validate_summary(result.summary)
        assert is_safe, f"Summary leaked sensitive data: {violations}"

        # Explicitly check function names are NOT in summary
        assert "production-payment-api" not in result.summary
        assert "arn:aws:lambda" not in result.summary

    @mock_aws
    def test_asset_data_contains_policy(self, db_session, aws_credentials):
        """Test that asset data contains the parsed policy."""
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
        lambda_client.add_permission(
            FunctionName="test-function",
            StatementId="allow-s3",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "test-function"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)
        result = technique.execute()

        assets = db_session.query(Asset).filter_by(execution_id=result.execution_id).all()
        assert len(assets) == 1
        asset = assets[0]

        # Check policy is stored as parsed JSON
        assert "Policy" in asset.data
        assert "PolicyText" in asset.data
        assert isinstance(asset.data["Policy"], dict)
        assert "Statement" in asset.data["Policy"]

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
        lambda_client.add_permission(
            FunctionName="test-function",
            StatementId="allow-invoke",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)
        result = technique.execute()

        assert "execution_id" in result.summary
        assert result.execution_id in result.summary

    @mock_aws
    def test_summarize_has_statement_count(self, db_session, aws_credentials):
        """Test that summary includes total policy statement count."""
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
        lambda_client.add_permission(
            FunctionName="test-function",
            StatementId="allow-invoke",
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        config = TechniqueConfig(
            technique_name="lambda.get_function_policy",
            parameters={"function_name": "all"},
            dry_run=False,
        )
        technique = GetFunctionPolicyTechnique(config, db_session)
        result = technique.execute()

        assert "Total policy statements" in result.summary
