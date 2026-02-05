"""Tests for cloak.core.aws_connection module."""

import pytest

from cloak.core.aws_connection import (
    AWSConnection,
    ConnectionInfo,
    get_aws_connection,
    reset_aws_connection,
    validate_aws_connection,
)


class TestConnectionInfo:
    """Tests for ConnectionInfo dataclass."""

    def test_user_identity_type(self):
        """Test identity type detection for IAM user."""
        info = ConnectionInfo(
            account_id="123456789012",
            arn="arn:aws:iam::123456789012:user/testuser",
            user_id="AIDAEXAMPLE",
        )

        assert info.identity_type == "user"
        assert info.identity_name == "testuser"

    def test_assumed_role_identity_type(self):
        """Test identity type detection for assumed role."""
        info = ConnectionInfo(
            account_id="123456789012",
            arn="arn:aws:sts::123456789012:assumed-role/TestRole/session-name",
            user_id="AROAEXAMPLE:session-name",
        )

        assert info.identity_type == "assumed-role"
        assert info.identity_name == "TestRole"

    def test_root_identity_type(self):
        """Test identity type detection for root account."""
        info = ConnectionInfo(
            account_id="123456789012",
            arn="arn:aws:iam::123456789012:root",
            user_id="123456789012",
        )

        assert info.identity_type == "root"
        assert info.identity_name == "root"

    def test_to_summary_success(self):
        """Test summary generation for successful connection."""
        info = ConnectionInfo(
            account_id="123456789012",
            arn="arn:aws:iam::123456789012:user/testuser",
            user_id="AIDAEXAMPLE",
        )

        summary = info.to_summary()
        assert "123456789012" in summary
        assert "user" in summary
        assert "testuser" in summary

    def test_to_summary_failure(self):
        """Test summary generation for failed connection."""
        info = ConnectionInfo.from_error("No credentials found")

        summary = info.to_summary()
        assert "failed" in summary.lower()
        assert "No credentials found" in summary

    def test_to_dict(self):
        """Test dictionary conversion."""
        info = ConnectionInfo(
            account_id="123456789012",
            arn="arn:aws:iam::123456789012:user/testuser",
            user_id="AIDAEXAMPLE",
        )

        data = info.to_dict()
        assert data["account_id"] == "123456789012"
        assert data["identity_type"] == "user"
        assert data["identity_name"] == "testuser"
        assert data["is_valid"] is True


class TestAWSConnection:
    """Tests for AWSConnection class."""

    def test_validate_success(self, mock_aws_env, test_config):
        """Test successful connection validation."""
        connection = AWSConnection(config=test_config)
        info = connection.validate()

        assert info.is_valid is True
        assert info.account_id is not None
        assert len(info.account_id) == 12  # AWS account IDs are 12 digits

    def test_validate_caches_result(self, mock_aws_env, test_config):
        """Test that validation result is cached."""
        connection = AWSConnection(config=test_config)

        info1 = connection.validate()
        info2 = connection.validate()

        assert info1 is info2  # Same object

    def test_get_client(self, mock_aws_env, test_config):
        """Test getting a boto3 client."""
        connection = AWSConnection(config=test_config)
        client = connection.get_client("s3")

        # Verify it's a working client
        response = client.list_buckets()
        assert "Buckets" in response

    def test_get_client_with_region(self, mock_aws_env, test_config):
        """Test getting a client with specific region."""
        connection = AWSConnection(config=test_config)
        client = connection.get_client("ec2", region_name="us-west-2")

        # The client should be configured for us-west-2
        assert client.meta.region_name == "us-west-2"

    def test_reset_clears_cache(self, mock_aws_env, test_config):
        """Test that reset clears cached session and connection info."""
        connection = AWSConnection(config=test_config)

        info1 = connection.validate()
        connection.reset()
        info2 = connection.validate()

        assert info1 is not info2  # Different objects after reset

    def test_require_valid_connection_success(self, mock_aws_env, test_config):
        """Test require_valid_connection with valid credentials."""
        connection = AWSConnection(config=test_config)
        info = connection.require_valid_connection()

        assert info.is_valid is True

    def test_require_valid_connection_failure(self, test_config):
        """Test require_valid_connection raises on invalid credentials."""
        from unittest.mock import patch

        from botocore.exceptions import ClientError

        connection = AWSConnection(config=test_config)

        # Mock the STS client to raise an error
        with patch.object(connection, "get_client") as mock_get_client:
            mock_sts = mock_get_client.return_value
            mock_sts.get_caller_identity.side_effect = ClientError(
                {"Error": {"Code": "InvalidClientTokenId", "Message": "Invalid credentials"}},
                "GetCallerIdentity",
            )

            with pytest.raises(RuntimeError, match="AWS connection failed"):
                connection.require_valid_connection()


class TestGlobalConnection:
    """Tests for global connection management functions."""

    def test_get_aws_connection(self, mock_aws_env, test_config):
        """Test getting global AWS connection."""
        reset_aws_connection()

        connection = get_aws_connection(test_config)
        assert isinstance(connection, AWSConnection)

    def test_validate_aws_connection(self, mock_aws_env, test_config):
        """Test validating AWS connection via convenience function."""
        reset_aws_connection()

        info = validate_aws_connection(test_config)
        assert info.is_valid is True

    def test_reset_aws_connection(self, mock_aws_env, test_config):
        """Test resetting global AWS connection."""
        reset_aws_connection()

        conn1 = get_aws_connection(test_config)
        conn1.validate()

        reset_aws_connection()

        conn2 = get_aws_connection(test_config)
        assert conn1 is not conn2
