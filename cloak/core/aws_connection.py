"""AWS connection validation and management for CLOAK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from cloak.core.config import CloakConfig, get_config
from cloak.core.logging import get_logger

logger = get_logger("aws_connection")


@dataclass
class ConnectionInfo:
    """Information about the current AWS connection.

    Contains identity information returned by STS GetCallerIdentity.
    """

    account_id: str
    arn: str
    user_id: str
    is_valid: bool = True
    error_message: str | None = None

    @property
    def identity_type(self) -> str:
        """Determine the type of identity (user, role, etc.)."""
        if ":user/" in self.arn:
            return "user"
        elif ":assumed-role/" in self.arn:
            return "assumed-role"
        elif ":root" in self.arn:
            return "root"
        else:
            return "unknown"

    @property
    def identity_name(self) -> str:
        """Extract the identity name from the ARN."""
        # ARN format: arn:aws:iam::123456789012:user/username
        # or: arn:aws:sts::123456789012:assumed-role/role-name/session-name
        try:
            if ":user/" in self.arn:
                return self.arn.split(":user/")[1]
            elif ":assumed-role/" in self.arn:
                parts = self.arn.split(":assumed-role/")[1]
                return parts.split("/")[0]  # Return role name
            elif ":root" in self.arn:
                return "root"
            else:
                return self.user_id
        except (IndexError, AttributeError):
            return self.user_id

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "account_id": self.account_id,
            "arn": self.arn,
            "user_id": self.user_id,
            "identity_type": self.identity_type,
            "identity_name": self.identity_name,
            "is_valid": self.is_valid,
            "error_message": self.error_message,
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary."""
        if not self.is_valid:
            return f"Connection failed: {self.error_message}"

        return (
            f"Connected to AWS account {self.account_id} "
            f"as {self.identity_type} '{self.identity_name}'"
        )

    @classmethod
    def from_error(cls, error_message: str) -> ConnectionInfo:
        """Create a ConnectionInfo representing a failed connection."""
        return cls(
            account_id="",
            arn="",
            user_id="",
            is_valid=False,
            error_message=error_message,
        )


class AWSConnection:
    """Manages AWS connections and session creation.

    Uses the standard boto3 credential chain for authentication.
    """

    def __init__(self, config: CloakConfig | None = None):
        """Initialize AWS connection manager.

        Args:
            config: Optional configuration. Uses global config if not provided.
        """
        self.config = config or get_config()
        self._session: boto3.Session | None = None
        self._connection_info: ConnectionInfo | None = None

    @property
    def session(self) -> boto3.Session:
        """Get or create a boto3 session.

        Returns:
            Configured boto3 session.
        """
        if self._session is None:
            session_kwargs: dict[str, Any] = {}

            if self.config.aws_profile:
                session_kwargs["profile_name"] = self.config.aws_profile

            if self.config.aws_regions:
                session_kwargs["region_name"] = self.config.aws_regions[0]

            self._session = boto3.Session(**session_kwargs)

        return self._session

    def get_client(self, service_name: str, region_name: str | None = None) -> Any:
        """Get a boto3 client for the specified service.

        Args:
            service_name: AWS service name (e.g., 's3', 'iam', 'ec2').
            region_name: Optional region override.

        Returns:
            boto3 service client.
        """
        kwargs: dict[str, Any] = {}
        if region_name:
            kwargs["region_name"] = region_name

        return self.session.client(service_name, **kwargs)  # type: ignore[call-overload]

    def get_resource(self, service_name: str, region_name: str | None = None) -> Any:
        """Get a boto3 resource for the specified service.

        Args:
            service_name: AWS service name (e.g., 's3', 'dynamodb').
            region_name: Optional region override.

        Returns:
            boto3 service resource.
        """
        kwargs: dict[str, Any] = {}
        if region_name:
            kwargs["region_name"] = region_name

        return self.session.resource(service_name, **kwargs)  # type: ignore[call-overload]

    def validate(self) -> ConnectionInfo:
        """Validate AWS connection using STS GetCallerIdentity.

        This is a lightweight check that verifies credentials are valid
        and returns information about the current identity.

        Returns:
            ConnectionInfo with identity details or error information.
        """
        if self._connection_info is not None:
            return self._connection_info

        try:
            sts_client = self.get_client("sts")
            response = sts_client.get_caller_identity()

            self._connection_info = ConnectionInfo(
                account_id=response["Account"],
                arn=response["Arn"],
                user_id=response["UserId"],
                is_valid=True,
            )

            logger.info(
                "AWS connection validated",
                account_id=self._connection_info.account_id,
                identity_type=self._connection_info.identity_type,
                identity_name=self._connection_info.identity_name,
            )

        except NoCredentialsError:
            error_msg = (
                "No AWS credentials found. Configure credentials via environment "
                "variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), "
                "~/.aws/credentials file, or IAM role."
            )
            logger.error("AWS connection failed: no credentials", error=error_msg)
            self._connection_info = ConnectionInfo.from_error(error_msg)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))

            if error_code == "ExpiredToken":
                error_msg = "AWS session token has expired. Please refresh your credentials."
            elif error_code == "InvalidClientTokenId":
                error_msg = "AWS access key is invalid. Please check your credentials."
            elif error_code == "SignatureDoesNotMatch":
                error_msg = "AWS secret key is invalid. Please check your credentials."

            logger.error("AWS connection failed", error_code=error_code, error=error_msg)
            self._connection_info = ConnectionInfo.from_error(error_msg)

        except BotoCoreError as e:
            error_msg = f"AWS connection error: {str(e)}"
            logger.error("AWS connection failed", error=error_msg)
            self._connection_info = ConnectionInfo.from_error(error_msg)

        return self._connection_info

    def reset(self) -> None:
        """Reset connection state.

        Clears cached session and connection info.
        """
        self._session = None
        self._connection_info = None

    def require_valid_connection(self) -> ConnectionInfo:
        """Validate connection and raise if invalid.

        Returns:
            ConnectionInfo if connection is valid.

        Raises:
            RuntimeError: If connection is not valid.
        """
        info = self.validate()
        if not info.is_valid:
            raise RuntimeError(f"AWS connection failed: {info.error_message}")
        return info


# Global connection instance (lazily initialized)
_connection: AWSConnection | None = None


def get_aws_connection(config: CloakConfig | None = None) -> AWSConnection:
    """Get the global AWS connection instance.

    Args:
        config: Optional configuration. Uses global config if not provided.

    Returns:
        AWSConnection instance.
    """
    global _connection

    if _connection is None:
        _connection = AWSConnection(config)

    return _connection


def validate_aws_connection(config: CloakConfig | None = None) -> ConnectionInfo:
    """Validate AWS connection and return connection info.

    Convenience function that gets the connection and validates it.

    Args:
        config: Optional configuration. Uses global config if not provided.

    Returns:
        ConnectionInfo with identity details or error information.
    """
    connection = get_aws_connection(config)
    return connection.validate()


def reset_aws_connection() -> None:
    """Reset the global AWS connection.

    Useful for testing or when credentials change.
    """
    global _connection

    if _connection is not None:
        _connection.reset()
        _connection = None
