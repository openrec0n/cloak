"""Pytest configuration and fixtures for CLOAK tests."""

from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import boto3
import pytest
from moto import mock_aws
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cloak.core.aws_connection import AWSConnection, reset_aws_connection
from cloak.core.config import CloakConfig
from cloak.core.database import close_database
from cloak.core.models import Base


@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset global state between tests."""
    yield
    close_database()
    reset_aws_connection()


@pytest.fixture
def aws_credentials():
    """Set up mock AWS credentials for moto.

    These credentials are used by moto to simulate AWS services.
    They are NOT real credentials.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    yield

    # Cleanup
    for key in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECURITY_TOKEN",
        "AWS_SESSION_TOKEN",
    ]:
        os.environ.pop(key, None)


@pytest.fixture
def test_config(tmp_path: Path) -> CloakConfig:
    """Create a test configuration with temporary paths.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        CloakConfig configured for testing.
    """
    return CloakConfig(
        database_path=tmp_path / "test_cloak.db",
        log_directory=tmp_path / "logs",
        log_level="DEBUG",
        log_format="text",
        aws_profile=None,
        aws_regions=["us-east-1"],
        dry_run_default=True,
        max_api_calls_per_technique=100,
        summary_max_items=5,
    )


@pytest.fixture
def in_memory_engine():
    """Create an in-memory SQLite engine for testing.

    Returns:
        SQLAlchemy engine using in-memory SQLite.
    """
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db_session(in_memory_engine) -> Generator[Session, None, None]:
    """Create a database session for testing.

    Args:
        in_memory_engine: In-memory SQLite engine fixture.

    Yields:
        SQLAlchemy session with automatic cleanup.
    """
    SessionLocal = sessionmaker(bind=in_memory_engine, expire_on_commit=False)
    session = SessionLocal()

    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def mock_aws_env(aws_credentials):
    """Set up a complete mocked AWS environment.

    Combines AWS credentials with moto mocking.

    Yields:
        Context with mocked AWS services.
    """
    with mock_aws():
        yield


@pytest.fixture
def s3_client(mock_aws_env):
    """Create a mocked S3 client.

    Args:
        mock_aws_env: Mocked AWS environment fixture.

    Returns:
        Mocked boto3 S3 client.
    """
    return boto3.client("s3", region_name="us-east-1")


@pytest.fixture
def s3_with_buckets(s3_client):
    """Create an S3 client with pre-populated buckets.

    Args:
        s3_client: Mocked S3 client fixture.

    Returns:
        S3 client with test buckets created.
    """
    # Create test buckets
    s3_client.create_bucket(Bucket="test-bucket-1")
    s3_client.create_bucket(Bucket="test-bucket-2")
    s3_client.create_bucket(
        Bucket="test-bucket-west",
        CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
    )

    return s3_client


@pytest.fixture
def iam_client(mock_aws_env):
    """Create a mocked IAM client.

    Args:
        mock_aws_env: Mocked AWS environment fixture.

    Returns:
        Mocked boto3 IAM client.
    """
    return boto3.client("iam", region_name="us-east-1")


@pytest.fixture
def ec2_client(mock_aws_env):
    """Create a mocked EC2 client.

    Args:
        mock_aws_env: Mocked AWS environment fixture.

    Returns:
        Mocked boto3 EC2 client.
    """
    return boto3.client("ec2", region_name="us-east-1")


@pytest.fixture
def lambda_client(mock_aws_env):
    """Create a mocked Lambda client.

    Args:
        mock_aws_env: Mocked AWS environment fixture.

    Returns:
        Mocked boto3 Lambda client.
    """
    return boto3.client("lambda", region_name="us-east-1")


@pytest.fixture
def sts_client(mock_aws_env):
    """Create a mocked STS client.

    Args:
        mock_aws_env: Mocked AWS environment fixture.

    Returns:
        Mocked boto3 STS client.
    """
    return boto3.client("sts", region_name="us-east-1")


@pytest.fixture
def aws_connection(mock_aws_env, test_config) -> AWSConnection:
    """Create an AWS connection with mocked services.

    Args:
        mock_aws_env: Mocked AWS environment fixture.
        test_config: Test configuration fixture.

    Returns:
        AWSConnection configured for testing.
    """
    return AWSConnection(config=test_config)


@pytest.fixture
def validated_connection(aws_connection) -> AWSConnection:
    """Create a validated AWS connection.

    Args:
        aws_connection: AWS connection fixture.

    Returns:
        AWSConnection that has been validated.
    """
    aws_connection.validate()
    return aws_connection
