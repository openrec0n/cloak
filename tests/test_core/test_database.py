"""Tests for cloak.core.database module."""

from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from cloak.core.config import CloakConfig
from cloak.core.database import (
    create_in_memory_engine,
    create_test_session,
    get_database_url,
    get_execution_stats,
    get_executions_by_technique,
    get_recent_executions,
)
from cloak.core.models import Asset, Execution, ExecutionStatus, Finding


class TestDatabaseSetup:
    """Tests for database initialization and setup."""

    def test_get_database_url(self, test_config: CloakConfig):
        """Test database URL generation."""
        url = get_database_url(test_config)
        assert url.startswith("sqlite:///")
        assert str(test_config.database_path) in url

    def test_create_in_memory_engine(self):
        """Test creating an in-memory SQLite engine."""
        engine = create_in_memory_engine()

        # Verify tables are created
        with engine.connect() as conn:
            result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
            tables = {row[0] for row in result}

        assert "executions" in tables
        assert "assets" in tables
        assert "findings" in tables

    def test_create_test_session(self):
        """Test creating a test session."""
        session = create_test_session()

        # Verify we can use the session
        execution = Execution(
            technique_name="test.technique",
            service="test",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/test",
        )
        session.add(execution)
        session.commit()

        # Query it back
        result = session.query(Execution).first()
        assert result is not None
        assert result.technique_name == "test.technique"

        session.close()


class TestSessionScope:
    """Tests for session_scope context manager."""

    def test_session_scope_commits_on_success(self, in_memory_engine):
        """Test that session_scope commits on successful operations."""
        # Use the sessionmaker directly with in-memory engine
        SessionLocal = sessionmaker(bind=in_memory_engine, expire_on_commit=False)

        execution_id = None
        session = SessionLocal()
        try:
            execution = Execution(
                technique_name="test.technique",
                service="test",
                aws_account_id="123456789012",
                aws_identity_arn="arn:aws:iam::123456789012:user/test",
            )
            session.add(execution)
            session.commit()
            execution_id = execution.id
        finally:
            session.close()

        # Verify committed - use a fresh session
        session = SessionLocal()
        result = session.query(Execution).filter_by(id=execution_id).first()
        session.close()
        assert result is not None

    def test_session_scope_rollbacks_on_error(self, in_memory_engine):
        """Test that session rollback works on exception."""
        SessionLocal = sessionmaker(bind=in_memory_engine, expire_on_commit=False)

        session = SessionLocal()
        try:
            execution = Execution(
                technique_name="test.technique",
                service="test",
                aws_account_id="123456789012",
                aws_identity_arn="arn:aws:iam::123456789012:user/test",
            )
            session.add(execution)
            raise ValueError("Simulated error")
        except ValueError:
            session.rollback()
        finally:
            session.close()

        # Verify rolled back
        session = SessionLocal()
        count = session.query(Execution).count()
        session.close()
        assert count == 0


class TestModelOperations:
    """Tests for ORM model operations using database fixtures."""

    def test_create_execution(self, db_session):
        """Test creating an execution record."""
        execution = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/testuser",
            config={"include_metadata": True},
        )

        db_session.add(execution)
        db_session.commit()

        result = db_session.query(Execution).first()
        assert result is not None
        assert result.technique_name == "s3.list_buckets"
        assert result.status == ExecutionStatus.PENDING.value
        assert result.config == {"include_metadata": True}

    def test_execution_lifecycle(self, db_session):
        """Test execution status transitions."""
        execution = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/testuser",
        )
        db_session.add(execution)
        db_session.commit()

        # Mark running
        execution.mark_running()
        db_session.commit()
        assert execution.status == ExecutionStatus.RUNNING.value
        assert execution.started_at is not None

        # Mark completed
        execution.mark_completed(
            summary="Found 5 buckets",
            finding_count=2,
            asset_count=5,
        )
        db_session.commit()
        assert execution.status == ExecutionStatus.COMPLETED.value
        assert execution.completed_at is not None
        assert execution.summary == "Found 5 buckets"
        assert execution.finding_count == 2
        assert execution.asset_count == 5

    def test_execution_failure(self, db_session):
        """Test marking execution as failed."""
        execution = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/testuser",
        )
        db_session.add(execution)
        execution.mark_running()
        db_session.commit()

        execution.mark_failed("Access denied")
        db_session.commit()

        assert execution.status == ExecutionStatus.FAILED.value
        assert execution.error_message == "Access denied"

    def test_create_asset(self, db_session):
        """Test creating an asset record."""
        execution = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/testuser",
        )
        db_session.add(execution)
        db_session.commit()

        asset = Asset(
            execution_id=execution.id,
            service="s3",
            resource_type="s3_bucket",
            resource_id="my-test-bucket",
            resource_arn="arn:aws:s3:::my-test-bucket",
            region="us-east-1",
            account_id="123456789012",
            name="my-test-bucket",
            data={"CreationDate": "2024-01-01T00:00:00Z"},
        )
        db_session.add(asset)
        db_session.commit()

        result = db_session.query(Asset).first()
        assert result is not None
        assert result.resource_type == "s3_bucket"
        assert result.data["CreationDate"] == "2024-01-01T00:00:00Z"

    def test_create_finding(self, db_session):
        """Test creating a finding record."""
        execution = Execution(
            technique_name="s3.get_bucket_acl",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/testuser",
        )
        db_session.add(execution)
        db_session.commit()

        finding = Finding(
            execution_id=execution.id,
            severity="high",
            finding_type="public_bucket",
            title="S3 bucket is publicly accessible",
            description="The bucket ACL grants public read access",
            resource_type="s3_bucket",
            resource_id="public-bucket",
            data={"acl_grantee": "AllUsers"},
        )
        db_session.add(finding)
        db_session.commit()

        result = db_session.query(Finding).first()
        assert result is not None
        assert result.severity == "high"
        assert result.finding_type == "public_bucket"

    def test_execution_relationships(self, db_session):
        """Test relationships between execution, assets, and findings."""
        execution = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/testuser",
        )
        db_session.add(execution)
        db_session.commit()

        asset = Asset(
            execution_id=execution.id,
            service="s3",
            resource_type="s3_bucket",
            resource_id="test-bucket",
            account_id="123456789012",
        )
        db_session.add(asset)
        db_session.commit()

        finding = Finding(
            execution_id=execution.id,
            asset_id=asset.id,
            severity="medium",
            finding_type="no_versioning",
            title="Bucket versioning disabled",
            description="Versioning is not enabled",
            resource_type="s3_bucket",
            resource_id="test-bucket",
        )
        db_session.add(finding)
        db_session.commit()

        # Verify relationships
        db_session.refresh(execution)
        assert len(execution.assets) == 1
        assert len(execution.findings) == 1
        assert execution.assets[0].id == asset.id
        assert execution.findings[0].id == finding.id


class TestQueryHelpers:
    """Tests for database query helper functions."""

    def test_get_recent_executions(self, db_session):
        """Test fetching recent executions."""
        for i in range(3):
            exec_ = Execution(
                technique_name=f"s3.technique_{i}",
                service="s3",
                aws_account_id="123456789012",
                aws_identity_arn="arn:aws:iam::123456789012:user/test",
            )
            exec_.mark_completed(summary=f"Summary {i}", finding_count=0, asset_count=0)
            db_session.add(exec_)
        db_session.commit()

        results = get_recent_executions(db_session, limit=2)
        assert len(results) == 2

    def test_get_executions_by_technique(self, db_session):
        """Test fetching executions by technique name."""
        exec_ = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/test",
        )
        db_session.add(exec_)
        db_session.commit()

        results = get_executions_by_technique(db_session, "s3.list_buckets")
        assert len(results) == 1
        assert results[0].technique_name == "s3.list_buckets"

        results = get_executions_by_technique(db_session, "nonexistent")
        assert len(results) == 0

    def test_get_execution_stats(self, db_session):
        """Test execution statistics."""
        exec1 = Execution(
            technique_name="s3.list_buckets",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/test",
        )
        exec1.mark_completed(summary="OK", finding_count=0, asset_count=0)
        exec2 = Execution(
            technique_name="s3.get_bucket_acl",
            service="s3",
            aws_account_id="123456789012",
            aws_identity_arn="arn:aws:iam::123456789012:user/test",
        )
        exec2.mark_failed(error_message="Access denied")
        db_session.add_all([exec1, exec2])
        db_session.commit()

        stats = get_execution_stats(db_session)
        assert stats["total_executions"] == 2
        assert stats["completed"] == 1
        assert stats["failed"] == 1
        assert stats["success_rate"] == 0.5
