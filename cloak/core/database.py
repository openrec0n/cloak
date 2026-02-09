"""Database management for CLOAK."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from cloak.core.config import CloakConfig, get_config
from cloak.core.models import Base

if TYPE_CHECKING:
    from cloak.core.models import Execution


# Enable foreign key constraints for SQLite
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection: object, connection_record: object) -> None:
    """Enable foreign key support in SQLite."""
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# Global engine and session factory
_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_database_url(config: CloakConfig | None = None) -> str:
    """Get the database URL from configuration."""
    if config is None:
        config = get_config()
    # Use as_posix() to ensure forward slashes on Windows
    return f"sqlite:///{config.database_path.as_posix()}"


def get_engine(config: CloakConfig | None = None) -> Engine:
    """Get or create the SQLAlchemy engine.

    Args:
        config: Optional configuration. Uses global config if not provided.

    Returns:
        SQLAlchemy engine instance.
    """
    global _engine

    if _engine is None:
        if config is None:
            config = get_config()

        # Ensure database directory exists
        config.ensure_directories()

        database_url = get_database_url(config)
        _engine = create_engine(
            database_url,
            echo=False,  # Set to True for SQL debugging
            pool_pre_ping=True,
        )

    return _engine


def get_session_factory(config: CloakConfig | None = None) -> sessionmaker[Session]:
    """Get or create the session factory.

    Args:
        config: Optional configuration. Uses global config if not provided.

    Returns:
        SQLAlchemy sessionmaker instance.
    """
    global _session_factory

    if _session_factory is None:
        engine = get_engine(config)
        _session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    return _session_factory


def get_session(config: CloakConfig | None = None) -> Session:
    """Create a new database session.

    Args:
        config: Optional configuration. Uses global config if not provided.

    Returns:
        New SQLAlchemy session instance.
    """
    factory = get_session_factory(config)
    return factory()


@contextmanager
def session_scope(config: CloakConfig | None = None) -> Generator[Session, None, None]:
    """Provide a transactional scope around a series of operations.

    Usage:
        with session_scope() as session:
            session.add(execution)
            session.commit()

    Args:
        config: Optional configuration. Uses global config if not provided.

    Yields:
        SQLAlchemy session with automatic commit/rollback.
    """
    session = get_session(config)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_database(config: CloakConfig | None = None) -> None:
    """Initialize the database schema.

    Creates all tables if they don't exist.

    Args:
        config: Optional configuration. Uses global config if not provided.
    """
    engine = get_engine(config)
    Base.metadata.create_all(engine)


def reset_database(config: CloakConfig | None = None) -> None:
    """Reset the database by dropping and recreating all tables.

    WARNING: This will delete all data!

    Args:
        config: Optional configuration. Uses global config if not provided.
    """
    engine = get_engine(config)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def close_database() -> None:
    """Close database connections and reset global state.

    Useful for testing and cleanup.
    """
    global _engine, _session_factory

    if _engine is not None:
        _engine.dispose()
        _engine = None

    _session_factory = None


def create_in_memory_engine() -> Engine:
    """Create an in-memory SQLite engine for testing.

    Returns:
        SQLAlchemy engine using in-memory SQLite.
    """
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    return engine


def create_test_session(engine: Engine | None = None) -> Session:
    """Create a session for testing.

    Args:
        engine: Optional engine. Creates in-memory engine if not provided.

    Returns:
        SQLAlchemy session for testing.
    """
    if engine is None:
        engine = create_in_memory_engine()

    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    return SessionLocal()


# Query helpers for CLI commands


def get_recent_executions(session: Session, limit: int = 10) -> list:
    """Get recent executions, ordered by start time.

    Args:
        session: Database session
        limit: Maximum number of executions to return

    Returns:
        List of Execution objects
    """
    from cloak.core.models import Execution

    return session.query(Execution).order_by(Execution.started_at.desc()).limit(limit).all()


def get_execution_by_id(session: Session, execution_id: str) -> Execution | None:
    """Get execution by ID.

    Args:
        session: Database session
        execution_id: Execution ID (UUID string)

    Returns:
        Execution object or None if not found
    """
    from cloak.core.models import Execution

    return session.query(Execution).filter(Execution.id == execution_id).first()


def get_executions_by_technique(session: Session, technique_name: str) -> list:
    """Get all executions for a technique.

    Args:
        session: Database session
        technique_name: Technique name (e.g., "s3.list_buckets")

    Returns:
        List of Execution objects
    """
    from cloak.core.models import Execution

    return (
        session.query(Execution)
        .filter(Execution.technique_name == technique_name)
        .order_by(Execution.started_at.desc())
        .all()
    )


def get_execution_stats(session: Session) -> dict:
    """Get execution statistics.

    Args:
        session: Database session

    Returns:
        Dictionary with execution statistics
    """
    from cloak.core.models import Execution

    total = session.query(Execution).count()
    completed = session.query(Execution).filter(Execution.status == "completed").count()
    failed = session.query(Execution).filter(Execution.status == "failed").count()

    return {
        "total_executions": total,
        "completed": completed,
        "failed": failed,
        "success_rate": completed / total if total > 0 else 0,
    }
