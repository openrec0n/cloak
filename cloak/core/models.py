"""SQLAlchemy ORM models for CLOAK database."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class ExecutionStatus(str, Enum):
    """Status of a technique execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Execution(Base):
    """Represents a single technique execution.

    Tracks the execution lifecycle, configuration, and results summary.
    """

    __tablename__ = "executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    technique_name: Mapped[str] = mapped_column(String(100), nullable=False)
    service: Mapped[str] = mapped_column(String(50), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ExecutionStatus.PENDING.value
    )
    aws_account_id: Mapped[str] = mapped_column(String(20), nullable=False)
    aws_identity_arn: Mapped[str] = mapped_column(String(500), nullable=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    # Relationships
    assets: Mapped[list[Asset]] = relationship(
        "Asset", back_populates="execution", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="execution", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_executions_technique", "technique_name"),
        Index("idx_executions_status", "status"),
        Index("idx_executions_account", "aws_account_id"),
        Index("idx_executions_started_at", "started_at"),
    )

    @property
    def config(self) -> dict[str, Any]:
        """Parse config JSON into dictionary."""
        return json.loads(self.config_json) if self.config_json else {}

    @config.setter
    def config(self, value: dict[str, Any]) -> None:
        """Set config from dictionary."""
        self.config_json = json.dumps(value)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "technique_name": self.technique_name,
            "service": self.service,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "aws_account_id": self.aws_account_id,
            "aws_identity_arn": self.aws_identity_arn,
            "config": self.config,
            "summary": self.summary,
            "error_message": self.error_message,
            "finding_count": self.finding_count,
            "asset_count": self.asset_count,
        }

    def mark_running(self) -> None:
        """Mark execution as running."""
        self.status = ExecutionStatus.RUNNING.value
        self.started_at = utc_now()

    def mark_completed(self, summary: str, finding_count: int = 0, asset_count: int = 0) -> None:
        """Mark execution as completed with results."""
        self.status = ExecutionStatus.COMPLETED.value
        self.completed_at = utc_now()
        self.summary = summary
        self.finding_count = finding_count
        self.asset_count = asset_count

    def mark_failed(self, error_message: str, summary: str | None = None) -> None:
        """Mark execution as failed with error.

        Args:
            error_message: The error message from the failure.
            summary: Optional sanitized summary for display.
        """
        self.status = ExecutionStatus.FAILED.value
        self.completed_at = utc_now()
        self.error_message = error_message
        if summary is not None:
            self.summary = summary


class Asset(Base):
    """Represents a discovered cloud resource.

    Stores the full resource data in OCSF-compatible format.
    """

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("executions.id"), nullable=False
    )
    service: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)
    resource_arn: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    region: Mapped[str | None] = mapped_column(String(50), nullable=True)
    account_id: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    # Relationships
    execution: Mapped[Execution] = relationship("Execution", back_populates="assets")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="asset")

    __table_args__ = (
        Index("idx_assets_service", "service"),
        Index("idx_assets_type", "resource_type"),
        Index("idx_assets_execution", "execution_id"),
        Index("idx_assets_resource", "resource_type", "resource_id"),
    )

    @property
    def data(self) -> dict[str, Any]:
        """Parse data JSON into dictionary."""
        return json.loads(self.data_json) if self.data_json else {}

    @data.setter
    def data(self, value: dict[str, Any]) -> None:
        """Set data from dictionary."""
        self.data_json = json.dumps(value, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "region": self.region,
            "account_id": self.account_id,
            "name": self.name,
            "data": self.data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_ocsf(self) -> dict[str, Any]:
        """Convert to OCSF Cloud Resource format."""
        return {
            "uid": self.resource_id,
            "cloud": {
                "provider": "AWS",
                "region": self.region,
                "account": {"uid": self.account_id},
            },
            "type": self.resource_type,
            "name": self.name,
            "data": self.data,
        }


class Finding(Base):
    """Represents a security finding from an enumeration.

    Stores finding details including severity, description, and recommendations.
    """

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    execution_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("executions.id"), nullable=False
    )
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default=Severity.INFO.value)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)
    region: Mapped[str | None] = mapped_column(String(50), nullable=True)
    data_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    # Relationships
    execution: Mapped[Execution] = relationship("Execution", back_populates="findings")
    asset: Mapped[Asset | None] = relationship("Asset", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_type", "finding_type"),
        Index("idx_findings_execution", "execution_id"),
        Index("idx_findings_resource", "resource_type", "resource_id"),
        Index("idx_findings_asset", "asset_id"),
    )

    @property
    def data(self) -> dict[str, Any]:
        """Parse data JSON into dictionary."""
        return json.loads(self.data_json) if self.data_json else {}

    @data.setter
    def data(self, value: dict[str, Any]) -> None:
        """Set data from dictionary."""
        self.data_json = json.dumps(value, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "execution_id": self.execution_id,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "data": self.data,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_ocsf_detection_finding(self) -> dict[str, Any]:
        """Convert to OCSF Detection Finding format."""
        severity_mapping = {
            Severity.CRITICAL.value: 5,
            Severity.HIGH.value: 4,
            Severity.MEDIUM.value: 3,
            Severity.LOW.value: 2,
            Severity.INFO.value: 1,
        }

        return {
            "class_uid": 2004,  # Detection Finding
            "class_name": "Detection Finding",
            "severity_id": severity_mapping.get(self.severity, 0),
            "severity": self.severity,
            "finding_info": {
                "uid": self.id,
                "title": self.title,
                "desc": self.description,
                "types": [self.finding_type],
            },
            "resources": [
                {
                    "type": self.resource_type,
                    "uid": self.resource_id,
                    "region": self.region,
                }
            ],
            "remediation": {"desc": self.recommendation} if self.recommendation else None,
            "data": self.data,
        }
