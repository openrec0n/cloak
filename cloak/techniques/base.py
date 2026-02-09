"""Base technique class and result types for CLOAK."""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from cloak.core.aws_connection import AWSConnection, ConnectionInfo
from cloak.core.config import ParameterSpec, TechniqueConfig
from cloak.core.logging import TechniqueLogger
from cloak.core.models import Asset, Execution, ExecutionStatus, Finding
from cloak.output.sanitizers import sanitize_text


@dataclass
class TechniqueMetadata:
    """Metadata describing a technique.

    Used for technique discovery and documentation.
    """

    name: str
    service: str
    description: str
    required_permissions: list[str]
    optional_parameters: list[ParameterSpec] = field(default_factory=list)
    required_parameters: list[ParameterSpec] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        """Get the full technique name (service.name)."""
        return f"{self.service}.{self.name}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "full_name": self.full_name,
            "service": self.service,
            "description": self.description,
            "required_permissions": self.required_permissions,
            "required_parameters": [p.model_dump() for p in self.required_parameters],
            "optional_parameters": [p.model_dump() for p in self.optional_parameters],
        }


@dataclass
class ValidationResult:
    """Result of technique configuration validation."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, error: str) -> None:
        """Add a validation error."""
        self.errors.append(error)
        self.valid = False

    def add_warning(self, warning: str) -> None:
        """Add a validation warning."""
        self.warnings.append(warning)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class DryRunResult:
    """Result of a technique dry-run.

    Shows what actions would be performed without actually executing.
    """

    actions: list[str]
    estimated_api_calls: str
    regions: list[str]
    required_permissions: list[str]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "actions": self.actions,
            "estimated_api_calls": self.estimated_api_calls,
            "regions": self.regions,
            "required_permissions": self.required_permissions,
            "warnings": self.warnings,
        }

    def to_summary(self, technique_name: str = "", config: dict[str, Any] | None = None) -> str:
        """Generate a human-readable summary for display.

        Args:
            technique_name: Optional technique name for example command.
            config: Optional config dict for example command.
        """
        import json as json_module  # Local import to avoid circular dependency

        lines = ["[DRY-RUN] Planned actions:"]
        for action in self.actions:
            lines.append(f"  - {action}")
        lines.append(f"Estimated API calls: {self.estimated_api_calls}")
        lines.append(f"Regions: {', '.join(self.regions)}")
        lines.append(f"Required permissions: {', '.join(self.required_permissions)}")
        if self.warnings:
            lines.append("Warnings:")
            for warning in self.warnings:
                lines.append(f"  - {warning}")

        # Add example execution command
        if technique_name:
            lines.append("")
            lines.append("To execute, run:")
            if config:
                config_str = json_module.dumps(config)
                lines.append(
                    f"  python -m cloak.cli --technique {technique_name} --config '{config_str}' --execute"
                )
            else:
                lines.append(f"  python -m cloak.cli --technique {technique_name} --execute")

        return "\n".join(lines)


@dataclass
class ExecutionResult:
    """Result of a technique execution.

    Contains summary information safe for display in Claude context.
    Full results are stored in the database.
    """

    execution_id: str
    success: bool
    summary: str
    asset_count: int = 0
    finding_count: int = 0
    duration_seconds: float = 0.0
    error_message: str | None = None

    def to_dict(self, web_ui_port: int = 8080) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Args:
            web_ui_port: Port the web UI runs on, for generating deep links.
        """
        result: dict[str, Any] = {
            "execution_id": self.execution_id,
            "success": self.success,
            "summary": self.summary,
            "asset_count": self.asset_count,
            "finding_count": self.finding_count,
            "duration_seconds": round(self.duration_seconds, 2),
            "error_message": self.error_message,
            "web_ui_url": (f"http://localhost:{web_ui_port}/#/executions/{self.execution_id}"),
        }
        return result

    @classmethod
    def from_error(cls, execution_id: str, error_message: str) -> ExecutionResult:
        """Create an ExecutionResult representing a failure."""
        return cls(
            execution_id=execution_id,
            success=False,
            summary=f"Execution failed: {error_message}",
            error_message=error_message,
        )


class BaseTechnique(ABC):
    """Abstract base class for all enumeration techniques.

    Techniques must implement:
    - metadata: Technique metadata for discovery
    - validate(): Validate configuration
    - dry_run(): Show planned actions
    - execute(): Perform the enumeration
    - summarize(): Generate safe summary
    """

    def __init__(
        self,
        config: TechniqueConfig,
        session: Session,
        aws_connection: AWSConnection | None = None,
    ):
        """Initialize the technique.

        Args:
            config: Technique configuration.
            session: Database session for storing results.
            aws_connection: Optional AWS connection (created if not provided).
        """
        self.config = config
        self.session = session
        self.aws_connection = aws_connection or AWSConnection()
        self.execution_id = config.execution_id or str(uuid.uuid4())
        self.logger = TechniqueLogger(config.technique_name, self.execution_id)
        self._connection_info: ConnectionInfo | None = None

    @property
    @abstractmethod
    def metadata(self) -> TechniqueMetadata:
        """Get technique metadata.

        Returns:
            TechniqueMetadata describing this technique.
        """
        pass

    @abstractmethod
    def validate(self) -> ValidationResult:
        """Validate technique configuration.

        Check that all required parameters are present and valid.

        Returns:
            ValidationResult indicating if configuration is valid.
        """
        pass

    @abstractmethod
    def dry_run(self) -> DryRunResult:
        """Show planned actions without execution.

        Returns:
            DryRunResult describing what would be done.
        """
        pass

    @abstractmethod
    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
        """Implementation of the technique execution.

        Subclasses implement this to perform the actual enumeration.
        Called by execute() after validation and setup.

        Returns:
            Tuple of (assets, findings) discovered.
        """
        pass

    @abstractmethod
    def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
        """Generate a safe summary of results.

        The summary should NOT contain sensitive data like resource names,
        ARNs, or any identifying information. It should only contain
        aggregate counts and general observations.

        Args:
            assets: List of discovered assets.
            findings: List of security findings.

        Returns:
            Human-readable summary safe for AI context.
        """
        pass

    def get_client(self, service_name: str, region_name: str | None = None) -> Any:
        """Get a boto3 client for the specified service.

        Args:
            service_name: AWS service name.
            region_name: Optional region override.

        Returns:
            boto3 service client.
        """
        return self.aws_connection.get_client(service_name, region_name)

    def get_regions(self) -> list[str]:
        """Get the list of regions to enumerate.

        Returns config regions if specified, otherwise default regions.

        Returns:
            List of AWS region names.
        """
        if self.config.regions:
            return self.config.regions
        return self.aws_connection.config.aws_regions

    def validate_connection(self) -> ConnectionInfo:
        """Validate AWS connection and cache the result.

        Returns:
            ConnectionInfo with identity details.

        Raises:
            RuntimeError: If connection is not valid.
        """
        if self._connection_info is None:
            self._connection_info = self.aws_connection.require_valid_connection()
        return self._connection_info

    def create_execution_record(self) -> Execution:
        """Create and persist an execution record.

        Returns:
            Execution record for this technique run.
        """
        connection_info = self.validate_connection()

        execution = Execution(
            id=self.execution_id,
            technique_name=self.config.technique_name,
            service=self.config.service,
            status=ExecutionStatus.PENDING.value,
            aws_account_id=connection_info.account_id,
            aws_identity_arn=connection_info.arn,
            config_json=self.config.model_dump_json(),
        )

        self.session.add(execution)
        self.session.commit()

        return execution

    def execute(self) -> ExecutionResult:
        """Execute the technique and store results.

        This is the main entry point for running a technique.
        It handles:
        1. Validation
        2. Connection validation
        3. Execution record creation
        4. Calling the implementation
        5. Storing results in database
        6. Generating summary

        Returns:
            ExecutionResult with summary and counts.
        """
        # Validate configuration
        validation = self.validate()
        if not validation.valid:
            return ExecutionResult.from_error(
                self.execution_id,
                f"Validation failed: {'; '.join(validation.errors)}",
            )

        # Create execution record
        try:
            execution = self.create_execution_record()
        except RuntimeError as e:
            return ExecutionResult.from_error(self.execution_id, str(e))

        # Mark as running
        execution.mark_running()
        self.session.commit()

        self.logger.execution_started(self.config.parameters)
        start_time = time.time()

        try:
            # Execute the technique implementation
            assets, findings = self._execute_impl()

            # Store assets
            for asset in assets:
                asset.execution_id = self.execution_id
                self.session.add(asset)

            # Store findings
            for finding in findings:
                finding.execution_id = self.execution_id
                self.session.add(finding)

            self.session.commit()

            # Generate summary
            summary = self.summarize(assets, findings)
            duration = time.time() - start_time

            # Mark execution complete
            execution.mark_completed(
                summary=summary,
                finding_count=len(findings),
                asset_count=len(assets),
            )
            self.session.commit()

            self.logger.execution_completed(
                asset_count=len(assets),
                finding_count=len(findings),
                duration_seconds=duration,
            )

            return ExecutionResult(
                execution_id=self.execution_id,
                success=True,
                summary=summary,
                asset_count=len(assets),
                finding_count=len(findings),
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            error_message = str(e)

            # Create sanitized summary for failed executions
            # Truncate long errors and remove sensitive data (ARNs, account IDs, etc.)
            sanitized_error = sanitize_text(error_message[:200])
            summary = f"Execution failed: {sanitized_error}"

            # Mark execution failed with sanitized summary
            execution.mark_failed(error_message, summary=summary)
            self.session.commit()

            self.logger.execution_failed(error_message)

            return ExecutionResult(
                execution_id=self.execution_id,
                success=False,
                summary=summary,
                duration_seconds=duration,
                error_message=error_message,
            )

    def run(self) -> ExecutionResult | DryRunResult:
        """Run the technique in either dry-run or execute mode.

        Convenience method that checks config.dry_run and calls
        the appropriate method.

        Returns:
            DryRunResult if dry_run is True, ExecutionResult otherwise.
        """
        if self.config.dry_run:
            return self.dry_run()
        return self.execute()
