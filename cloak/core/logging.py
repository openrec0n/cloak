"""Structured logging configuration for CLOAK.

This module configures structlog to integrate with Python's stdlib logging,
enabling both console and file output while preserving sensitive data filtering.
"""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime
from typing import Any

import structlog
from structlog.types import EventDict, Processor

from cloak.core.config import CloakConfig, get_config


def add_timestamp(logger: logging.Logger, method_name: str, event_dict: EventDict) -> EventDict:
    """Add ISO format timestamp to log events."""
    event_dict["timestamp"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return event_dict


def filter_sensitive_data(
    logger: logging.Logger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Filter sensitive data from log events.

    Redacts credentials and AWS resource identifiers to prevent leakage.
    """
    # Import here to avoid circular dependency
    from cloak.output.sanitizers import sanitize_text

    sensitive_keys = {
        "access_key",
        "secret_key",
        "password",
        "token",
        "credentials",
        "aws_access_key_id",
        "aws_secret_access_key",
        "session_token",
    }

    # Additional keys that commonly contain resource identifiers
    resource_keys = {
        "bucket",
        "bucket_name",
        "resource_id",
        "resource_name",
        "arn",
        "instance_id",
        "security_group",
        "vpc_id",
        "subnet_id",
        "role_name",
        "user_name",
        "policy_name",
    }

    def redact_value(key: str, value: Any) -> Any:
        if isinstance(value, str):
            key_lower = key.lower()

            # Redact credential keys
            for sensitive in sensitive_keys:
                if sensitive in key_lower:
                    return "[REDACTED]"

            # Redact known resource identifier keys
            for resource_key in resource_keys:
                if resource_key in key_lower:
                    return "[REDACTED_RESOURCE]"

            # Apply pattern-based sanitization to catch any missed resource IDs
            sanitized = sanitize_text(value, replacement="[REDACTED_RESOURCE]")
            if sanitized != value:
                # Value was sanitized, return the sanitized version
                return sanitized

            # Redact AWS access key patterns (fallback)
            if value.startswith("AKIA") or value.startswith("ASIA"):
                return "[REDACTED_ACCESS_KEY]"

        elif isinstance(value, dict):
            return {k: redact_value(k, v) for k, v in value.items()}
        elif isinstance(value, list):
            return [redact_value(key, v) for v in value]

        return value

    for key in list(event_dict.keys()):
        event_dict[key] = redact_value(key, event_dict[key])

    return event_dict


def get_processors() -> list[Processor]:
    """Get the processor chain for structlog stdlib integration.

    These processors run before the log event is passed to stdlib logging.
    The final rendering (JSON or text) is handled by the ProcessorFormatter.

    Returns:
        List of structlog processors for pre-formatting.
    """
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        add_timestamp,
        filter_sensitive_data,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]


def get_formatter_processors(log_format: str = "json") -> list[Processor]:
    """Get the processor chain for the stdlib ProcessorFormatter.

    These processors run inside the logging formatter to render the final output.

    Args:
        log_format: Output format ('json' or 'text').

    Returns:
        List of structlog processors for final rendering.
    """
    renderer: structlog.processors.JSONRenderer | structlog.dev.ConsoleRenderer
    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    return [
        structlog.stdlib.ProcessorFormatter.remove_processors_meta,
        renderer,
    ]


def setup_logging(config: CloakConfig | None = None) -> None:
    """Configure structured logging for the application.

    Integrates structlog with Python's stdlib logging to enable both
    console and file output. All logs pass through the sensitive data
    filter before being written.

    Args:
        config: Optional configuration. Uses global config if not provided.
    """
    if config is None:
        config = get_config()

    # Ensure log directory exists
    config.ensure_directories()

    # Configure standard library logging
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)

    # Create the ProcessorFormatter that renders structlog events
    # This formatter is shared by all handlers
    formatter = structlog.stdlib.ProcessorFormatter(
        # Processors for logs originating from structlog
        processors=get_formatter_processors(config.log_format),
        # Processors for logs originating from stdlib (e.g., boto3, botocore)
        foreign_pre_chain=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            add_timestamp,
            filter_sensitive_data,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ],
    )

    # Console handler (always enabled)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    # File handler
    log_file = config.log_directory / f"cloak_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    # Configure root logger
    # Clear any existing handlers to avoid duplicates on re-initialization
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Configure structlog to use stdlib logging
    structlog.configure(
        processors=get_processors(),
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance.

    Args:
        name: Optional logger name. Uses 'cloak' as default.

    Returns:
        Configured structlog logger.
    """
    return structlog.get_logger(name or "cloak")  # type: ignore[no-any-return]


class TechniqueLogger:
    """Specialized logger for technique executions.

    Provides structured logging with execution context.
    """

    def __init__(self, technique_name: str, execution_id: str | None = None):
        """Initialize technique logger.

        Args:
            technique_name: Name of the technique being executed.
            execution_id: Optional execution ID for correlation.
        """
        self.logger = get_logger("technique")
        self.technique_name = technique_name
        self.execution_id = execution_id

    def _bind_context(self) -> structlog.stdlib.BoundLogger:
        """Bind common context to logger."""
        return self.logger.bind(
            technique=self.technique_name,
            execution_id=self.execution_id,
        )

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message with technique context."""
        self._bind_context().info(message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message with technique context."""
        self._bind_context().warning(message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message with technique context."""
        self._bind_context().error(message, **kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message with technique context."""
        self._bind_context().debug(message, **kwargs)

    def execution_started(self, config: dict[str, Any]) -> None:
        """Log execution start event."""
        self.info("Technique execution started", config=config)

    def execution_completed(
        self, asset_count: int, finding_count: int, duration_seconds: float
    ) -> None:
        """Log execution completion event."""
        self.info(
            "Technique execution completed",
            asset_count=asset_count,
            finding_count=finding_count,
            duration_seconds=round(duration_seconds, 2),
        )

    def execution_failed(self, error: str) -> None:
        """Log execution failure event."""
        self.error("Technique execution failed", error=error)

    def api_call(self, operation: str, **kwargs: Any) -> None:
        """Log AWS API call."""
        self.debug(f"AWS API call: {operation}", operation=operation, **kwargs)
