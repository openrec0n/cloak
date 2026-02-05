"""Configuration management for CLOAK."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class CloakSettings(BaseSettings):
    """Environment-based settings for CLOAK.

    Settings can be configured via environment variables with CLOAK_ prefix.
    Example: CLOAK_DATABASE_PATH=/custom/path/cloak.db
    """

    model_config = SettingsConfigDict(
        env_prefix="CLOAK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database settings
    database_path: str = "data/cloak.db"

    # Logging settings
    log_directory: str = "data/logs"
    log_level: str = "INFO"
    log_format: str = "json"  # json or text

    # AWS settings
    aws_profile: str | None = None
    aws_default_region: str = "us-east-1"

    # Execution settings
    dry_run_default: bool = True
    max_api_calls_per_technique: int = 1000

    # Output settings
    summary_max_items: int = 10


@dataclass
class CloakConfig:
    """Runtime configuration for CLOAK.

    Combines settings from environment, config files, and runtime overrides.
    """

    # Database settings
    database_path: Path = field(default_factory=lambda: Path("data/cloak.db"))

    # Logging settings
    log_directory: Path = field(default_factory=lambda: Path("data/logs"))
    log_level: str = "INFO"
    log_format: str = "json"

    # AWS settings
    aws_profile: str | None = None
    aws_regions: list[str] = field(default_factory=lambda: ["us-east-1"])

    # Execution settings
    dry_run_default: bool = True
    max_api_calls_per_technique: int = 1000

    # Output settings
    summary_max_items: int = 10

    @classmethod
    def from_settings(cls, settings: CloakSettings | None = None) -> CloakConfig:
        """Create config from environment settings."""
        if settings is None:
            settings = CloakSettings()

        return cls(
            database_path=Path(settings.database_path),
            log_directory=Path(settings.log_directory),
            log_level=settings.log_level,
            log_format=settings.log_format,
            aws_profile=settings.aws_profile,
            aws_regions=[settings.aws_default_region],
            dry_run_default=settings.dry_run_default,
            max_api_calls_per_technique=settings.max_api_calls_per_technique,
            summary_max_items=settings.summary_max_items,
        )

    @classmethod
    def default(cls) -> CloakConfig:
        """Create default configuration."""
        return cls.from_settings()

    def ensure_directories(self) -> None:
        """Ensure required directories exist."""
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_directory.mkdir(parents=True, exist_ok=True)


class TechniqueConfig(BaseModel):
    """Configuration for a specific technique execution.

    This is passed to techniques when they are executed, containing
    all parameters needed for the operation.
    """

    technique_name: str = Field(..., description="Full technique name (e.g., 's3.list_buckets')")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Technique-specific parameters"
    )
    dry_run: bool = Field(
        default=True, description="If True, show planned actions without execution"
    )
    regions: list[str] | None = Field(
        default=None, description="AWS regions to target (None = use default)"
    )
    execution_id: str | None = Field(default=None, description="Optional execution ID for tracking")

    @property
    def service(self) -> str:
        """Extract service name from technique name."""
        return self.technique_name.split(".")[0]

    @property
    def technique(self) -> str:
        """Extract technique name without service prefix."""
        parts = self.technique_name.split(".", 1)
        return parts[1] if len(parts) > 1 else parts[0]


class ParameterSpec(BaseModel):
    """Specification for a technique parameter.

    Used to document and validate technique parameters.
    """

    name: str = Field(..., description="Parameter name")
    param_type: str = Field(..., description="Parameter type (str, int, bool, list)")
    required: bool = Field(default=False, description="Whether parameter is required")
    default: Any = Field(default=None, description="Default value if not provided")
    description: str = Field(default="", description="Human-readable description")
    choices: list[Any] | None = Field(
        default=None, description="Valid choices for enum-like parameters"
    )


# Global config instance (lazily initialized)
_config: CloakConfig | None = None


def get_config() -> CloakConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = CloakConfig.default()
    return _config


def set_config(config: CloakConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
