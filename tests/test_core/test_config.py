"""Tests for cloak.core.config module."""

from pathlib import Path

from cloak.core.config import (
    CloakConfig,
    CloakSettings,
    ParameterSpec,
    TechniqueConfig,
    get_config,
    set_config,
)


class TestCloakSettings:
    """Tests for CloakSettings environment-based configuration."""

    def test_default_values(self):
        """Test that default values are set correctly."""
        settings = CloakSettings()

        assert settings.database_path == "data/cloak.db"
        assert settings.log_directory == "data/logs"
        assert settings.log_level == "INFO"
        assert settings.log_format == "json"
        assert settings.aws_profile is None
        assert settings.aws_default_region == "us-east-1"
        assert settings.dry_run_default is True
        assert settings.max_api_calls_per_technique == 1000
        assert settings.summary_max_items == 10


class TestCloakConfig:
    """Tests for CloakConfig runtime configuration."""

    def test_default_config(self):
        """Test creating default configuration."""
        config = CloakConfig.default()

        assert config.database_path == Path("data/cloak.db")
        assert config.log_directory == Path("data/logs")
        assert config.log_level == "INFO"
        assert config.dry_run_default is True

    def test_from_settings(self):
        """Test creating config from settings."""
        settings = CloakSettings()
        config = CloakConfig.from_settings(settings)

        assert config.database_path == Path(settings.database_path)
        assert config.log_level == settings.log_level

    def test_ensure_directories(self, tmp_path: Path):
        """Test that ensure_directories creates required directories."""
        config = CloakConfig(
            database_path=tmp_path / "subdir" / "cloak.db",
            log_directory=tmp_path / "logs",
        )

        config.ensure_directories()

        assert (tmp_path / "subdir").exists()
        assert (tmp_path / "logs").exists()


class TestTechniqueConfig:
    """Tests for TechniqueConfig."""

    def test_basic_config(self):
        """Test creating basic technique configuration."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={"include_metadata": True},
        )

        assert config.technique_name == "s3.list_buckets"
        assert config.service == "s3"
        assert config.technique == "list_buckets"
        assert config.dry_run is True  # Default
        assert config.parameters["include_metadata"] is True

    def test_service_extraction(self):
        """Test service name extraction from technique name."""
        config = TechniqueConfig(technique_name="iam.list_users", parameters={})
        assert config.service == "iam"
        assert config.technique == "list_users"

    def test_single_part_technique_name(self):
        """Test technique name without service prefix."""
        config = TechniqueConfig(technique_name="simple_technique", parameters={})
        assert config.service == "simple_technique"
        assert config.technique == "simple_technique"

    def test_regions_override(self):
        """Test regions configuration."""
        config = TechniqueConfig(
            technique_name="ec2.describe_instances",
            parameters={},
            regions=["us-west-2", "eu-west-1"],
        )

        assert config.regions == ["us-west-2", "eu-west-1"]

    def test_dry_run_disabled(self):
        """Test explicitly disabling dry-run mode."""
        config = TechniqueConfig(
            technique_name="s3.list_buckets",
            parameters={},
            dry_run=False,
        )

        assert config.dry_run is False


class TestParameterSpec:
    """Tests for ParameterSpec."""

    def test_required_parameter(self):
        """Test creating a required parameter specification."""
        spec = ParameterSpec(
            name="bucket_name",
            param_type="str",
            required=True,
            description="Name of the S3 bucket",
        )

        assert spec.name == "bucket_name"
        assert spec.param_type == "str"
        assert spec.required is True
        assert spec.default is None

    def test_optional_parameter_with_default(self):
        """Test creating an optional parameter with default value."""
        spec = ParameterSpec(
            name="include_metadata",
            param_type="bool",
            required=False,
            default=False,
            description="Include additional metadata",
        )

        assert spec.required is False
        assert spec.default is False

    def test_parameter_with_choices(self):
        """Test parameter with enumerated choices."""
        spec = ParameterSpec(
            name="output_format",
            param_type="str",
            choices=["json", "csv", "text"],
            default="json",
        )

        assert spec.choices == ["json", "csv", "text"]


class TestGlobalConfig:
    """Tests for global configuration management."""

    def test_get_config_returns_default(self):
        """Test that get_config returns a default config."""
        # Reset global state
        import cloak.core.config as config_module

        config_module._config = None

        config = get_config()
        assert isinstance(config, CloakConfig)

    def test_set_config(self):
        """Test setting custom global configuration."""
        custom_config = CloakConfig(
            log_level="DEBUG",
            dry_run_default=False,
        )

        set_config(custom_config)
        retrieved = get_config()

        assert retrieved.log_level == "DEBUG"
        assert retrieved.dry_run_default is False
