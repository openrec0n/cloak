"""Tests for technique registry generation and compression."""

import json
import tempfile
from pathlib import Path

from cloak.core.config import ParameterSpec
from cloak.core.registry import (
    _compress_param,
    _expand_technique,
    generate_technique_registry,
    get_technique_info,
    list_techniques_by_service,
    load_registry,
    validate_registry,
    write_registry,
)


class TestCompressParam:
    """Test parameter compression."""

    def test_compress_param_minimal(self):
        """Test compression of minimal parameter (no choices, no default)."""
        param = ParameterSpec(
            name="test_param",
            param_type="str",
            required=True,
            description="Test parameter description",
        )

        compressed = _compress_param(param)

        assert compressed == {
            "n": "test_param",
            "t": "s",  # str → s
            "d": "Test parameter description",
        }
        # No 'c' key because choices is None
        assert "c" not in compressed
        # No 'df' key because no default
        assert "df" not in compressed

    def test_compress_param_with_choices(self):
        """Test compression of parameter with choices."""
        param = ParameterSpec(
            name="scope",
            param_type="str",
            required=True,
            description="Scope parameter",
            choices=["Local", "AWS", "All"],
        )

        compressed = _compress_param(param)

        assert compressed["c"] == ["Local", "AWS", "All"]

    def test_compress_param_with_default(self):
        """Test compression of optional parameter with default."""
        param = ParameterSpec(
            name="limit",
            param_type="int",
            required=False,
            default=100,
            description="Limit parameter",
        )

        compressed = _compress_param(param)

        assert compressed["t"] == "i"  # int → i
        assert compressed["df"] == 100

    def test_compress_param_type_abbreviations(self):
        """Test that all type abbreviations work correctly."""
        type_map = {
            "str": "s",
            "int": "i",
            "bool": "b",
            "list": "l",
        }

        for full_type, abbrev in type_map.items():
            param = ParameterSpec(
                name="test",
                param_type=full_type,
                required=True,
                description="Test",
            )
            compressed = _compress_param(param)
            assert compressed["t"] == abbrev


class TestExpandTechnique:
    """Test technique expansion from compressed format."""

    def test_expand_technique_minimal(self):
        """Test expansion of minimal technique (no parameters)."""
        compressed = {
            "id": "s3.list_buckets",
            "d": "List all S3 buckets",
            "p": ["s3:ListAllMyBuckets", "s3:GetBucketLocation"],
        }

        expanded = _expand_technique(compressed)

        assert expanded["id"] == "s3.list_buckets"
        assert expanded["name"] == "list_buckets"
        assert expanded["service"] == "s3"
        assert expanded["description"] == "List all S3 buckets"
        assert expanded["permissions"] == ["s3:ListAllMyBuckets", "s3:GetBucketLocation"]
        assert expanded["required_params"] == []
        assert expanded["optional_params"] == []

    def test_expand_technique_with_required_params(self):
        """Test expansion of technique with required parameters."""
        compressed = {
            "id": "iam.list_policies",
            "d": "List IAM policies",
            "p": ["iam:ListPolicies"],
            "rp": [
                {
                    "n": "scope",
                    "t": "s",
                    "d": "Policy scope",
                    "c": ["Local", "AWS", "All"],
                }
            ],
        }

        expanded = _expand_technique(compressed)

        assert len(expanded["required_params"]) == 1
        param = expanded["required_params"][0]
        assert param["name"] == "scope"
        assert param["type"] == "str"  # s → str
        assert param["description"] == "Policy scope"
        assert param["choices"] == ["Local", "AWS", "All"]

    def test_expand_technique_with_optional_params(self):
        """Test expansion of technique with optional parameters."""
        compressed = {
            "id": "s3.list_objects",
            "d": "List objects in bucket",
            "p": ["s3:ListBucket"],
            "op": [
                {
                    "n": "max_keys",
                    "t": "i",
                    "d": "Maximum number of keys",
                    "df": 1000,
                }
            ],
        }

        expanded = _expand_technique(compressed)

        assert len(expanded["optional_params"]) == 1
        param = expanded["optional_params"][0]
        assert param["name"] == "max_keys"
        assert param["type"] == "int"  # i → int
        assert param["default"] == 1000

    def test_expand_technique_type_abbreviations(self):
        """Test that all type abbreviations are correctly reversed."""
        type_map_reverse = {
            "s": "str",
            "i": "int",
            "b": "bool",
            "l": "list",
        }

        for abbrev, full_type in type_map_reverse.items():
            compressed = {
                "id": "test.technique",
                "d": "Test",
                "p": [],
                "rp": [{"n": "param", "t": abbrev, "d": "Test param"}],
            }
            expanded = _expand_technique(compressed)
            assert expanded["required_params"][0]["type"] == full_type


class TestRegistryRoundTrip:
    """Test compression and expansion round-trip."""

    def test_round_trip_preserves_structure(self):
        """Test that compress → expand round-trip preserves structure."""
        # Generate compressed registry
        registry = generate_technique_registry()

        # Should be in compressed format
        assert len(registry["techniques"]) > 0
        first_tech = registry["techniques"][0]
        assert "d" in first_tech  # compressed description
        assert "p" in first_tech  # compressed permissions
        assert "description" not in first_tech
        assert "permissions" not in first_tech

        # Expand
        expanded = _expand_technique(first_tech)

        # Should have full structure
        assert "name" in expanded
        assert "service" in expanded
        assert "description" in expanded
        assert "permissions" in expanded
        assert "required_params" in expanded
        assert "optional_params" in expanded


class TestRegistryGeneration:
    """Test registry generation."""

    def test_generate_technique_registry_structure(self):
        """Test that registry has correct structure."""
        registry = generate_technique_registry()

        # Top-level structure
        assert "version" in registry
        assert "generated_at" in registry
        assert "services" in registry
        assert "techniques" in registry

        # Services should be a sorted list
        assert isinstance(registry["services"], list)
        assert registry["services"] == sorted(registry["services"])

        # Techniques should be a list
        assert isinstance(registry["techniques"], list)

    def test_generate_technique_registry_compressed_format(self):
        """Test that registry is generated in compressed format."""
        registry = generate_technique_registry()

        # Verify compressed field names in techniques
        for technique in registry["techniques"]:
            assert "d" in technique  # description
            assert "p" in technique  # permissions
            assert "description" not in technique
            assert "permissions" not in technique
            assert "name" not in technique
            assert "service" not in technique

    def test_generate_technique_registry_omits_empty(self):
        """Test that empty params are omitted from compressed format."""
        registry = generate_technique_registry()

        # Find a technique with no required params
        for technique in registry["techniques"]:
            if technique["id"] == "s3.list_buckets":
                # Should not have 'rp' or 'op' keys
                assert "rp" not in technique or technique["rp"] == []
                assert "op" not in technique or technique["op"] == []
                break


class TestRegistryIO:
    """Test registry reading and writing."""

    def test_write_registry_compact_format(self):
        """Test that registry is written in compact format."""
        registry = generate_technique_registry()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            write_registry(registry, temp_path)

            # Read raw file to verify it's compact
            with open(temp_path) as f:
                content = f.read()

            # Compact format should have no indentation
            assert "\n  " not in content or content.count("\n  ") < 5
            # Should use compact separators
            assert ",{" in content or ',"' in content
        finally:
            Path(temp_path).unlink()

    def test_load_registry_expands_automatically(self):
        """Test that load_registry() returns expanded format."""
        # Generate and write compressed registry
        registry = generate_technique_registry()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            write_registry(registry, temp_path)

            # Load should return expanded format
            loaded = load_registry(temp_path)

            # Verify expanded fields exist
            assert len(loaded["techniques"]) > 0
            for technique in loaded["techniques"]:
                assert "name" in technique
                assert "service" in technique
                assert "description" in technique
                assert "permissions" in technique
                assert "required_params" in technique
                assert "optional_params" in technique
        finally:
            Path(temp_path).unlink()


class TestRegistrySizeCompliance:
    """Test that registry meets token budget."""

    def test_registry_size_within_budget(self):
        """Test that compressed registry meets token budget."""
        registry = generate_technique_registry()

        # Write to temporary file to measure size
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            write_registry(registry, temp_path)

            # Check file size
            file_size = Path(temp_path).stat().st_size
            estimated_tokens = file_size / 4  # Conservative estimate

            # With 12 techniques, should be under 650 tokens
            assert (
                estimated_tokens < 650
            ), f"Registry too large: {estimated_tokens} tokens (expected <650)"

            # Projected for 20 techniques (linear scaling)
            num_techniques = len(registry["techniques"])
            if num_techniques > 0:
                projected_20 = (estimated_tokens / num_techniques) * 20
                assert (
                    projected_20 < 1100
                ), f"Projected for 20 techniques: {projected_20} tokens (expected <1100)"
        finally:
            Path(temp_path).unlink()

    def test_compression_achieves_reduction(self):
        """Test that compression actually reduces size vs verbose format."""
        registry = generate_technique_registry()

        # Write compressed
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            compressed_path = f.name
        write_registry(registry, compressed_path)

        # Write verbose (manually reconstruct to compare)
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            verbose_path = f.name

        try:
            # Expand all techniques and write with pretty formatting
            expanded_techniques = [_expand_technique(t) for t in registry["techniques"]]
            verbose_registry = {
                "version": registry["version"],
                "generated_at": registry["generated_at"],
                "services": registry["services"],
                "techniques": expanded_techniques,
            }
            with open(verbose_path, "w") as f:
                json.dump(verbose_registry, f, indent=2)

            compressed_size = Path(compressed_path).stat().st_size
            verbose_size = Path(verbose_path).stat().st_size

            # Compressed should be smaller
            reduction_percent = ((verbose_size - compressed_size) / verbose_size) * 100
            assert (
                compressed_size < verbose_size
            ), f"Compression failed: {compressed_size} >= {verbose_size}"
            assert (
                reduction_percent > 30
            ), f"Insufficient compression: only {reduction_percent:.1f}% reduction"

        finally:
            Path(compressed_path).unlink()
            Path(verbose_path).unlink()


class TestRegistryValidation:
    """Test registry validation."""

    def test_validate_registry_valid(self):
        """Test validation of valid registry."""
        # Generate compressed registry, write, and load (which expands it)
        registry = generate_technique_registry()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            write_registry(registry, temp_path)
            loaded = load_registry(temp_path)

            # Validate the expanded registry
            is_valid, errors = validate_registry(loaded)
            assert is_valid, f"Validation errors: {errors}"
            assert len(errors) == 0
        finally:
            Path(temp_path).unlink()

    def test_validate_registry_missing_field(self):
        """Test validation catches missing fields."""
        registry = {"version": "1.0.0"}
        is_valid, errors = validate_registry(registry)
        assert not is_valid
        assert len(errors) > 0


class TestRegistryQueries:
    """Test registry query functions."""

    def test_get_technique_info(self):
        """Test getting technique info."""
        registry = generate_technique_registry()

        # Should work with loaded (expanded) registry
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            write_registry(registry, temp_path)
            loaded = load_registry(temp_path)

            # Get info for a known technique
            if len(loaded["techniques"]) > 0:
                first_tech_id = loaded["techniques"][0]["id"]
                info = get_technique_info(first_tech_id, loaded)
                assert info is not None
                assert info["id"] == first_tech_id
        finally:
            Path(temp_path).unlink()

    def test_list_techniques_by_service(self):
        """Test listing techniques by service."""
        registry = generate_technique_registry()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            write_registry(registry, temp_path)
            loaded = load_registry(temp_path)

            # List S3 techniques
            s3_techniques = list_techniques_by_service("s3", loaded)
            assert isinstance(s3_techniques, list)
            for tech in s3_techniques:
                assert tech["service"] == "s3"
        finally:
            Path(temp_path).unlink()


class TestBackwardCompatibility:
    """Test backward compatibility with CLI."""

    def test_expanded_registry_structure(self):
        """Test that expanded registry has expected structure for CLI."""
        registry = generate_technique_registry()

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            temp_path = f.name

        try:
            write_registry(registry, temp_path)
            loaded = load_registry(temp_path)

            # Verify structure matches what CLI expects
            for tech in loaded["techniques"]:
                # Must have all these fields
                assert "id" in tech
                assert "name" in tech
                assert "service" in tech
                assert "description" in tech
                assert "permissions" in tech
                assert "required_params" in tech
                assert "optional_params" in tech

                # Permissions must be list
                assert isinstance(tech["permissions"], list)

                # Params must be lists
                assert isinstance(tech["required_params"], list)
                assert isinstance(tech["optional_params"], list)

                # Each param must have expected structure
                for param in tech["required_params"] + tech["optional_params"]:
                    assert "name" in param
                    assert "type" in param
                    assert "description" in param
                    # choices is optional but if present must be correct type
                    if "choices" in param and param["choices"] is not None:
                        assert isinstance(param["choices"], list)
        finally:
            Path(temp_path).unlink()
