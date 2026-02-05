"""Technique registry generation for Claude Code optimization."""

import json
from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import Any

from cloak.core.config import ParameterSpec, get_config


def _compress_param(param: ParameterSpec) -> dict[str, Any]:
    """Compress a parameter spec to minimal JSON representation.

    Args:
        param: Parameter specification to compress

    Returns:
        Compressed parameter dict with abbreviated keys
    """
    # Map full type names to abbreviations
    type_map = {"str": "s", "int": "i", "bool": "b", "list": "l"}

    compressed: dict[str, Any] = {
        "n": param.name,
        "t": type_map.get(param.param_type, param.param_type),
        "d": param.description,
    }

    # Only include choices if not None
    if param.choices is not None:
        compressed["c"] = param.choices

    # Include default for optional parameters
    if hasattr(param, "default") and param.default is not None:
        compressed["df"] = param.default

    return compressed


def _expand_technique(compressed: dict[str, Any]) -> dict[str, Any]:
    """Expand compressed technique to verbose format for CLI consumption.

    Args:
        compressed: Compressed technique dict

    Returns:
        Expanded technique dict with full field names
    """
    # Extract service and name from id
    service, name = compressed["id"].split(".", 1)

    # Reverse type abbreviations
    type_map_reverse = {"s": "str", "i": "int", "b": "bool", "l": "list"}

    def expand_param(p: dict[str, Any]) -> dict[str, Any]:
        expanded = {
            "name": p["n"],
            "type": type_map_reverse.get(p["t"], p["t"]),
            "description": p["d"],
            "choices": p.get("c"),  # None if not present
        }
        # Include default if present
        if "df" in p:
            expanded["default"] = p["df"]
        return expanded

    return {
        "id": compressed["id"],
        "name": name,
        "service": service,
        "description": compressed["d"],
        "permissions": compressed["p"],
        "required_params": [expand_param(p) for p in compressed.get("rp", [])],
        "optional_params": [expand_param(p) for p in compressed.get("op", [])],
    }


def generate_technique_registry() -> dict[str, Any]:
    """Generate technique registry by introspecting technique classes.

    Returns a structured JSON containing all available techniques with their
    metadata. This enables programmatic discovery and reduces context window
    consumption.
    """
    # List of services to scan
    services = ["s3", "iam", "ec2", "lambda_", "sts"]

    techniques = []
    available_services = []

    for service in services:
        try:
            # Import the service module
            module = import_module(f"cloak.techniques.{service}")

            # Get the TECHNIQUES registry
            if not hasattr(module, "TECHNIQUES"):
                continue

            techniques_dict = module.TECHNIQUES
            if not techniques_dict:
                continue

            # Service has techniques, add to available list
            service_name = service.rstrip("_")  # lambda_ -> lambda
            available_services.append(service_name)

            # Extract metadata from each technique class
            for technique_name, technique_class in techniques_dict.items():
                # We need to get metadata without full initialization
                # Create a mock object that satisfies minimum requirements
                try:
                    # Create a minimal mock object with required attributes
                    class MockConfig:
                        def __init__(self, tech_name: str) -> None:
                            self.technique_name = tech_name
                            self.parameters: dict[str, Any] = {}
                            self.execution_id = "00000000-0000-0000-0000-000000000000"
                            self.dry_run = True

                    class MockSession:
                        pass

                    # Instantiate with mock objects
                    technique_instance = technique_class(
                        config=MockConfig(f"{service_name}.{technique_name}"),  # type: ignore
                        session=MockSession(),  # type: ignore
                    )

                    metadata = technique_instance.metadata
                except Exception as e:
                    print(
                        f"Warning: Could not extract metadata from {service_name}.{technique_name}: {e}"
                    )
                    continue

                # Build compressed technique entry
                technique_entry = {
                    "id": f"{service_name}.{technique_name}",
                    "d": metadata.description,  # Compressed: description → d
                    "p": metadata.required_permissions,  # Compressed: permissions → p
                }

                # Add required params only if non-empty (compressed format)
                if metadata.required_parameters:
                    technique_entry["rp"] = [
                        _compress_param(p) for p in metadata.required_parameters
                    ]

                # Add optional params only if non-empty (compressed format)
                if metadata.optional_parameters:
                    technique_entry["op"] = [
                        _compress_param(p) for p in metadata.optional_parameters
                    ]

                techniques.append(technique_entry)

        except ImportError:
            # Service module doesn't exist yet, skip
            continue
        except Exception as e:
            # Log but don't fail the entire generation
            print(f"Warning: Failed to load techniques from {service}: {e}")
            continue

    # Build registry
    registry = {
        "version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "services": sorted(available_services),
        "techniques": sorted(techniques, key=lambda t: t["id"]),
    }

    return registry


def write_registry(registry: dict[str, Any], output_path: str | None = None) -> str:
    """Write registry to JSON file in compact format.

    Args:
        registry: The registry dictionary to write (compressed format)
        output_path: Optional output path. If None, uses default location.

    Returns:
        Path where registry was written
    """
    if output_path is None:
        # Default location: .claude/skills/cloak-techniques.json
        get_config()
        project_root = Path(__file__).parent.parent.parent
        output_path = str(project_root / ".claude" / "skills" / "cloak-techniques.json")

    # Ensure directory exists
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write with compact formatting (no spaces/indents) for minimal size
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(registry, f, separators=(",", ":"), ensure_ascii=False)
        f.write("\n")  # Add trailing newline

    return str(output_file)


def load_registry(registry_path: str | None = None) -> dict[str, Any]:
    """Load and expand technique registry from JSON file.

    The registry is stored in compressed format on disk but expanded to
    verbose format at load time for backward compatibility with CLI code.

    Args:
        registry_path: Optional path to registry file. If None, uses default location.

    Returns:
        Registry dictionary in expanded (verbose) format

    Raises:
        FileNotFoundError: If registry file doesn't exist
        json.JSONDecodeError: If registry file is invalid JSON
    """
    if registry_path is None:
        # Default location
        project_root = Path(__file__).parent.parent.parent
        registry_path = str(project_root / ".claude" / "skills" / "cloak-techniques.json")

    with open(registry_path, encoding="utf-8") as f:
        compressed_registry = json.load(f)

    # Expand all techniques for backward compatibility with CLI
    expanded_techniques = [_expand_technique(t) for t in compressed_registry["techniques"]]

    return {
        "version": compressed_registry["version"],
        "generated_at": compressed_registry["generated_at"],
        "services": compressed_registry["services"],
        "techniques": expanded_techniques,
    }


def validate_registry(registry: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate registry structure.

    Args:
        registry: The registry dictionary to validate

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    # Check required top-level fields
    required_fields = ["version", "generated_at", "services", "techniques"]
    for field in required_fields:
        if field not in registry:
            errors.append(f"Missing required field: {field}")

    if errors:
        return False, errors

    # Validate services is a list
    if not isinstance(registry["services"], list):
        errors.append("'services' must be a list")

    # Validate techniques is a list
    if not isinstance(registry["techniques"], list):
        errors.append("'techniques' must be a list")

    if errors:
        return False, errors

    # Validate each technique
    required_technique_fields = ["id", "name", "service", "description", "permissions"]
    for i, technique in enumerate(registry["techniques"]):
        for field in required_technique_fields:
            if field not in technique:
                errors.append(f"Technique {i}: Missing required field '{field}'")

        # Validate id format
        if "id" in technique and "." not in technique["id"]:
            errors.append(f"Technique {i}: 'id' must be in format 'service.name'")

        # Validate permissions is a list
        if "permissions" in technique and not isinstance(technique["permissions"], list):
            errors.append(f"Technique {i}: 'permissions' must be a list")

    return len(errors) == 0, errors


def get_technique_info(
    technique_id: str, registry: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Get information about a specific technique.

    Args:
        technique_id: The technique ID (e.g., "s3.list_buckets")
        registry: Optional registry dict. If None, loads from default location.

    Returns:
        Technique information dict or None if not found
    """
    if registry is None:
        registry = load_registry()

    for technique in registry["techniques"]:
        if technique["id"] == technique_id:
            return dict(technique)  # Explicit dict to satisfy type checker

    return None


def list_techniques_by_service(
    service: str, registry: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """List all techniques for a specific service.

    Args:
        service: The service name (e.g., "s3")
        registry: Optional registry dict. If None, loads from default location.

    Returns:
        List of technique information dicts
    """
    if registry is None:
        registry = load_registry()

    return [t for t in registry["techniques"] if t["service"] == service]
