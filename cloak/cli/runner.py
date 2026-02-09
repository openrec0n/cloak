"""CLI runner for executing CLOAK techniques."""

import argparse
import contextlib
import json
import sys
import urllib.error
import urllib.request
from typing import Any

from cloak.core.aws_connection import validate_aws_connection
from cloak.core.config import CloakConfig, TechniqueConfig, get_config
from cloak.core.database import (
    get_execution_by_id,
    get_recent_executions,
    init_database,
    session_scope,
)
from cloak.core.logging import setup_logging
from cloak.core.registry import (
    generate_technique_registry,
    load_registry,
    write_registry,
)
from cloak.output.formatters import format_dry_run_output, format_json_output, format_text_output
from cloak.output.sanitizers import validate_summary


def load_technique_class(technique_name: str) -> type[Any]:
    """Dynamically load technique class by name.

    Args:
        technique_name: Full technique name (e.g., "s3.list_buckets")

    Returns:
        Technique class

    Raises:
        ValueError: If technique not found or service not implemented
    """
    parts = technique_name.split(".")
    if len(parts) != 2:
        raise ValueError(
            f"Invalid technique name: {technique_name}. Expected format: service.technique"
        )

    service, technique = parts

    # Map public service names to internal module names
    # (lambda is a Python reserved keyword, so module is lambda_)
    SERVICE_MODULE_MAP = {
        "lambda": "lambda_",
    }
    module_service = SERVICE_MODULE_MAP.get(service, service)

    # Import service module dynamically
    try:
        if module_service == "s3":
            from cloak.techniques.s3 import TECHNIQUES
        elif module_service == "iam":
            from cloak.techniques.iam import TECHNIQUES
        elif module_service == "ec2":
            from cloak.techniques.ec2 import TECHNIQUES
        elif module_service == "lambda_":
            from cloak.techniques.lambda_ import TECHNIQUES
        else:
            available_services = ["s3", "iam", "ec2", "lambda"]
            raise ValueError(
                f"Unknown service '{service}'\n\n"
                f"Available services: {', '.join(available_services)}\n\n"
                f"Hint: Use --list-services to see all services"
            )
    except ImportError as e:
        raise ValueError(f"Service '{service}' not implemented yet: {e}") from e

    # Get technique class from registry
    if technique not in TECHNIQUES:
        available = ", ".join(TECHNIQUES.keys())
        raise ValueError(
            f"Unknown technique '{technique}' for service '{service}'. Available: {available}"
        )

    return TECHNIQUES[technique]


def validate_connection() -> int:
    """Validate AWS connection.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        connection_info = validate_aws_connection()
        print(connection_info.to_summary())
        return 0
    except RuntimeError as e:
        print(f"AWS connection validation failed: {e}", file=sys.stderr)
        return 1


def run_technique(
    technique_name: str,
    config_json: str | None,
    dry_run: bool,
    output_format: str,
    open_ui: bool = False,
    port: int = 8080,
) -> int:
    """Run a technique.

    Args:
        technique_name: Full technique name (e.g., "s3.list_buckets")
        config_json: Optional JSON config string
        dry_run: If True, show planned actions without executing
        output_format: Output format (json or text)
        open_ui: If True, open Web UI to execution detail after execution
        port: Web UI port for deep links

    Returns:
        Exit code (0 success, 1 validation error, 2 execution error)
    """
    try:
        # Parse config
        parameters = {}
        if config_json:
            try:
                parameters = json.loads(config_json)
            except json.JSONDecodeError as e:
                print(f"Invalid JSON config: {e}", file=sys.stderr)
                return 1

        # Create technique config
        technique_config = TechniqueConfig(
            technique_name=technique_name,
            parameters=parameters,
            dry_run=dry_run,
        )

        # Load technique class
        technique_class = load_technique_class(technique_name)

        # Initialize database (for execution only)
        cloak_config = CloakConfig.default()
        cloak_config.ensure_directories()

        # Emit agent status to Web UI
        _emit_agent_event(
            port,
            {
                "type": "technique_start",
                "technique": technique_name,
                "dry_run": dry_run,
            },
        )

        # Execute technique
        if dry_run:
            # Dry-run mode - no database needed
            technique = technique_class(technique_config, None)
            result = technique.dry_run()
            print(
                format_dry_run_output(
                    result, technique_name=technique_name, config=parameters or None
                )
            )
            _emit_agent_event(
                port,
                {"type": "technique_complete", "technique": technique_name, "dry_run": True},
            )
            return 0
        else:
            # Real execution - initialize database
            init_database(cloak_config)

            with session_scope(cloak_config) as session:
                technique = technique_class(technique_config, session)
                result = technique.execute()

                # Validate summary for sensitive data
                is_safe, violations = validate_summary(result.summary)
                if not is_safe:
                    print(
                        f"WARNING: Summary contains sensitive data: {violations}", file=sys.stderr
                    )

                # Format output
                if output_format == "json":
                    print(format_json_output(result, web_ui_port=port))
                else:
                    print(format_text_output(result, web_ui_port=port))

                # Emit completion to Web UI
                _emit_agent_event(
                    port,
                    {
                        "type": "technique_complete",
                        "technique": technique_name,
                        "dry_run": False,
                        "execution_id": result.execution_id,
                        "success": result.success,
                        "asset_count": result.asset_count,
                        "finding_count": result.finding_count,
                    },
                )

                # Open Web UI to execution detail if requested
                if open_ui and result.success:
                    open_web_ui_to_execution(result.execution_id, port)

                return 0 if result.success else 2

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        _emit_agent_event(
            port,
            {"type": "technique_failed", "technique": technique_name, "error": str(e)},
        )
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback

        _emit_agent_event(
            port,
            {
                "type": "technique_failed",
                "technique": technique_name,
                "error": str(e),
            },
        )
        traceback.print_exc()
        return 2


def list_services(output_format: str = "text") -> int:
    """List available AWS services.

    Args:
        output_format: Output format (json or text)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        registry = load_registry()
        services = registry["services"]

        if output_format == "json":
            print(json.dumps({"services": services}, indent=2))
        else:
            print("Available services:")
            for service in services:
                # Count techniques per service
                count = len([t for t in registry["techniques"] if t["service"] == service])
                print(f"  {service}: {count} technique(s)")
        return 0
    except Exception as e:
        print(f"Error loading registry: {e}", file=sys.stderr)
        return 1


def list_techniques(
    service: str | None = None, output_format: str = "text", brief: bool = False
) -> int:
    """List available techniques, optionally filtered by service.

    Args:
        service: Optional service name to filter by
        output_format: Output format (json or text)
        brief: If True, show only id and description (reduces token usage)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        registry = load_registry()

        if service:
            techniques = [t for t in registry["techniques"] if t["service"] == service]
            if not techniques:
                available_services = registry["services"]
                print(
                    f"No techniques found for service: {service}\n\n"
                    f"Available services: {', '.join(available_services)}\n\n"
                    f"Hint: Use --list-services to see all services",
                    file=sys.stderr,
                )
                return 1
        else:
            techniques = registry["techniques"]

        if output_format == "json":
            if brief:
                # Output only id and description for each technique (reduces token usage)
                brief_techniques = [
                    {"id": t["id"], "description": t["description"]} for t in techniques
                ]
                print(json.dumps({"techniques": brief_techniques}, indent=2))
            else:
                print(json.dumps({"techniques": techniques}, indent=2))
        else:
            if service:
                print(f"Techniques for {service}:")
            else:
                print("Available techniques:")
            print()
            for tech in techniques:
                print(f"  {tech['id']}")
                print(f"    {tech['description']}")
                if not brief:
                    print(f"    Permissions: {', '.join(tech['permissions'])}")
                print()
        return 0
    except Exception as e:
        print(f"Error loading registry: {e}", file=sys.stderr)
        return 1


def technique_info(technique_name: str, output_format: str = "text") -> int:
    """Show detailed information about a technique.

    Args:
        technique_name: Full technique name (e.g., "s3.list_buckets")
        output_format: Output format (json or text)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        registry = load_registry()
        technique = next((t for t in registry["techniques"] if t["id"] == technique_name), None)

        if not technique:
            # Build helpful error message with available techniques
            service_name = technique_name.split(".")[0] if "." in technique_name else None
            service_techniques = [
                t["id"] for t in registry["techniques"] if t["service"] == service_name
            ]

            error_msg = f"Error: Unknown technique '{technique_name}'"
            if service_techniques:
                error_msg += f"\n\nAvailable {service_name} techniques:\n"
                error_msg += "\n".join(f"  - {t}" for t in service_techniques)
            error_msg += "\n\nHint: Use --list-techniques to see all techniques"

            print(error_msg, file=sys.stderr)
            return 1

        if output_format == "json":
            print(json.dumps(technique, indent=2))
        else:
            print(f"Technique: {technique['id']}")
            print(f"Service: {technique['service']}")
            print(f"Description: {technique['description']}")
            print()
            print("Permissions Required:")
            for perm in technique["permissions"]:
                print(f"  - {perm}")
            print()
            if technique["required_params"]:
                print("Required Parameters:")
                for param in technique["required_params"]:
                    print(f"  - {param['name']} ({param['type']}): {param['description']}")
                print()
            if technique["optional_params"]:
                print("Optional Parameters:")
                for param in technique["optional_params"]:
                    default_str = f", default: {param['default']}" if "default" in param else ""
                    print(
                        f"  - {param['name']} ({param['type']}{default_str}): {param.get('description', '')}"
                    )
                print()
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def generate_registry_cmd() -> int:
    """Generate technique registry file.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        print("Generating technique registry...")
        registry = generate_technique_registry()

        # Write compressed registry (validation happens in tests)
        # The compressed format will be expanded automatically when loaded
        output_path = write_registry(registry)

        # Calculate file size and token estimate
        import os

        file_size = os.path.getsize(output_path)
        estimated_tokens = file_size / 4

        print(f"Registry written to: {output_path}")
        print(f"  Services: {len(registry['services'])}")
        print(f"  Techniques: {len(registry['techniques'])}")
        print(f"  File size: {file_size} bytes (~{estimated_tokens:.0f} tokens)")
        return 0
    except Exception as e:
        print(f"Error generating registry: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


def list_executions(limit: int = 10, output_format: str = "text") -> int:
    """List recent executions.

    Args:
        limit: Maximum number of executions to list
        output_format: Output format (json or text)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        cloak_config = CloakConfig.default()
        init_database(cloak_config)

        with session_scope(cloak_config) as session:
            executions = get_recent_executions(session, limit)

            if output_format == "json":
                data = [exec.to_dict() for exec in executions]
                print(json.dumps({"executions": data}, indent=2))
            else:
                if not executions:
                    print("No executions found in database.")
                    return 0

                print(f"Recent Executions (last {len(executions)}):\n")
                for exec in executions:
                    status_icon = "✓" if exec.status == "completed" else "✗"
                    print(f"{status_icon} ID {exec.id}: {exec.technique_name}")
                    print(f"   Started: {exec.started_at}")
                    print(f"   Account: {exec.aws_account_id}")
                    print(f"   Assets: {exec.asset_count}, Findings: {exec.finding_count}")
                    print()
            return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def execution_info(execution_id: str, output_format: str = "text") -> int:
    """Show detailed execution information.

    Args:
        execution_id: Execution ID to show (UUID string)
        output_format: Output format (json or text)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        cloak_config = CloakConfig.default()
        init_database(cloak_config)

        with session_scope(cloak_config) as session:
            execution = get_execution_by_id(session, execution_id)

            if not execution:
                print(f"Error: Execution {execution_id} not found", file=sys.stderr)
                return 1

            if output_format == "json":
                data = execution.to_dict()
                # Include assets and findings
                data["assets"] = [asset.to_dict() for asset in execution.assets]
                data["findings"] = [finding.to_dict() for finding in execution.findings]
                print(json.dumps(data, indent=2))
            else:
                print(f"Execution #{execution.id}")
                print(f"Technique: {execution.technique_name}")
                print(f"Service: {execution.service}")
                print(f"Status: {execution.status}")
                print(f"Started: {execution.started_at}")
                print(f"Completed: {execution.completed_at or 'N/A'}")
                print()
                print(f"AWS Account: {execution.aws_account_id}")
                print(f"AWS Identity: {execution.aws_identity_arn}")
                print()
                print(f"Assets Discovered: {execution.asset_count}")
                print(f"Findings Generated: {execution.finding_count}")
                print()
                print("Summary:")
                print(execution.summary)
            return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def interactive_config(technique_name: str) -> dict[str, Any]:
    """Interactively collect technique parameters.

    Args:
        technique_name: Full technique name

    Returns:
        Configuration dictionary

    Raises:
        ValueError: If technique not found
    """
    registry = load_registry()
    technique = next((t for t in registry["techniques"] if t["id"] == technique_name), None)

    if not technique:
        raise ValueError(f"Unknown technique: {technique_name}")

    config: dict[str, Any] = {}

    print(f"\nConfiguring {technique_name}")
    print(f"Description: {technique['description']}\n")

    # Prompt for required parameters
    if technique["required_params"]:
        print("Required parameters:")
        for param in technique["required_params"]:
            while True:
                value = input(f"  {param['name']} ({param['type']}) [required]: ")
                if not value:
                    print("    Error: This parameter is required.")
                    continue
                try:
                    config[param["name"]] = _convert_param_value(value, param["type"])
                    break
                except ValueError as e:
                    print(f"    Error: {e}. Please try again.")

    # Prompt for optional parameters
    if technique["optional_params"]:
        print("\nOptional parameters (press Enter to skip):")
        for param in technique["optional_params"]:
            default_str = f", default: {param.get('default', 'none')}"
            value = input(f"  {param['name']} ({param['type']}{default_str}): ")
            if value:
                try:
                    config[param["name"]] = _convert_param_value(value, param["type"])
                except ValueError as e:
                    print(f"    Error: {e}. Using default.")

    return config


def _convert_param_value(value: str, param_type: str) -> Any:
    """Convert parameter value to correct type.

    Args:
        value: String value from user input
        param_type: Expected parameter type

    Returns:
        Converted value

    Raises:
        ValueError: If conversion fails
    """
    if param_type == "string":
        return value
    elif param_type == "integer":
        return int(value)
    elif param_type == "boolean":
        return value.lower() in ["true", "yes", "1", "y"]
    elif param_type == "array":
        return [s.strip() for s in value.split(",")]
    else:
        raise ValueError(f"Unsupported parameter type: {param_type}")


def _emit_agent_event(port: int, event: dict[str, Any]) -> None:
    """Emit agent event to Web UI (fire-and-forget).

    Posts the event directly without a health check first.
    If the server isn't running, the POST will fail silently.
    """
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/agent-events",
            data=json.dumps(event).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as _:
            pass
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        pass  # Ignore - Web UI may not be running


def is_web_ui_running(port: int = 8080) -> bool:
    """Check if the CLOAK web UI server is running on the given port.

    Verifies the health endpoint to confirm it's actually a CLOAK server,
    not some other service occupying the port.

    Args:
        port: Port to check (default: 8080).

    Returns:
        True if CLOAK Web UI is responding on the port.
    """
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/health",
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return bool(data.get("service") == "cloak-web-ui")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return False


def launch_web_ui(port: int = 8080, background: bool = False) -> int:
    """Launch the CLOAK web UI server.

    Args:
        port: Port to listen on (default: 8080).
        background: If True, run server as a background daemon process.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    try:
        if is_web_ui_running(port):
            print(f"Web UI already running at http://localhost:{port}")
            return 0

        if background:
            return _launch_web_ui_background(port)
        else:
            return _launch_web_ui_foreground(port)
    except Exception as e:
        print(f"Error starting web UI: {e}", file=sys.stderr)
        return 1


def _launch_web_ui_foreground(port: int) -> int:
    """Launch web UI in foreground (blocking) mode.

    Args:
        port: Port to listen on.

    Returns:
        Exit code.
    """
    try:
        import webbrowser

        from cloak.web.server import run_server

        cloak_config = CloakConfig.default()
        cloak_config.ensure_directories()

        # Open browser after a short delay
        import threading

        def open_browser() -> None:
            import time

            time.sleep(1.0)
            webbrowser.open(f"http://localhost:{port}")

        threading.Thread(target=open_browser, daemon=True).start()

        run_server(config=cloak_config, port=port)
        return 0
    except KeyboardInterrupt:
        print("\nWeb UI server stopped.")
        return 0


def _launch_web_ui_background(port: int) -> int:
    """Launch web UI as a background daemon process.

    Args:
        port: Port to listen on.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    import os
    import subprocess
    import time

    # Build the command to run the web server
    cmd = [
        sys.executable,
        "-m",
        "cloak.web.server",
        "--port",
        str(port),
    ]

    # Launch as a detached subprocess
    pid_file = os.path.join("data", ".web_ui.pid")
    os.makedirs("data", exist_ok=True)

    # Start the subprocess, detached from the parent
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    # Write PID file with port so we can find it later
    with open(pid_file, "w") as f:
        json.dump({"pid": process.pid, "port": port}, f)

    # Wait briefly and verify it started
    time.sleep(1.0)
    if is_web_ui_running(port):
        print(f"  CLOAK Web UI running in background at http://localhost:{port}")
        print(f"  PID: {process.pid}")
        return 0
    else:
        print("Error: Web UI failed to start in background", file=sys.stderr)
        return 1


def get_background_web_ui_port() -> int | None:
    """Read the port of a background Web UI process from the PID file.

    Returns:
        The port number if a PID file exists and is valid, None otherwise.
    """
    import os

    pid_file = os.path.join("data", ".web_ui.pid")
    if not os.path.exists(pid_file):
        return None
    try:
        with open(pid_file) as f:
            content = f.read().strip()
        # Support both JSON format (new) and plain PID format (legacy)
        try:
            data = json.loads(content)
            return int(data.get("port", 8080))
        except json.JSONDecodeError:
            # Legacy format: just a PID number, assume default port
            return 8080
    except OSError:
        return None


def stop_web_ui() -> int:
    """Stop a background CLOAK Web UI process.

    Reads the PID file, sends SIGTERM, and cleans up the PID file.
    Supports both JSON format (new: {"pid": ..., "port": ...}) and
    plain PID format (legacy: just a number).

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    import os
    import signal

    pid_file = os.path.join("data", ".web_ui.pid")

    if not os.path.exists(pid_file):
        print("No background Web UI process found (no PID file).")
        return 0

    try:
        with open(pid_file) as f:
            content = f.read().strip()
        # Support both JSON format (new) and plain PID format (legacy)
        try:
            data = json.loads(content)
            pid = data["pid"]
        except (json.JSONDecodeError, KeyError):
            pid = int(content)
    except (ValueError, OSError) as e:
        print(f"Error reading PID file: {e}", file=sys.stderr)
        os.remove(pid_file)
        return 1

    # Check if process is still running
    try:
        os.kill(pid, 0)  # Signal 0 = check if process exists
    except OSError:
        print(f"  Web UI process (PID {pid}) is not running. Cleaning up stale PID file.")
        os.remove(pid_file)
        return 0

    # Send SIGTERM for graceful shutdown
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"  Stopped Web UI background process (PID {pid}).")
    except OSError as e:
        print(f"Error stopping process {pid}: {e}", file=sys.stderr)
        return 1
    finally:
        with contextlib.suppress(OSError):
            os.remove(pid_file)

    return 0


def open_web_ui_to_execution(execution_id: str, port: int = 8080) -> None:
    """Open the web UI browser to a specific execution detail page.

    If the Web UI server is not running, prints the URL for the user
    to visit later (does not open the browser to avoid a confusing
    connection-refused page).

    Args:
        execution_id: The execution ID to navigate to.
        port: Port the web UI is running on.
    """
    import webbrowser

    url = f"http://localhost:{port}/#/executions/{execution_id}"

    if not is_web_ui_running(port):
        print(
            f"\n  Note: Web UI is not running on port {port}."
            f"\n  Start it with: cloak --web-ui --port {port}"
            f"\n  Then visit: {url}\n"
        )
        return

    webbrowser.open(url)


def main() -> int:
    """Main CLI entry point."""
    setup_logging(get_config())

    parser = argparse.ArgumentParser(
        description="CLOAK - Cloud Security AI Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discovery
  cloak --list-services
  cloak --list-techniques s3
  cloak --technique-info s3.list_buckets

  # Validate AWS connection
  cloak --validate-connection

  # Execute techniques
  cloak --technique s3.list_buckets  # Dry-run (default)
  cloak --technique s3.list_buckets --execute
  cloak --technique s3.list_buckets --interactive --execute

  # Execution history
  cloak --list-executions --limit 20
  cloak --execution-info 42

  # Web UI
  cloak --web-ui
  cloak --web-ui --port 9090
  cloak --web-ui --background

  # Execute and open Web UI to results
  cloak --technique s3.list_buckets --execute --open-ui

  # Registry management
  cloak --generate-registry
        """,
    )

    parser.add_argument(
        "--validate-connection",
        action="store_true",
        help="Validate AWS connection and display identity",
    )

    parser.add_argument("--technique", type=str, help="Technique to run (e.g., s3.list_buckets)")

    parser.add_argument("--config", type=str, help="Technique configuration as JSON string")

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show planned actions without executing (enabled by default unless --execute is used)",
    )

    parser.add_argument(
        "--execute", action="store_true", help="Actually execute technique (disables dry-run)"
    )

    parser.add_argument(
        "--output",
        type=str,
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )

    # Discovery commands
    parser.add_argument("--list-services", action="store_true", help="List available AWS services")

    parser.add_argument(
        "--list-techniques",
        type=str,
        nargs="?",
        const="__all__",
        metavar="SERVICE",
        help="List available techniques (optionally filter by service)",
    )

    parser.add_argument(
        "--brief",
        action="store_true",
        help="Show brief technique list (name and description only, reduces token usage)",
    )

    parser.add_argument(
        "--technique-info",
        type=str,
        metavar="TECHNIQUE",
        help="Show detailed technique information",
    )

    # Interactive mode
    parser.add_argument(
        "--interactive", action="store_true", help="Interactively collect technique parameters"
    )

    # Execution history
    parser.add_argument(
        "--list-executions", action="store_true", help="List recent technique executions"
    )

    parser.add_argument(
        "--limit", type=int, default=10, help="Limit number of results (default: 10)"
    )

    parser.add_argument(
        "--execution-info",
        type=str,
        metavar="ID",
        help="Show detailed execution information (UUID)",
    )

    # Web UI
    parser.add_argument(
        "--web-ui",
        action="store_true",
        help="Launch the CLOAK web UI in a browser",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for web UI server (default: 8080)",
    )

    parser.add_argument(
        "--background",
        action="store_true",
        help="Run web UI server as a background daemon process",
    )

    parser.add_argument(
        "--open-ui",
        action="store_true",
        help="After technique execution, open the Web UI to the execution detail page",
    )

    parser.add_argument(
        "--stop-web-ui",
        action="store_true",
        help="Stop a background Web UI process",
    )

    # Registry management
    parser.add_argument(
        "--generate-registry", action="store_true", help="Generate technique registry file"
    )

    args = parser.parse_args()

    # Handle discovery commands
    if args.list_services:
        return list_services(args.output)

    if args.list_techniques:
        service = None if args.list_techniques == "__all__" else args.list_techniques
        return list_techniques(service, args.output, args.brief)

    if args.technique_info:
        return technique_info(args.technique_info, args.output)

    # Handle web UI
    if args.stop_web_ui:
        return stop_web_ui()

    if args.web_ui:
        return launch_web_ui(args.port, background=args.background)

    # Handle execution history commands
    if args.list_executions:
        return list_executions(args.limit, args.output)

    if args.execution_info is not None:
        return execution_info(args.execution_info, args.output)

    # Handle registry generation
    if args.generate_registry:
        return generate_registry_cmd()

    # Validate connection
    if args.validate_connection:
        return validate_connection()

    # Technique execution requires --technique
    if not args.technique:
        parser.print_help()
        print("\nError: --technique is required for execution", file=sys.stderr)
        return 1

    # Interactive mode: collect parameters
    if args.interactive:
        try:
            config = interactive_config(args.technique)
            config_json = json.dumps(config)
        except (ValueError, KeyboardInterrupt) as e:
            if isinstance(e, KeyboardInterrupt):
                print("\nInteractive configuration cancelled.")
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1
    else:
        config_json = args.config

    # Determine dry-run mode: default is dry-run unless --execute is specified
    dry_run = not args.execute

    return run_technique(
        technique_name=args.technique,
        config_json=config_json,
        dry_run=dry_run,
        output_format=args.output,
        open_ui=args.open_ui,
        port=args.port,
    )


if __name__ == "__main__":
    sys.exit(main())
