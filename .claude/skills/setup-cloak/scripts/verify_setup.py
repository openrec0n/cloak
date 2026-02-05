#!/usr/bin/env python3
"""Verify CLOAK setup status.

Outputs JSON with the status of each setup component.
Run from the project root directory.
"""

import configparser
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def _parse_aws_credentials_file(filepath: Path) -> list[str]:
    """Parse AWS credentials file and return list of valid profile names.

    A valid profile must have both aws_access_key_id and aws_secret_access_key
    with actual non-empty values (not just the keys present).
    """
    config = configparser.ConfigParser()
    try:
        config.read(filepath)
    except configparser.Error:
        return []

    valid_profiles = []
    for section in config.sections():
        access_key = config.get(section, "aws_access_key_id", fallback="").strip()
        secret_key = config.get(section, "aws_secret_access_key", fallback="").strip()
        if access_key and secret_key:
            valid_profiles.append(section)
    return valid_profiles


def get_python_status() -> dict:
    """Check Python version."""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"
    meets_requirement = version >= (3, 11)
    return {
        "installed": True,
        "version": version_str,
        "meets_requirement": meets_requirement,
        "message": "OK" if meets_requirement else "Python 3.11+ required",
    }


def get_poetry_status() -> dict:
    """Check Poetry installation."""
    poetry_path = shutil.which("poetry")
    if not poetry_path:
        return {
            "installed": False,
            "version": None,
            "message": "Poetry not found in PATH",
        }

    try:
        result = subprocess.run(
            ["poetry", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # Output format: "Poetry (version 1.8.0)"
        version = result.stdout.strip().split()[-1].rstrip(")")
        return {
            "installed": True,
            "version": version,
            "message": "OK",
        }
    except Exception as e:
        return {
            "installed": False,
            "version": None,
            "message": f"Error checking Poetry: {e}",
        }


def get_dependencies_status() -> dict:
    """Check if dependencies are installed via Poetry.

    Verifies:
    1. poetry.lock exists
    2. Poetry virtual environment exists
    3. Core dependencies (boto3) are actually importable in the venv
    4. Whether the script is running inside the Poetry venv
    """
    # Check if poetry.lock exists
    if not Path("poetry.lock").exists():
        return {
            "installed": False,
            "message": "poetry.lock not found - run 'poetry install'",
        }

    # Check if virtual environment exists
    try:
        result = subprocess.run(
            ["poetry", "env", "info", "--path"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {
                "installed": False,
                "message": "Virtual environment not found - run 'poetry install'",
            }

        venv_path = Path(result.stdout.strip())
        if not venv_path.exists():
            return {
                "installed": False,
                "message": "Virtual environment not found - run 'poetry install'",
            }

        # Check if currently running inside the Poetry venv
        running_in_venv = sys.executable.startswith(str(venv_path))

        # Verify boto3 is importable in the venv (using poetry run)
        boto3_check = subprocess.run(
            ["poetry", "run", "python", "-c", "import boto3"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        boto3_available = boto3_check.returncode == 0

        if not boto3_available:
            return {
                "installed": False,
                "venv_path": str(venv_path),
                "running_in_venv": running_in_venv,
                "message": "Virtual environment exists but dependencies not installed - run 'poetry install'",
            }

        return {
            "installed": True,
            "venv_path": str(venv_path),
            "running_in_venv": running_in_venv,
            "message": "OK",
        }

    except FileNotFoundError:
        return {
            "installed": False,
            "message": "Poetry not available to check dependencies",
        }
    except subprocess.TimeoutExpired:
        return {
            "installed": False,
            "message": "Timeout checking dependencies",
        }
    except Exception as e:
        return {
            "installed": False,
            "message": f"Error checking dependencies: {e}",
        }


def get_aws_credentials_status() -> dict:
    """Check if AWS credentials are configured."""
    # Check environment variables
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return {
            "configured": True,
            "method": "environment_variables",
            "message": "OK - using environment variables",
        }

    # Check AWS_PROFILE
    if os.environ.get("AWS_PROFILE"):
        profile = os.environ.get("AWS_PROFILE")
        return {
            "configured": True,
            "method": "profile",
            "profile": profile,
            "message": f"OK - using profile '{profile}'",
        }

    # Check default credentials file (must have at least one profile with non-empty keys)
    aws_creds_file = Path.home() / ".aws" / "credentials"

    if aws_creds_file.exists():
        valid_profiles = _parse_aws_credentials_file(aws_creds_file)
        if valid_profiles:
            profiles_msg = ", ".join(valid_profiles)
            return {
                "configured": True,
                "method": "credentials_file",
                "profiles": valid_profiles,
                "message": f"OK - using ~/.aws/credentials (profiles: {profiles_msg})",
            }
        return {
            "configured": False,
            "method": "credentials_file",
            "message": "~/.aws/credentials exists but contains no valid credential profiles (need aws_access_key_id and aws_secret_access_key with non-empty values)",
        }

    return {
        "configured": False,
        "method": None,
        "message": "No AWS credentials found",
    }


def get_aws_connection_status() -> dict:
    """Validate AWS connection using the CLOAK CLI.

    Uses 'poetry run' to ensure the CLI runs in the Poetry venv
    regardless of how this script was invoked.
    """
    try:
        result = subprocess.run(
            ["poetry", "run", "python", "-m", "cloak.cli", "--validate-connection"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            # Parse account info from output (format: "Connected to AWS account XXX...")
            output = result.stdout.strip()
            return {
                "valid": True,
                "message": output,
            }
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Connection failed"
            # Check for common boto3/dependency errors
            if "ModuleNotFoundError" in error_msg or "No module named" in error_msg:
                return {
                    "valid": False,
                    "message": "Cannot validate - dependencies not installed (run 'poetry install')",
                }
            return {
                "valid": False,
                "message": error_msg,
            }
    except FileNotFoundError:
        return {
            "valid": False,
            "message": "Cannot validate - Poetry not found in PATH",
        }
    except subprocess.TimeoutExpired:
        return {
            "valid": False,
            "message": "Connection validation timed out",
        }
    except Exception as e:
        return {
            "valid": False,
            "message": f"Error validating connection: {e}",
        }


def get_database_status() -> dict:
    """Check database directory status."""
    data_dir = Path("data")
    db_path = data_dir / "cloak.db"
    logs_dir = data_dir / "logs"

    return {
        "data_dir_exists": data_dir.exists(),
        "database_exists": db_path.exists(),
        "logs_dir_exists": logs_dir.exists(),
        "message": "OK" if data_dir.exists() else "Will be created on first run",
    }


def get_system_info() -> dict:
    """Get system information."""
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "in_project_root": Path("pyproject.toml").exists(),
    }


def main() -> None:
    """Run all checks and output JSON status."""
    status = {
        "system": get_system_info(),
        "python": get_python_status(),
        "poetry": get_poetry_status(),
        "dependencies": get_dependencies_status(),
        "aws_credentials": get_aws_credentials_status(),
        "aws_connection": get_aws_connection_status(),
        "database": get_database_status(),
    }

    # Calculate overall readiness
    ready = all([
        status["python"]["meets_requirement"],
        status["poetry"]["installed"],
        status["dependencies"]["installed"],
        status["aws_credentials"]["configured"],
        status["aws_connection"]["valid"],
    ])
    status["ready"] = ready

    print(json.dumps(status, indent=2))

    # Exit with appropriate code
    sys.exit(0 if ready else 1)


if __name__ == "__main__":
    main()
