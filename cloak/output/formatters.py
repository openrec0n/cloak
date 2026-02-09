"""Output formatting utilities for CLOAK execution results."""

import json

from cloak.techniques.base import DryRunResult, ExecutionResult


def format_json_output(result: ExecutionResult, web_ui_port: int = 8080) -> str:
    """Format ExecutionResult as JSON.

    Args:
        result: Execution result to format
        web_ui_port: Port the Web UI runs on, for generating deep links (default: 8080)

    Returns:
        JSON string with all execution details

    Example:
        >>> result = ExecutionResult(...)
        >>> print(format_json_output(result))
        {
          "execution_id": "abc-123",
          "success": true,
          ...
        }
    """
    return json.dumps(result.to_dict(web_ui_port=web_ui_port), indent=2)


def format_text_output(result: ExecutionResult, web_ui_port: int = 8080) -> str:
    """Format ExecutionResult as human-readable text.

    Args:
        result: Execution result to format
        web_ui_port: Port the Web UI runs on, for generating deep links (default: 8080)

    Returns:
        Formatted text output

    Example:
        >>> result = ExecutionResult(...)
        >>> print(format_text_output(result))
        Execution ID: abc-123
        Status: completed
        ...
    """
    lines = []
    lines.append(f"Execution ID: {result.execution_id}")
    lines.append(f"Status: {'success' if result.success else 'failed'}")
    lines.append(f"Duration: {result.duration_seconds:.2f}s")
    lines.append("")

    if result.success:
        lines.append(f"Assets: {result.asset_count}")
        lines.append(f"Findings: {result.finding_count}")
        lines.append("")
        lines.append("Summary:")
        lines.append(result.summary)
        lines.append("")
        lines.append(
            f"View details: http://localhost:{web_ui_port}/#/executions/{result.execution_id}"
        )
    else:
        lines.append(f"Error: {result.error_message}")

    return "\n".join(lines)


def format_dry_run_output(
    result: DryRunResult, technique_name: str = "", config: dict | None = None
) -> str:
    """Format DryRunResult for display.

    Args:
        result: Dry-run result to format
        technique_name: Optional technique name for example command
        config: Optional config dict for example command

    Returns:
        Formatted text showing planned actions

    Example:
        >>> result = DryRunResult(...)
        >>> print(format_dry_run_output(result))
        Planned Actions:
          - Call s3:ListAllMyBuckets
        ...
    """
    return result.to_summary(technique_name=technique_name, config=config)
