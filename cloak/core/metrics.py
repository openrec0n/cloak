"""Token usage tracking and metrics for context optimization."""

import structlog

logger = structlog.get_logger(__name__)


def estimate_tokens(text: str) -> int:
    """Estimate token count using rough heuristic.

    This uses a simple approximation of ~4 characters per token, which is
    conservative for English text. Actual token counts may vary based on
    the specific tokenizer used by Claude.

    Args:
        text: The text to estimate tokens for

    Returns:
        Estimated token count
    """
    return len(text) // 4


def log_token_usage(source: str, text: str) -> int:
    """Log token usage for analysis.

    Args:
        source: Description of the text source (e.g., "registry", "summary")
        text: The text to measure

    Returns:
        Estimated token count
    """
    token_count = estimate_tokens(text)
    logger.info(
        "token_usage",
        source=source,
        tokens=token_count,
        chars=len(text),
    )
    return token_count


def measure_file_tokens(file_path: str, source_label: str | None = None) -> int:
    """Measure token count for a file.

    Args:
        file_path: Path to the file to measure
        source_label: Optional label for logging. If None, uses filename.

    Returns:
        Estimated token count
    """
    with open(file_path) as f:
        content = f.read()

    label = source_label or file_path
    return log_token_usage(label, content)


def get_token_summary(measurements: dict[str, int]) -> dict[str, int | float]:
    """Calculate summary statistics from token measurements.

    Args:
        measurements: Dictionary mapping source labels to token counts

    Returns:
        Dictionary with summary statistics
    """
    if not measurements:
        return {
            "total": 0,
            "count": 0,
            "average": 0.0,
            "min": 0,
            "max": 0,
        }

    counts = list(measurements.values())
    return {
        "total": sum(counts),
        "count": len(counts),
        "average": sum(counts) / len(counts),
        "min": min(counts),
        "max": max(counts),
    }
