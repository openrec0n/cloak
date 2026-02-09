#!/bin/bash
# session-context.sh - SessionStart hook for CLOAK
# Injects AWS connection status and recent execution context into Claude's context
#
# This hook runs at session start (startup/resume) and provides:
# 1. AWS connection validation status
# 2. Recent CLOAK execution history
# 3. Reminders about CLOAK's core rules

set -euo pipefail

# Read JSON input from stdin (contains session_id, cwd, source, etc.)
INPUT=$(cat)

# Validate JSON input - if invalid, continue with defaults
if ! echo "$INPUT" | jq empty 2>/dev/null; then
    echo "Warning: Invalid JSON input, using defaults" >&2
    SOURCE="startup"
else
    # Extract session source (startup, resume, clear, compact)
    SOURCE=$(echo "$INPUT" | jq -r '.source // "startup"')
fi

# Get project directory
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}"
CLOAK_DB="$PROJECT_DIR/data/cloak.db"

# Function to validate Python/Poetry environment
# This prevents AI agents from wasting turns discovering the correct command prefix
validate_environment() {
    # Check if poetry is available
    if ! command -v poetry &> /dev/null; then
        echo "Environment: Poetry not found"
        echo "  Install: curl -sSL https://install.python-poetry.org | python3 -"
        echo "  Command Prefix: N/A (install poetry first)"
        return 1
    fi
    
    # Check if .venv exists
    if [ ! -d "$PROJECT_DIR/.venv" ]; then
        echo "Environment: Virtual environment not found"
        echo "  Run: poetry install"
        echo "  Command Prefix: poetry run python"
        return 1
    fi
    
    # Check if dependencies are installed by trying to import boto3
    if ! (cd "$PROJECT_DIR" && poetry run python -c "import boto3" 2>/dev/null); then
        echo "Environment: Dependencies not installed"
        echo "  Run: poetry install"
        echo "  Command Prefix: poetry run python"
        return 1
    fi
    
    echo "Environment: Ready"
    echo "  Command Prefix: poetry run python"
    return 0
}

# Function to validate AWS connection
validate_aws() {
    # Try to get caller identity - this validates credentials
    if command -v aws &> /dev/null; then
        AWS_IDENTITY=$(aws sts get-caller-identity 2>/dev/null) || true
        if [ -n "$AWS_IDENTITY" ]; then
            ACCOUNT=$(echo "$AWS_IDENTITY" | jq -r '.Account')
            ARN=$(echo "$AWS_IDENTITY" | jq -r '.Arn')
            
            # Extract identity type and name from ARN
            if [[ "$ARN" == *":user/"* ]]; then
                IDENTITY_TYPE="user"
                IDENTITY_NAME=$(echo "$ARN" | sed 's/.*:user\///')
            elif [[ "$ARN" == *":assumed-role/"* ]]; then
                IDENTITY_TYPE="assumed-role"
                IDENTITY_NAME=$(echo "$ARN" | sed 's/.*:assumed-role\///' | cut -d'/' -f1)
            elif [[ "$ARN" == *":root"* ]]; then
                IDENTITY_TYPE="root"
                IDENTITY_NAME="root"
            else
                IDENTITY_TYPE="unknown"
                IDENTITY_NAME="unknown"
            fi
            
            echo "AWS Connection: Valid - Account $ACCOUNT, $IDENTITY_TYPE: $IDENTITY_NAME"
            return 0
        fi
    fi
    
    # Also try using CLOAK's validate-connection
    if [ -f "$PROJECT_DIR/pyproject.toml" ]; then
        CLOAK_RESULT=$(cd "$PROJECT_DIR" && poetry run python -m cloak.cli --validate-connection 2>/dev/null) || true
        if [ -n "$CLOAK_RESULT" ] && [[ "$CLOAK_RESULT" != *"failed"* ]]; then
            echo "AWS Connection: $CLOAK_RESULT"
            return 0
        fi
    fi
    
    echo "AWS Connection: Not configured or credentials expired. Run: poetry run python -m cloak.cli --validate-connection"
    # Return 0 anyway - this is informational, not blocking
    return 0
}

# Function to get recent executions from SQLite database
get_recent_executions() {
    if [ -f "$CLOAK_DB" ]; then
        # Query last 5 executions from the database
        RECENT=$(sqlite3 "$CLOAK_DB" "SELECT technique_name, status, datetime(started_at) FROM executions ORDER BY started_at DESC LIMIT 5" 2>/dev/null) || true
        if [ -n "$RECENT" ]; then
            echo "Recent CLOAK executions:"
            echo "$RECENT" | while IFS='|' read -r technique status timestamp; do
                STATUS_ICON="✓"
                [ "$status" != "COMPLETED" ] && STATUS_ICON="✗"
                echo "  $STATUS_ICON $technique ($timestamp)"
            done
        else
            echo "No recent CLOAK executions found."
        fi
    else
        echo "No execution history (database not initialized)."
    fi
}

# Function to detect if the Web UI server is running
detect_web_ui() {
    # Check common web UI ports
    for PORT in 8080 9090; do
        if command -v curl &> /dev/null; then
            if curl -s --max-time 1 "http://127.0.0.1:$PORT/api/stats" > /dev/null 2>&1; then
                echo "Web UI: Running at http://localhost:$PORT"
                echo "  Dashboard: http://localhost:$PORT/"
                echo "  Use deep links after executions: http://localhost:$PORT/#/executions/<id>"
                return 0
            fi
        elif command -v nc &> /dev/null; then
            if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
                echo "Web UI: Running at http://localhost:$PORT"
                echo "  Dashboard: http://localhost:$PORT/"
                echo "  Use deep links after executions: http://localhost:$PORT/#/executions/<id>"
                return 0
            fi
        fi
    done

    # Check PID file
    PID_FILE="$PROJECT_DIR/data/.web_ui.pid"
    if [ -f "$PID_FILE" ]; then
        WEB_PID=$(cat "$PID_FILE")
        if kill -0 "$WEB_PID" 2>/dev/null; then
            echo "Web UI: Background process running (PID $WEB_PID)"
            return 0
        else
            # Stale PID file
            rm -f "$PID_FILE"
        fi
    fi

    echo "Web UI: Not running"
    echo "  Launch: poetry run cloak --web-ui --background"
    echo "  The Web UI shows full sensitive data in the browser (outside AI context)"
    return 0
}

# Output context based on session source
echo "=== CLOAK Session Context ==="
echo ""

# Validate environment first - this tells AI agents the correct command prefix
validate_environment
echo ""

# Always validate AWS connection
validate_aws

echo ""

# Detect Web UI status
detect_web_ui

echo ""

# Show recent executions for context continuity
get_recent_executions

echo ""

# Remind about core rules
echo "Core Rules:"
echo "  - Dry-run by default: Always preview with --technique before using --execute"
echo "  - Privacy-first: Sensitive data stays in data/cloak.db, only summaries shown"
echo "  - Web UI preferred: Direct users to Web UI deep links for full details"
echo "  - Confirmation required: User must approve before any AWS API calls"
echo "  - Use --execution-info <id> as CLI fallback for sensitive details"

# Exit 0 to allow session to proceed - stdout becomes Claude's context
exit 0
