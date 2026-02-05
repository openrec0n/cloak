#!/bin/bash
# approve-db-access.sh - PreToolUse hook for CLOAK
# Triggers human-in-the-loop approval for database access
#
# This hook runs before Bash commands and:
# 1. Detects --execution-info commands that fetch sensitive data
# 2. Returns permissionDecision: "ask" to trigger Claude Code UI approval
# 3. Shows the execution ID being accessed for user context

set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)

# Validate JSON input - if invalid, allow through gracefully
if ! echo "$INPUT" | jq empty 2>/dev/null; then
    echo "Invalid JSON input, allowing through" >&2
    exit 0
fi

# Extract the command being run
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

# If no command, allow it
if [ -z "$COMMAND" ]; then
    exit 0
fi

# ============================================================
# Check for database access commands
# ============================================================

# Detect --execution-info commands (fetches full sensitive data)
if [[ "$COMMAND" == *"--execution-info"* ]]; then
    # Extract execution ID for user context
    # Handles both --execution-info UUID and --execution-info=UUID formats
    EXEC_ID=""
    
    # Try space-separated format: --execution-info UUID
    if [[ "$COMMAND" =~ --execution-info[[:space:]]+([a-f0-9-]+) ]]; then
        EXEC_ID="${BASH_REMATCH[1]}"
    # Try equals format: --execution-info=UUID
    elif [[ "$COMMAND" =~ --execution-info=([a-f0-9-]+) ]]; then
        EXEC_ID="${BASH_REMATCH[1]}"
    fi
    
    # Build the approval reason message
    if [ -n "$EXEC_ID" ]; then
        REASON="Database access requested for execution $EXEC_ID. This will reveal sensitive AWS data (ARNs, bucket names, account IDs)."
    else
        REASON="Database access requested. This will reveal sensitive AWS data (ARNs, bucket names, account IDs)."
    fi
    
    # Return ask decision to trigger Claude Code UI approval dialog
    jq -n \
        --arg reason "$REASON" \
        '{
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": $reason
            }
        }'
    exit 0
fi

# ============================================================
# Not a database access command - allow through
# ============================================================

exit 0
