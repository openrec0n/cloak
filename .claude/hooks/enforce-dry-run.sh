#!/bin/bash
# enforce-dry-run.sh - PreToolUse hook for CLOAK
# Enforces dry-run workflow and blocks dangerous commands
#
# This hook runs before every Bash tool use and:
# 1. Blocks CLOAK --execute commands that weren't preceded by a dry-run
# 2. Blocks dangerous AWS CLI commands (delete, terminate, etc.)
# 3. Provides clear feedback when blocking

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

# State file to track dry-run approvals (session-scoped via session_id)
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "default"')
STATE_DIR="${TMPDIR:-/tmp}/cloak-hooks"
STATE_FILE="$STATE_DIR/dryrun-$SESSION_ID"

mkdir -p "$STATE_DIR"

# Function to output JSON denial
deny_with_reason() {
    local reason="$1"
    jq -n \
        --arg reason "$reason" \
        '{
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": $reason
            }
        }'
    exit 0
}

# Function to record a dry-run for a technique
record_dryrun() {
    local technique="$1"
    echo "$technique" >> "$STATE_FILE"
}

# Function to check if dry-run was done for a technique
check_dryrun_done() {
    local technique="$1"
    if [ -f "$STATE_FILE" ]; then
        grep -q "^${technique}$" "$STATE_FILE" 2>/dev/null && return 0
    fi
    return 1
}

# ============================================================
# Check 1: Block dangerous AWS CLI commands
# ============================================================

# Patterns for dangerous AWS CLI commands
DANGEROUS_PATTERNS=(
    "aws s3 rm "
    "aws s3 rb "
    "aws s3api delete"
    "aws ec2 terminate-instances"
    "aws ec2 delete-"
    "aws iam delete-"
    "aws rds delete-"
    "aws lambda delete-"
    "aws cloudformation delete-"
    "aws dynamodb delete-table"
)

# Check for --force flag specifically with AWS commands
if [[ "$COMMAND" == *"aws "* ]] && [[ "$COMMAND" == *"--force"* ]]; then
    deny_with_reason "Blocked: Dangerous AWS command detected ('--force' flag). CLOAK is for security assessment only - destructive operations are not permitted."
fi

for pattern in "${DANGEROUS_PATTERNS[@]}"; do
    if [[ "$COMMAND" == *"$pattern"* ]]; then
        deny_with_reason "Blocked: Dangerous AWS command detected ('$pattern'). CLOAK is for security assessment only - destructive operations are not permitted."
    fi
done

# ============================================================
# Check 2: Enforce dry-run workflow for CLOAK CLI
# ============================================================

# Check if this is a CLOAK CLI command
if [[ "$COMMAND" == *"cloak.cli"* ]] || [[ "$COMMAND" == *"cloak"* && "$COMMAND" == *"--technique"* ]]; then
    
    # Extract technique name from command
    TECHNIQUE=""
    if [[ "$COMMAND" =~ --technique[[:space:]]+([a-z0-9_.]+) ]]; then
        TECHNIQUE="${BASH_REMATCH[1]}"
    elif [[ "$COMMAND" =~ --technique=([a-z0-9_.]+) ]]; then
        TECHNIQUE="${BASH_REMATCH[1]}"
    fi
    
    # Check if this is an --execute command
    if [[ "$COMMAND" == *"--execute"* ]]; then
        
        if [ -z "$TECHNIQUE" ]; then
            deny_with_reason "Cannot execute: Unable to determine technique name. Use format: --technique <service.technique> --execute"
        fi
        
        # Check if dry-run was done for this technique
        if ! check_dryrun_done "$TECHNIQUE"; then
            deny_with_reason "Blocked: Must run dry-run preview first before --execute. Run without --execute flag to see planned actions, then get user confirmation before executing."
        fi
        
        # Dry-run was done, allow the execute
        exit 0
        
    else
        # This is a dry-run command - record it for later
        if [ -n "$TECHNIQUE" ]; then
            record_dryrun "$TECHNIQUE"
        fi
        
        # Allow dry-run to proceed
        exit 0
    fi
fi

# ============================================================
# Check 3: Block direct boto3/AWS SDK calls that bypass CLOAK
# ============================================================

# These patterns suggest someone is trying to bypass CLOAK's safety controls
BYPASS_PATTERNS=(
    "boto3.client"
    "boto3.resource"
    "import boto3"
    "from boto3"
)

for pattern in "${BYPASS_PATTERNS[@]}"; do
    if [[ "$COMMAND" == *"$pattern"* ]]; then
        deny_with_reason "Blocked: Direct AWS SDK usage detected. Please use CLOAK techniques for AWS operations to ensure proper safety controls and audit logging."
    fi
done

# All checks passed - allow the command
exit 0
