#!/bin/bash
# validate-output.sh - PostToolUse hook for CLOAK
# Validates that command output contains no sensitive data
#
# This hook runs after every Bash tool use and:
# 1. Checks output for sensitive AWS patterns (ARNs, account IDs, etc.)
# 2. Logs execution IDs for audit trail
# 3. Warns if any sensitive data is detected (defense in depth)

set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)

# Validate JSON input - if invalid, allow through gracefully
if ! echo "$INPUT" | jq empty 2>/dev/null; then
    echo "Invalid JSON input, allowing through" >&2
    exit 0
fi

# Extract the tool response (command output)
TOOL_RESPONSE=$(echo "$INPUT" | jq -r '.tool_response // ""')
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')

# If no response or not a CLOAK command, skip validation
if [ -z "$TOOL_RESPONSE" ]; then
    exit 0
fi

# Only do deep validation for CLOAK commands
if [[ "$COMMAND" != *"cloak"* ]] && [[ "$COMMAND" != *"cloak.cli"* ]]; then
    exit 0
fi

# ============================================================
# Sensitive Data Patterns (mirrors cloak/output/sanitizers.py)
# ============================================================

# Function to check for sensitive patterns
check_sensitive_patterns() {
    local text="$1"
    local violations=""
    
    # ARN pattern: arn:aws:service:region:account:resource
    if echo "$text" | grep -qE 'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[a-zA-Z0-9/_-]+'; then
        violations="${violations}ARN detected; "
    fi
    
    # AWS Account ID (12 digits, not preceded by dash)
    if echo "$text" | grep -qE '(^|[^-])[0-9]{12}([^0-9]|$)'; then
        # Exclude common false positives like timestamps, execution IDs
        ACCOUNT_MATCHES=$(echo "$text" | grep -oE '(^|[^-])[0-9]{12}([^0-9]|$)' | grep -vE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)
        if [ -n "$ACCOUNT_MATCHES" ]; then
            violations="${violations}Account ID detected; "
        fi
    fi
    
    # Access Key IDs
    if echo "$text" | grep -qE '(AKIA|ASIA)[0-9A-Z]{16}'; then
        violations="${violations}Access Key detected; "
    fi
    
    # S3 bucket ARN or URL patterns (both .s3. URLs and s3:// URIs)
    if echo "$text" | grep -qE '[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\.'; then
        violations="${violations}S3 bucket URL detected; "
    fi

    # S3 URI pattern (s3://bucket-name)
    if echo "$text" | grep -qE 's3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]'; then
        violations="${violations}S3 URI detected; "
    fi
    
    # EC2/VPC resource IDs
    if echo "$text" | grep -qE '\b(i|sg|vpc|subnet|vol|snap|ami|eni|igw|rtb|acl|natgw|eip)-[a-f0-9]{8,17}\b'; then
        violations="${violations}EC2/VPC resource ID detected; "
    fi
    
    # IAM resource paths
    if echo "$text" | grep -qE '(user|role|group|policy)/[a-zA-Z0-9+=,.@_-]+'; then
        # Only flag if it looks like an actual IAM path, not documentation
        if echo "$text" | grep -qE 'arn:aws:iam::[0-9]{12}:(user|role|group|policy)/'; then
            violations="${violations}IAM resource path detected; "
        fi
    fi
    
    # Private IP addresses (less strict - only flag in certain contexts)
    # Skip this check as it has too many false positives
    
    echo "$violations"
}

# ============================================================
# Main Validation
# ============================================================

VIOLATIONS=$(check_sensitive_patterns "$TOOL_RESPONSE")

if [ -n "$VIOLATIONS" ]; then
    # Log the violation for audit
    echo "[CLOAK HOOK WARNING] Potential sensitive data in output: $VIOLATIONS" >&2
    
    # Return additional context to Claude warning about the potential leak
    # Note: PostToolUse cannot block (tool already ran), but can add context
    jq -n \
        --arg violations "$VIOLATIONS" \
        '{
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": ("WARNING: Output may contain sensitive AWS data that should not be repeated in conversation: " + $violations + "Do not include specific resource identifiers in your response. Reference execution IDs instead for users to fetch details locally.")
            }
        }'
    exit 0
fi

# ============================================================
# Extract and Log Execution IDs for Audit Trail
# ============================================================

# Look for execution IDs in the output (CLOAK format)
EXECUTION_ID=$(echo "$TOOL_RESPONSE" | grep -oE '"execution_id":\s*"[a-f0-9-]+"' | head -1 | sed 's/.*"\([a-f0-9-]*\)".*/\1/' || true)

if [ -n "$EXECUTION_ID" ]; then
    # Log execution for audit trail
    AUDIT_DIR="${CLAUDE_PROJECT_DIR:-$(pwd)}/data/logs"
    mkdir -p "$AUDIT_DIR" 2>/dev/null || true
    
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "$TIMESTAMP | execution_id=$EXECUTION_ID | command=$COMMAND" >> "$AUDIT_DIR/hook-audit.log" 2>/dev/null || true
fi

# No issues - allow output to pass through
exit 0
