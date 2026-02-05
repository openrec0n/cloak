#!/bin/bash
# filter-prompt.sh - UserPromptSubmit hook for CLOAK
# Filters user prompts for sensitive data before processing
#
# This hook runs when user submits a prompt and:
# 1. Blocks prompts containing AWS credentials (access keys, secret keys)
# 2. Warns about prompts containing ARNs or account IDs
# 3. Protects against accidental secret exposure in conversation

set -euo pipefail

# Read JSON input from stdin
INPUT=$(cat)

# Validate JSON input - if invalid, allow through gracefully
if ! echo "$INPUT" | jq empty 2>/dev/null; then
    echo "Invalid JSON input, allowing through" >&2
    exit 0
fi

# Extract the user's prompt
PROMPT=$(echo "$INPUT" | jq -r '.prompt // ""')

# If no prompt, allow it
if [ -z "$PROMPT" ]; then
    exit 0
fi

# Function to block prompt with reason
block_prompt() {
    local reason="$1"
    jq -n \
        --arg reason "$reason" \
        '{
            "decision": "block",
            "reason": $reason
        }'
    exit 0
}

# Function to add context warning (allow but warn)
warn_and_allow() {
    local warning="$1"
    jq -n \
        --arg warning "$warning" \
        '{
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": $warning
            }
        }'
    exit 0
}

# ============================================================
# Critical: Block AWS Credentials (Always Block)
# ============================================================

# AWS Access Key ID pattern (AKIA for permanent, ASIA for temporary)
if echo "$PROMPT" | grep -qE '(AKIA|ASIA)[0-9A-Z]{16}'; then
    block_prompt "BLOCKED: Your prompt contains what appears to be an AWS Access Key ID. Please remove the credential and try again. Never share AWS credentials in conversation."
fi

# AWS Secret Access Key pattern (40 character base64-ish string following common patterns)
# This is a heuristic - secret keys are 40 chars of [A-Za-z0-9+/]
if echo "$PROMPT" | grep -qE '[A-Za-z0-9+/]{40}'; then
    # Additional check: is it near "secret" or "key" or follows an access key?
    if echo "$PROMPT" | grep -qiE '(secret|aws_secret|secret_access_key|secretaccesskey)'; then
        block_prompt "BLOCKED: Your prompt may contain an AWS Secret Access Key. Please remove any credentials and try again. Never share AWS credentials in conversation."
    fi
fi

# AWS Session Token (temporary credentials)
if echo "$PROMPT" | grep -qiE 'aws_session_token|sessiontoken'; then
    if echo "$PROMPT" | grep -qE '[A-Za-z0-9+/=]{100,}'; then
        block_prompt "BLOCKED: Your prompt may contain an AWS Session Token. Please remove any credentials and try again."
    fi
fi

# ============================================================
# High Risk: Block Specific Resource Identifiers
# ============================================================

# Full ARNs with account IDs (these are sensitive identifiers)
if echo "$PROMPT" | grep -qE 'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[a-zA-Z0-9/_-]+'; then
    block_prompt "BLOCKED: Your prompt contains an AWS ARN with account information. CLOAK keeps sensitive identifiers local - please describe what you want to do instead of pasting ARNs. Use --execution-info <id> to review specific resources."
fi

# ============================================================
# Medium Risk: Warn about potentially sensitive data
# ============================================================

WARNINGS=""

# Standalone 12-digit numbers (potential account IDs)
if echo "$PROMPT" | grep -qE '\b[0-9]{12}\b'; then
    # Check it's not clearly a timestamp or other number
    POTENTIAL_ACCOUNT=$(echo "$PROMPT" | grep -oE '\b[0-9]{12}\b' | head -1)
    # Account IDs don't start with 0
    if [[ "$POTENTIAL_ACCOUNT" != 0* ]]; then
        WARNINGS="${WARNINGS}Note: Detected what might be an AWS Account ID. CLOAK keeps account IDs private - summaries will not include them. "
    fi
fi

# EC2/VPC resource IDs (less critical but still sensitive)
if echo "$PROMPT" | grep -qE '\b(i|sg|vpc|subnet|vol|snap|ami|eni)-[a-f0-9]{8,17}\b'; then
    WARNINGS="${WARNINGS}Note: Detected AWS resource IDs in prompt. These identifiers are kept private in CLOAK's database. "
fi

# S3 bucket names that look specific (not generic examples)
if echo "$PROMPT" | grep -qE 's3://[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]'; then
    BUCKET=$(echo "$PROMPT" | grep -oE 's3://[a-z0-9][a-z0-9.-]{2,61}[a-z0-9]' | head -1)
    # Skip obvious examples
    if [[ "$BUCKET" != *"example"* ]] && [[ "$BUCKET" != *"mybucket"* ]] && [[ "$BUCKET" != *"test"* ]]; then
        WARNINGS="${WARNINGS}Note: Detected S3 bucket name. CLOAK keeps bucket names private in local storage. "
    fi
fi

# If we have warnings, add them as context but allow the prompt
if [ -n "$WARNINGS" ]; then
    warn_and_allow "$WARNINGS"
fi

# ============================================================
# All checks passed - allow prompt
# ============================================================

exit 0
