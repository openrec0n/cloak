# PostToolUse: Output Validation

**Hook Location:** `.claude/settings.json`  
**Event:** PostToolUse  
**Matcher:** Bash  
**Script:** `.claude/hooks/validate-output.sh`

## Value Provided

- Validates command output for sensitive AWS data patterns
- Warns Claude not to repeat sensitive identifiers in conversation
- Logs execution IDs to `data/logs/hook-audit.log` for audit trail
- Provides defense-in-depth against data leakage

## Without This Hook

- Sensitive data could leak into conversation if CLOAK sanitizers fail
- No audit trail of hook validations
- Claude might repeat sensitive identifiers from command output

## Implementation

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/validate-output.sh"
          }
        ]
      }
    ]
  }
}
```

## Detected Patterns

| Pattern | Description |
|---------|-------------|
| `arn:aws:*:*:123456789012:*` | Full ARN with account ID |
| 12-digit account IDs | AWS Account identifiers |
| `AKIA*` / `ASIA*` | AWS Access Key IDs |
| `*.s3.*` URLs | S3 bucket URLs |
| `s3://*` URIs | S3 bucket URIs |
| `i-*`, `sg-*`, `vpc-*`, etc. | EC2/VPC resource IDs |
| `arn:aws:iam::*:(user\|role\|group\|policy)/*` | IAM resource paths |

## Warning Output

When sensitive data is detected, the hook adds context to Claude:

```
WARNING: Output may contain sensitive AWS data that should not be repeated in conversation: 
ARN detected; Account ID detected; 
Do not include specific resource identifiers in your response. 
Reference execution IDs instead for users to fetch details locally.
```

## Audit Logging

Successful CLOAK executions are logged to `data/logs/hook-audit.log`:

```
2024-01-15T10:30:00Z | execution_id=abc-123 | command=python -m cloak.cli --technique s3.list_buckets --execute
```
