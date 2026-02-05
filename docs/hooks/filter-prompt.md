# UserPromptSubmit: Sensitive Data Filter

**Hook Location:** `.claude/settings.json`  
**Event:** UserPromptSubmit  
**Script:** `.claude/hooks/filter-prompt.sh`

## Value Provided

- Blocks prompts containing AWS credentials (access keys, secret keys, session tokens)
- Blocks prompts containing full ARNs with account information
- Warns about prompts containing account IDs or resource identifiers
- Protects against accidental secret exposure in conversation

## Without This Hook

- Users could accidentally paste AWS credentials into the conversation
- Sensitive identifiers (ARNs, account IDs) could enter Claude's context
- No defense against credential leakage through copy-paste errors

## Implementation

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/filter-prompt.sh"
          }
        ]
      }
    ]
  }
}
```

## Blocked Patterns

| Pattern | Action | Reason |
|---------|--------|--------|
| `AKIA...` / `ASIA...` (20 chars) | Block | AWS Access Key ID |
| 40-char base64 string near "secret" | Block | AWS Secret Access Key |
| Long base64 string near "session_token" | Block | AWS Session Token |
| Full ARN with account ID | Block | Sensitive resource identifier |

## Warning Patterns

| Pattern | Action | Reason |
|---------|--------|--------|
| 12-digit number | Warn | Potential AWS Account ID |
| `i-`, `sg-`, `vpc-` prefixed IDs | Warn | EC2/VPC resource identifiers |
| `s3://bucket-name` | Warn | S3 bucket name |

## Example Blocked Message

```
BLOCKED: Your prompt contains what appears to be an AWS Access Key ID. 
Please remove the credential and try again. Never share AWS credentials in conversation.
```
