# PreToolUse: Database Access Approval

**Hook Location:** `.claude/settings.json`  
**Event:** PreToolUse  
**Matcher:** Bash  
**Script:** `.claude/hooks/approve-db-access.sh`

## Value Provided

- Human-in-the-loop approval for database access containing sensitive AWS data
- Uses Claude Code's built-in permission dialog for approve/deny decisions
- Shows execution ID being accessed for informed consent
- Supports "always allow" option for session persistence via Claude Code UI

## Without This Hook

- Claude could access and display sensitive AWS data (ARNs, bucket names, account IDs) without explicit user consent
- Users would have no gating mechanism before sensitive data enters the conversation
- No clear audit trail of when sensitive data was intentionally revealed

## Implementation

This hook runs as part of a chain with `enforce-dry-run.sh`. Both hooks must be under the same matcher entry to ensure sequential execution:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/enforce-dry-run.sh",
            "timeout": 5,
            "statusMessage": "Validating command safety..."
          },
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/approve-db-access.sh",
            "timeout": 5,
            "statusMessage": "Checking database access permissions..."
          }
        ]
      }
    ]
  }
}
```

## Commands Requiring Approval

### Database Access Operations

- `--execution-info <id>` - Fetches full execution details including:
  - AWS ARNs (resource identifiers)
  - S3 bucket names
  - AWS Account IDs
  - EC2/VPC resource IDs
  - IAM resource paths

## Workflow

1. User asks Claude to show details of a previous execution
2. Claude runs: `python -m cloak.cli --execution-info <uuid>`
3. Hook intercepts and returns `permissionDecision: "ask"`
4. Claude Code shows approval dialog:
   ```
   Database access requested for execution <uuid>.
   This will reveal sensitive AWS data (ARNs, bucket names, account IDs).
   ```
5. User chooses:
   - **Allow** - Proceed with this command only
   - **Deny** - Block the command
   - **Always Allow** - Allow for the rest of the session (Claude Code built-in)

## Decision Logic

```
┌─────────────────────────────────┐
│ Bash command received           │
└─────────────┬───────────────────┘
              │
              ▼
┌─────────────────────────────────┐
│ Contains --execution-info?      │
└─────────────┬───────────────────┘
              │
    ┌─────────┴─────────┐
    │ Yes               │ No
    ▼                   ▼
┌───────────────┐  ┌───────────────┐
│ Return "ask"  │  │ Allow (exit 0)│
│ with reason   │  │               │
└───────────────┘  └───────────────┘
```

## Security Considerations

- This hook provides defense-in-depth alongside CLOAK's output sanitization
- Even if sensitive data is retrieved, it requires explicit user consent
- The "always allow" option is session-scoped and resets on new sessions
- Audit logging in other hooks tracks when database access occurs
