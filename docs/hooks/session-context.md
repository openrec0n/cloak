# SessionStart: AWS Context Injection

**Hook Location:** `.claude/settings.json`  
**Event:** SessionStart  
**Script:** `.claude/hooks/session-context.sh`

## Value Provided

- **Environment validation** - Checks Poetry/venv setup and outputs the correct command prefix
- Auto-validates AWS connection at session start
- Injects current AWS identity (account, role/user) into Claude's context
- Shows recent CLOAK executions for continuity
- Reminds Claude of CLOAK's core rules (dry-run default, privacy-first)

## Without This Hook

- Claude wastes turns discovering `poetry run` is needed instead of bare `python`
- User must manually run `--validate-connection` to check credentials
- Claude may attempt techniques with expired/invalid credentials
- No awareness of previous assessment work in the session
- Increased back-and-forth when credentials fail mid-assessment

## Implementation

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup|resume",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/session-context.sh"
          }
        ]
      }
    ]
  }
}
```

## Output Example

```
=== CLOAK Session Context ===

Environment: Ready
  Command Prefix: poetry run python

AWS Connection: Valid - Account 123456789012, assumed-role: SecurityAudit

Recent CLOAK executions:
  ✓ s3.list_buckets (2024-01-15 10:30:00)
  ✓ iam.list_roles (2024-01-15 10:25:00)
  ✓ ec2.describe_vpcs (2024-01-15 10:20:00)

Core Rules:
  - Dry-run by default: Always preview with --technique before using --execute
  - Privacy-first: Sensitive data stays in data/cloak.db, only summaries shown
  - Confirmation required: User must approve before any AWS API calls
  - Use --execution-info <id> to fetch sensitive details when requested
```

When environment setup is incomplete:

```
=== CLOAK Session Context ===

Environment: Virtual environment not found
  Run: poetry install
  Command Prefix: poetry run python

AWS Connection: Not configured or credentials expired. Run: poetry run python -m cloak.cli --validate-connection
...
```
