# PreToolUse: Dry-Run Enforcement

**Hook Location:** `.claude/settings.json`  
**Event:** PreToolUse  
**Matcher:** Bash  
**Script:** `.claude/hooks/enforce-dry-run.sh`

## Value Provided

- Enforces dry-run workflow: blocks `--execute` without prior dry-run preview
- Blocks dangerous AWS CLI commands (delete, terminate, etc.)
- Blocks direct boto3/AWS SDK usage that bypasses CLOAK safety controls
- Tracks dry-run state per session to validate execution requests

## Without This Hook

- Claude could skip dry-run preview and execute directly
- Destructive AWS commands could be run accidentally
- Direct AWS SDK calls could bypass CLOAK's safety controls and audit logging

## Implementation

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/enforce-dry-run.sh"
          }
        ]
      }
    ]
  }
}
```

## Blocked Commands

### Dangerous AWS CLI Operations

- `aws s3 rm`, `aws s3 rb`, `aws s3api delete*`
- `aws ec2 terminate-instances`, `aws ec2 delete-*`
- `aws iam delete-*`
- `aws rds delete-*`
- `aws lambda delete-*`
- `aws cloudformation delete-*`
- `aws dynamodb delete-table`
- AWS commands with `--force` flag

### SDK Bypass Attempts

- `boto3.client`, `boto3.resource`
- `import boto3`, `from boto3`

## Workflow Enforcement

1. User requests a technique (e.g., "list S3 buckets")
2. Claude runs dry-run: `python -m cloak.cli --technique s3.list_buckets`
3. Hook records that `s3.list_buckets` dry-run was performed
4. User approves execution
5. Claude runs: `python -m cloak.cli --technique s3.list_buckets --execute`
6. Hook allows execution because dry-run was completed

If step 5 is attempted without step 2, the hook blocks with:

```
Blocked: Must run dry-run preview first before --execute. 
Run without --execute flag to see planned actions, then get user confirmation before executing.
```
