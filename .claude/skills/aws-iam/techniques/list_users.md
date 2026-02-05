# list_users Technique

## Description

Lists all IAM users in the AWS account with their creation dates, paths, and 
last password usage information. This technique provides an inventory of human
and service account identities.

## Required Parameters

None - this technique enumerates all users account-wide.

## Required AWS Permissions

- `iam:ListUsers` - List all users in the account

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call iam:ListUsers (paginated API calls)
Estimated API calls: 1-N (paginated based on user count)
Regions: global
Required permissions: iam:ListUsers
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
IAM User Enumeration Complete

Discovered X user(s).
Path distribution:
  - /: N user(s)
  - /admin/: N user(s)

Full details stored in database (execution_id: abc123)
```

**Note**: User names are NOT included in the summary to protect sensitive information.

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique iam.list_users --dry-run

# Execute
python -m cloak.cli --technique iam.list_users --execute
```
