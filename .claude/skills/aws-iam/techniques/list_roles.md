# list_roles Technique

## Description

Lists all IAM roles in the AWS account with their trust policies, paths, and
configuration details. This technique provides an inventory of service roles,
cross-account roles, and instance profiles.

## Required Parameters

None - this technique enumerates all roles account-wide.

## Required AWS Permissions

- `iam:ListRoles` - List all roles in the account

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call iam:ListRoles (paginated API calls)
Estimated API calls: 1-N (paginated based on role count)
Regions: global
Required permissions: iam:ListRoles
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
IAM Role Enumeration Complete

Discovered X role(s).
Path distribution:
  - /: N role(s)
  - /service-role/: N role(s)

Full details stored in database (execution_id: abc123)
```

**Note**: Role names are NOT included in the summary to protect sensitive information.

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique iam.list_roles --dry-run

# Execute
python -m cloak.cli --technique iam.list_roles --execute
```
