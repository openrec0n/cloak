# assume_role Technique

## Description

Assumes an IAM role and obtains temporary security credentials. This technique
calls AWS STS AssumeRole API to get temporary access credentials for the specified
role. Credentials are stored securely in the database and can be retrieved using
the `--execution-info` command.

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `role_arn` | string | Full ARN of the IAM role to assume (e.g., `arn:aws:iam::123456789012:role/MyRole`) |

## Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `session_name` | string | `cloak-{uuid}` | Identifier for the assumed role session (2-64 chars) |
| `duration_seconds` | int | 3600 | Session duration in seconds (900-43200) |
| `external_id` | string | None | External ID for cross-account role assumption |

## Required AWS Permissions

- `sts:AssumeRole` on the target role

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call sts:AssumeRole for role: arn:aws:iam::123456789012:role/MyRole
  - Request session duration: 3600 seconds
Estimated API calls: 1
Regions: global
Required permissions: sts:AssumeRole
```

## Summary Output Format

The summary returned to Claude contains only safe metadata:

```
IAM Role Assumption Complete

Successfully assumed role.
Session details:
  - Session Name: my-session
  - Expires: 2024-01-15T12:00:00+00:00
  - Duration: 3600 seconds

Credentials stored securely in database.
Use --execution-info <id> to retrieve credentials.

Full details stored in database (execution_id: abc123)
```

**Note**: Credentials (AccessKeyId, SecretAccessKey, SessionToken) are NEVER included
in the summary to protect sensitive information. Use `--execution-info <id>` to
retrieve credentials from the database.

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique sts.assume_role \
  --config '{"role_arn": "arn:aws:iam::123456789012:role/MyRole"}' \
  --dry-run

# Execute with basic parameters
python -m cloak.cli --technique sts.assume_role \
  --config '{"role_arn": "arn:aws:iam::123456789012:role/MyRole"}' \
  --execute

# Execute with custom session name and duration
python -m cloak.cli --technique sts.assume_role \
  --config '{"role_arn": "arn:aws:iam::123456789012:role/MyRole", "session_name": "audit-session", "duration_seconds": 1800}' \
  --execute

# Execute with external ID (for cross-account roles)
python -m cloak.cli --technique sts.assume_role \
  --config '{"role_arn": "arn:aws:iam::123456789012:role/CrossAccountRole", "external_id": "my-external-id"}' \
  --execute

# Retrieve credentials after execution
python -m cloak.cli --execution-info <execution_id>
```

## Use Cases

1. **Security Assessment**: Test which roles can be assumed by the current identity
2. **Cross-Account Access**: Assume roles in other AWS accounts for audit purposes
3. **Privilege Escalation Testing**: Verify role trust policies are properly configured
4. **Credential Rotation**: Obtain fresh temporary credentials for ongoing assessments
