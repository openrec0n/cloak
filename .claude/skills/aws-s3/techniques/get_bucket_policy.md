# get_bucket_policy Technique

## Description

Retrieves bucket policies for S3 buckets to analyze access permissions.
Bucket policies provide fine-grained control over who can access bucket
resources and under what conditions.

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| bucket_name | str | Name of the bucket to check (or "all" for all buckets) |

## Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| analyze_principals | bool | true | Analyze policy principals for risky patterns |

## Required AWS Permissions

- `s3:GetBucketPolicy` - Get bucket policy
- `s3:ListAllMyBuckets` - Required if bucket_name is "all"

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call s3:GetBucketPolicy for bucket(s)
Estimated API calls: 1 per bucket
Regions: Bucket region(s)
Required permissions: s3:GetBucketPolicy
```

## Summary Output Format

```
S3 Bucket Policy Enumeration Complete

Checked X bucket(s).
Policy analysis:
  - N buckets have policies attached
  - N buckets have no policy (default deny)

Findings:
  - N policies with wildcard principals (*)
  - N policies allowing cross-account access
  - N policies with overly permissive actions

Full policy details stored in database (execution_id: abc123)
```

## Risk Indicators

| Finding Type | Severity | Description |
|--------------|----------|-------------|
| wildcard_principal | HIGH | Policy uses `"Principal": "*"` |
| cross_account_principal | MEDIUM | Policy grants access to external accounts |
| public_access_granted | CRITICAL | Policy allows unauthenticated access |
| wildcard_action | HIGH | Policy uses `"Action": "s3:*"` |
| condition_bypass | MEDIUM | Policy conditions may be bypassable |

## Example Execution

```bash
# Check specific bucket
python -m cloak.cli --technique s3.get_bucket_policy --config '{"bucket_name": "my-bucket"}' --execute

# Check all buckets
python -m cloak.cli --technique s3.get_bucket_policy --config '{"bucket_name": "all"}' --execute
```

## Policy Analysis

The technique examines policies for:

### Dangerous Principal Patterns
- `"Principal": "*"` - Anyone
- `"Principal": {"AWS": "*"}` - Any AWS account
- External account IDs

### Risky Action Patterns
- `s3:*` - All S3 actions
- `s3:GetObject` with public access
- `s3:PutObject` with external access
- `s3:DeleteObject` permissions

### Condition Weaknesses
- Missing conditions on sensitive actions
- Easily bypassed IP conditions
- Missing MFA requirements

## Policy Statement Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StatementId",
      "Effect": "Allow|Deny",
      "Principal": "...",
      "Action": ["s3:..."],
      "Resource": ["arn:aws:s3:::bucket/*"],
      "Condition": {}
    }
  ]
}
```
