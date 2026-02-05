# get_bucket_acl Technique

## Description

Retrieves the Access Control List (ACL) for S3 buckets to identify permission
configurations. ACLs can grant access to specific AWS accounts or make buckets
publicly accessible.

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| bucket_name | str | Name of the bucket to check (or "all" for all buckets) |

## Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| check_public | bool | true | Flag buckets with public ACL grants |

## Required AWS Permissions

- `s3:GetBucketAcl` - Get bucket ACL configuration
- `s3:ListAllMyBuckets` - Required if bucket_name is "all"

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call s3:GetBucketAcl for bucket(s)
Estimated API calls: 1 per bucket
Regions: Bucket region(s)
Required permissions: s3:GetBucketAcl
```

## Summary Output Format

```
S3 Bucket ACL Enumeration Complete

Checked X bucket(s).
Findings:
  - N buckets with public read access
  - N buckets with public write access
  - N buckets with cross-account access

Full ACL details stored in database (execution_id: abc123)
```

**Note**: Bucket names and grantee details are NOT included in the summary.

## Risk Indicators

The technique generates findings for:

| Finding Type | Severity | Description |
|--------------|----------|-------------|
| public_read | HIGH | Bucket grants public read access |
| public_write | CRITICAL | Bucket grants public write access |
| public_read_acp | MEDIUM | Bucket ACL is publicly readable |
| public_write_acp | HIGH | Bucket ACL is publicly writable |
| cross_account_access | MEDIUM | Bucket grants access to other accounts |

## Example Execution

```bash
# Check specific bucket
python -m cloak.cli --technique s3.get_bucket_acl --config '{"bucket_name": "my-bucket"}' --execute

# Check all buckets
python -m cloak.cli --technique s3.get_bucket_acl --config '{"bucket_name": "all"}' --execute
```

## ACL Grant Types

| Permission | Description |
|------------|-------------|
| FULL_CONTROL | Full access to bucket and objects |
| WRITE | Create, overwrite, delete objects |
| WRITE_ACP | Write bucket ACL |
| READ | List objects in bucket |
| READ_ACP | Read bucket ACL |

## Public Access Indicators

A bucket is considered publicly accessible when:
- Grantee URI contains `AllUsers` (anyone on internet)
- Grantee URI contains `AuthenticatedUsers` (any AWS account)
