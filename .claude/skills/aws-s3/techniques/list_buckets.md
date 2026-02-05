# list_buckets Technique

## Description

Lists all S3 buckets in the AWS account with their creation dates and regions.
This is typically the first technique to run for S3 assessment as it provides
a complete inventory of storage resources.

## Required Parameters

None - this technique enumerates all buckets account-wide.

## Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| include_metadata | bool | false | Include additional bucket metadata (versioning, encryption status) |

## Required AWS Permissions

- `s3:ListAllMyBuckets` - List all buckets in the account
- `s3:GetBucketLocation` - Get the region for each bucket

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call s3:ListAllMyBuckets (1 API call)
  - Call s3:GetBucketLocation for each bucket (N API calls)
Estimated API calls: 1 + N (where N = number of buckets)
Regions: global (bucket listing), per-bucket regions for location
Required permissions: s3:ListAllMyBuckets, s3:GetBucketLocation
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
S3 Bucket Enumeration Complete

Discovered X buckets across Y regions.
Region distribution:
  - us-east-1: N buckets
  - us-west-2: N buckets
  - eu-west-1: N buckets

Full details stored in database (execution_id: abc123)
```

**Note**: Bucket names are NOT included in the summary to protect sensitive information.
All bucket details are stored in the SQLite database for human review.

## Risk Indicators

During enumeration, the technique may generate findings for:

- **Large bucket count**: May indicate resource sprawl
- **Multi-region deployment**: Buckets spread across many regions
- **Default naming patterns**: Buckets with predictable names

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique s3.list_buckets --dry-run

# Execute
python -m cloak.cli --technique s3.list_buckets --execute

# With metadata
python -m cloak.cli --technique s3.list_buckets --config '{"include_metadata": true}' --execute
```

## Database Schema

Results are stored in the `assets` table:

| Column | Description |
|--------|-------------|
| service | "s3" |
| resource_type | "s3_bucket" |
| resource_id | Bucket name |
| resource_arn | arn:aws:s3:::bucket-name |
| region | Bucket region |
| data_json | Full bucket metadata |
