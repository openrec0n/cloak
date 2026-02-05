# describe_vpcs Technique

## Description

Enumerates all VPCs across configured regions. Retrieves VPC configuration 
including CIDR blocks, state, and whether it's the default VPC. This technique
provides visibility into network infrastructure.

## Required Parameters

None - this technique enumerates all VPCs across configured regions.

## Required AWS Permissions

- `ec2:DescribeVpcs` - List and describe VPCs

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call ec2:DescribeVpcs in N region(s)
Estimated API calls: N (1 per region)
Regions: us-east-1
Required permissions: ec2:DescribeVpcs
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
EC2 VPC Enumeration Complete

Discovered X VPC(s) across N region(s).

Region distribution:
  - us-east-1: X VPC(s)
  - us-west-2: Y VPC(s)

VPC types:
  - Default VPCs: X
  - Custom VPCs: Y

Full details stored in database (execution_id: abc123)
```

**Note**: VPC IDs and CIDR blocks are NOT included in the summary.

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique ec2.describe_vpcs --dry-run

# Execute
python -m cloak.cli --technique ec2.describe_vpcs --execute

# Execute in specific regions
python -m cloak.cli --technique ec2.describe_vpcs --execute --regions us-east-1,us-west-2
```
