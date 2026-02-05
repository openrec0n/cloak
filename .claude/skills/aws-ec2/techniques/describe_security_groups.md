# describe_security_groups Technique

## Description

Enumerates all EC2 security groups across configured regions. Retrieves security
group configuration including inbound and outbound rules. This technique provides
visibility into network access controls.

## Required Parameters

None - this technique enumerates all security groups across configured regions.

## Required AWS Permissions

- `ec2:DescribeSecurityGroups` - List and describe security groups

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call ec2:DescribeSecurityGroups in N region(s) (paginated API calls)
Estimated API calls: 1-N per region (paginated based on security group count)
Regions: us-east-1
Required permissions: ec2:DescribeSecurityGroups
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
EC2 Security Group Enumeration Complete

Discovered X security group(s) across N region(s).

Region distribution:
  - us-east-1: X security group(s)
  - us-west-2: Y security group(s)

Rule statistics:
  - Security groups with inbound rules: X
  - Security groups with outbound rules: Y
  - Unique VPCs: Z

Full details stored in database (execution_id: abc123)
```

**Note**: Security group IDs, names, and VPC IDs are NOT included in the summary.

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique ec2.describe_security_groups --dry-run

# Execute
python -m cloak.cli --technique ec2.describe_security_groups --execute

# Execute in specific regions
python -m cloak.cli --technique ec2.describe_security_groups --execute --regions us-east-1,us-west-2
```
