# describe_instances Technique

## Description

Enumerates all EC2 instances across configured regions. Retrieves instance 
configuration including instance type, state, VPC, subnet, IPs, and tags.
This technique provides a comprehensive inventory of compute resources.

## Required Parameters

None - this technique enumerates all instances across configured regions.

## Required AWS Permissions

- `ec2:DescribeInstances` - List and describe EC2 instances

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call ec2:DescribeInstances in N region(s) (paginated API calls)
Estimated API calls: 1-N per region (paginated based on instance count)
Regions: us-east-1
Required permissions: ec2:DescribeInstances
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
EC2 Instance Enumeration Complete

Discovered X instance(s) across N region(s).

Region distribution:
  - us-east-1: X instance(s)
  - us-west-2: Y instance(s)

State distribution:
  - running: X instance(s)
  - stopped: Y instance(s)

Instance types (top 5):
  - t2.micro: X instance(s)
  - t3.small: Y instance(s)

Full details stored in database (execution_id: abc123)
```

**Note**: Instance IDs, names, and IP addresses are NOT included in the summary.

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique ec2.describe_instances --dry-run

# Execute
python -m cloak.cli --technique ec2.describe_instances --execute

# Execute in specific regions
python -m cloak.cli --technique ec2.describe_instances --execute --regions us-east-1,us-west-2
```
