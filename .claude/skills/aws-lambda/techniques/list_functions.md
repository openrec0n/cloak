# list_functions Technique

## Description

Enumerates all Lambda functions across configured regions. Retrieves function 
configuration including runtime, memory, timeout, and code size. This technique 
provides a comprehensive inventory of serverless compute resources.

## Required Parameters

None - this technique enumerates all functions across configured regions.

## Required AWS Permissions

- `lambda:ListFunctions` - List Lambda functions

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call lambda:ListFunctions in N region(s) (paginated API calls)
Estimated API calls: 1-N per region (paginated based on function count)
Regions: us-east-1
Required permissions: lambda:ListFunctions
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
Lambda Function Enumeration Complete

Discovered X function(s) across N region(s).

Region distribution:
  - us-east-1: X function(s)
  - us-west-2: Y function(s)

Runtime distribution:
  - python3.9: X function(s)
  - python3.11: Y function(s)
  - nodejs18.x: Z function(s)

Total code size: X.XX MB

Full details stored in database (execution_id: abc123)
```

**Note**: Function names and ARNs are NOT included in the summary.

## Example Execution

```bash
# Dry-run first
python -m cloak.cli --technique lambda.list_functions --dry-run

# Execute
python -m cloak.cli --technique lambda.list_functions --execute

# Execute in specific regions
python -m cloak.cli --technique lambda.list_functions --execute --regions us-east-1,us-west-2
```
