# get_function_policy Technique

## Description

Gets resource-based policies for Lambda functions. These policies control which
AWS services or accounts can invoke the function. Supports checking a specific
function or all functions in the configured regions.

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| function_name | string | Name of the function to check, or 'all' to check all functions |

## Required AWS Permissions

- `lambda:ListFunctions` - List Lambda functions (required for 'all' mode)
- `lambda:GetPolicy` - Get function resource-based policy

## Dry-Run Output

For specific function:
```
[DRY-RUN] Planned actions:
  - Call lambda:GetPolicy for function 'my-function' in N region(s)
Estimated API calls: N (1 per region)
Regions: us-east-1
Required permissions: lambda:ListFunctions, lambda:GetPolicy
```

For 'all' mode:
```
[DRY-RUN] Planned actions:
  - Call lambda:ListFunctions in N region(s) (paginated)
  - Call lambda:GetPolicy for each function (N API calls)
Estimated API calls: 1-N + N (list functions + get policy for each)
Regions: us-east-1
Required permissions: lambda:ListFunctions, lambda:GetPolicy
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
Lambda Function Policy Enumeration Complete

Discovered X function(s) with resource-based policies.

Region distribution:
  - us-east-1: X function(s) with policies
  - us-west-2: Y function(s) with policies

Total policy statements: X

Full details stored in database (execution_id: abc123)
```

**Note**: Function names and policy contents are NOT included in the summary.

## Example Execution

```bash
# Dry-run for all functions
python -m cloak.cli --technique lambda.get_function_policy --config '{"function_name": "all"}' --dry-run

# Execute for all functions
python -m cloak.cli --technique lambda.get_function_policy --config '{"function_name": "all"}' --execute

# Execute for specific function
python -m cloak.cli --technique lambda.get_function_policy --config '{"function_name": "my-function"}' --execute

# Interactive mode
python -m cloak.cli --technique lambda.get_function_policy --interactive
```
