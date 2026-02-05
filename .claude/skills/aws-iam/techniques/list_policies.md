# list_policies Technique

## Description

Lists IAM policies in the AWS account with configurable scope. Can enumerate
customer-managed policies (Local), AWS-managed policies (AWS), or all policies.

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| scope | string | Policy scope: 'Local' (customer-managed), 'AWS' (AWS-managed), or 'All' |

## Required AWS Permissions

- `iam:ListPolicies` - List policies in the account

## Dry-Run Output

```
[DRY-RUN] Planned actions:
  - Call iam:ListPolicies with Scope='Local' (paginated API calls)
Estimated API calls: 1-N (paginated based on policy count)
Regions: global
Required permissions: iam:ListPolicies
```

## Summary Output Format

The summary returned to Claude contains only aggregate information:

```
IAM Policy Enumeration Complete (Scope: Local)

Discovered X policy(ies).
Attachment status:
  - Attached: N
  - Unattached: N

Full details stored in database (execution_id: abc123)
```

**Note**: Policy names are NOT included in the summary to protect sensitive information.

## Example Execution

```bash
# Dry-run - customer-managed policies
python -m cloak.cli --technique iam.list_policies --config '{"scope": "Local"}'

# Execute - customer-managed policies
python -m cloak.cli --technique iam.list_policies --config '{"scope": "Local"}' --execute

# AWS-managed policies
python -m cloak.cli --technique iam.list_policies --config '{"scope": "AWS"}' --execute
```

## Scope Options

| Scope | Description |
|-------|-------------|
| Local | Customer-managed policies only |
| AWS | AWS-managed policies only |
| All | Both customer-managed and AWS-managed policies |

**Recommendation**: Start with `Local` scope for security assessments.
