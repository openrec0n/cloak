# CLOAK Development Guide

Guide for implementing AWS enumeration techniques in CLOAK.

## Quick Reference

### What Every Technique Must Have

- Class inheriting from `BaseTechnique`
- 5 required methods: `metadata`, `validate()`, `dry_run()`, `_execute_impl()`, `summarize()`
- Registration in service module's `TECHNIQUES` dict
- Test suite (15-20 tests)
- **CRITICAL:** Summary that passes `validate_summary()` (NO sensitive data)

### Files to Create/Modify

```
cloak/techniques/{service}/{technique}.py          # Implementation
cloak/techniques/{service}/__init__.py             # Registry update
tests/test_techniques/test_{service}/test_{technique}.py  # Tests
.claude/skills/{service}/techniques/{technique}.md # Skill documentation
.claude/skills/{service}/SKILL.md                  # Skill table update
```

## Implementation Checklist

1. Create technique class in `cloak/techniques/{service}/{technique}.py`
2. Implement the 5 required methods
3. Add to `TECHNIQUES` dict in `__init__.py`
4. Export class in `__init__.py`'s `__all__`
5. Write comprehensive tests (15-20 minimum)
6. **CRITICAL:** Verify summary passes `validate_summary()` in tests
7. Create skill documentation in `.claude/skills/{service}/techniques/`
8. Update `.claude/skills/{service}/SKILL.md` technique table
9. Run `python -m cloak.cli --generate-registry`

## BaseTechnique Interface

**Location:** `cloak/techniques/base.py`

### Required Methods

| Method | Return Type | Purpose |
|--------|-------------|---------|
| `metadata` (property) | `TechniqueMetadata` | Technique discovery info |
| `validate()` | `ValidationResult` | Parameter validation |
| `dry_run()` | `DryRunResult` | Action preview (no AWS calls) |
| `_execute_impl()` | `tuple[list[Asset], list[Finding]]` | Core enumeration logic |
| `summarize(assets, findings)` | `str` | Safe summary for Claude context |

### Helper Methods (provided by BaseTechnique)

| Method | Purpose |
|--------|---------|
| `get_client(service_name, region_name)` | Get boto3 client |
| `get_regions()` | Get regions to enumerate |
| `validate_connection()` | Validate AWS credentials |
| `execute()` | Main orchestration |

## Method Implementation Patterns

### 1. metadata Property

```python
@property
def metadata(self) -> TechniqueMetadata:
    return TechniqueMetadata(
        name="list_buckets",
        service="s3",
        description="List all S3 buckets with their regions",
        required_permissions=[
            "s3:ListAllMyBuckets",
            "s3:GetBucketLocation",
        ],
        required_parameters=[],
        optional_parameters=[],
    )
```

### 2. validate() Method

```python
def validate(self) -> ValidationResult:
    result = ValidationResult(valid=True)

    bucket_name = self.config.parameters.get("bucket_name")
    if not bucket_name:
        result.add_error("bucket_name parameter is required")
        return result  # Early return on error

    if not isinstance(bucket_name, str):
        result.add_error("bucket_name must be a string")
        return result

    return result
```

### 3. dry_run() Method

**Key constraint:** NEVER call AWS APIs.

```python
def dry_run(self) -> DryRunResult:
    bucket_name = self.config.parameters.get("bucket_name", "unknown")

    if bucket_name == "all":
        actions = [
            "Call s3:ListAllMyBuckets (1 API call)",
            "Call s3:GetBucketAcl for each bucket (N API calls)",
        ]
        estimated_api_calls = "1 + N (where N = number of buckets)"
    else:
        actions = [
            f"Call s3:GetBucketAcl for bucket '{bucket_name}' (1 API call)",
        ]
        estimated_api_calls = "1"

    return DryRunResult(
        actions=actions,
        estimated_api_calls=estimated_api_calls,
        regions=["global"],
        required_permissions=self.metadata.required_permissions,
    )
```

### 4. _execute_impl() Method

```python
def _execute_impl(self) -> tuple[list[Asset], list[Finding]]:
    assets: list[Asset] = []
    findings: list[Finding] = []

    client = self.get_client("s3")
    connection_info = self.validate_connection()

    try:
        response = client.list_buckets()
        self.logger.api_call("s3:ListBuckets")
    except Exception as e:
        self.logger.error(f"Failed to list buckets: {e}")
        raise

    for bucket in response.get("Buckets", []):
        bucket_name = bucket["Name"]

        # Get region (handle us-east-1 special case)
        try:
            location = client.get_bucket_location(Bucket=bucket_name)
            region = location.get("LocationConstraint") or "us-east-1"
            self.logger.api_call("s3:GetBucketLocation")
        except Exception as e:
            self.logger.warning(f"Could not get location: {e}")
            region = "unknown"

        asset = Asset(
            service="s3",
            resource_type="s3_bucket",
            resource_id=bucket_name,
            resource_arn=f"arn:aws:s3:::{bucket_name}",
            region=region,
            account_id=connection_info.account_id,
            name=bucket_name,
        )
        asset.data = {
            "Name": bucket_name,
            "CreationDate": bucket["CreationDate"].isoformat(),
            "Region": region,
        }
        assets.append(asset)

    return assets, findings
```

### 5. summarize() Method

**CRITICAL:** Summary must NOT contain sensitive data.

**Safe to include:** Counts, region names, aggregate statistics, execution ID

**Must NOT include:** Resource names, ARNs, account IDs, IP addresses

```python
def summarize(self, assets: list[Asset], findings: list[Finding]) -> str:
    if not assets:
        return "No S3 buckets found in this AWS account."

    region_counts: dict[str, int] = {}
    for asset in assets:
        region = asset.region or "unknown"
        region_counts[region] = region_counts.get(region, 0) + 1

    lines = [
        "S3 Bucket Enumeration Complete",
        "",
        f"Discovered {len(assets)} bucket(s) across {len(region_counts)} region(s).",
        "",
        "Region distribution:",
    ]

    for region, count in sorted(region_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  - {region}: {count} bucket(s)")

    lines.extend([
        "",
        f"Full details stored in database (execution_id: {self.execution_id})",
    ])

    return "\n".join(lines)
```

## Testing Requirements

Every technique needs comprehensive tests covering:

- Metadata correctness
- Validation (success, missing params, invalid types)
- Dry-run output
- Execution (no resources, single, multiple)
- Database persistence
- **CRITICAL:** Summary sanitization

### Summary Sanitization Test

```python
@mock_aws
def test_summarize_no_sensitive_data(self, db_session, aws_credentials):
    """CRITICAL: Test that summary contains NO sensitive data."""
    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="my-secret-bucket")

    config = TechniqueConfig(
        technique_name="s3.list_buckets",
        dry_run=False,
    )
    technique = ListBucketsTechnique(config, db_session)
    result = technique.execute()

    # CRITICAL validation
    from cloak.output.sanitizers import validate_summary
    is_safe, violations = validate_summary(result.summary)
    assert is_safe, f"Leaked: {violations}"
    assert "my-secret-bucket" not in result.summary
```

## Common Pitfalls

### 1. Including Sensitive Data in Summaries

```python
# WRONG - leaks bucket names
def summarize(self, assets, findings):
    bucket_names = [asset.resource_id for asset in assets]
    return f"Found buckets: {', '.join(bucket_names)}"

# RIGHT - only counts
def summarize(self, assets, findings):
    return f"Found {len(assets)} bucket(s)"
```

### 2. Calling AWS APIs in dry_run()

```python
# WRONG - makes AWS calls
def dry_run(self):
    response = self.get_client("s3").list_buckets()
    return DryRunResult(...)

# RIGHT - no AWS calls
def dry_run(self):
    return DryRunResult(
        actions=["Call s3:ListAllMyBuckets (1 API call)"],
        ...
    )
```

### 3. Not Handling Expected Errors

```python
# WRONG - crashes on missing policy
response = s3_client.get_bucket_policy(Bucket=bucket)

# RIGHT - handle gracefully
try:
    response = s3_client.get_bucket_policy(Bucket=bucket)
except Exception as e:
    if "NoSuchBucketPolicy" in str(e):
        self.logger.info(f"Bucket has no policy")
        continue
    raise
```

### 4. S3 us-east-1 Special Case

```python
# WRONG - None for us-east-1
region = location["LocationConstraint"]

# RIGHT - handle None
region = location.get("LocationConstraint") or "us-east-1"
```

### 5. Storing datetime Objects

```python
# WRONG - datetime object won't serialize
asset.data = {"CreationDate": response["CreationDate"]}

# RIGHT - convert to string
asset.data = {"CreationDate": response["CreationDate"].isoformat()}
```

### 6. Validation Without Early Return

```python
# WRONG - cascading errors
def validate(self):
    result = ValidationResult(valid=True)
    if not param:
        result.add_error("param required")
    if not isinstance(param, str):  # param might be None!
        result.add_error("must be string")
    return result

# RIGHT - early return
def validate(self):
    result = ValidationResult(valid=True)
    if not param:
        result.add_error("param required")
        return result  # Early return
    if not isinstance(param, str):
        result.add_error("must be string")
        return result
    return result
```

## Final Checklist

Before submitting a new technique:

- [ ] Class inherits from `BaseTechnique`
- [ ] `metadata` property has correct permissions
- [ ] `validate()` checks all required parameters
- [ ] `dry_run()` makes NO AWS calls
- [ ] `_execute_impl()` handles errors gracefully
- [ ] `summarize()` contains NO sensitive data
- [ ] Registered in `TECHNIQUES` dict
- [ ] 15-20 comprehensive tests
- [ ] **CRITICAL:** Summary passes `validate_summary()`
- [ ] Skill documentation created
- [ ] SKILL.md table updated
- [ ] Registry regenerated

## Resources

| Resource | Location |
|----------|----------|
| BaseTechnique source | `cloak/techniques/base.py` |
| Reference implementations | `cloak/techniques/s3/` |
| Test patterns | `tests/test_techniques/test_s3/` |
| Sanitizers | `cloak/output/sanitizers.py` |
| Database models | `cloak/core/models.py` |
