---
name: setup-cloak
description: Set up CLOAK development environment. Use when the user wants to install, configure, or troubleshoot CLOAK setup.
---

# CLOAK Setup

Guide users through CLOAK environment setup.

## Verification

Run verification to check current status:

```bash
poetry run python .claude/skills/setup-cloak/scripts/verify_setup.py
```

The script outputs JSON with status of each component. Use this to determine which steps are needed.

**Note:** Always use `poetry run python` to ensure the script runs in the Poetry virtual environment with all dependencies available.

## Requirements

- Python 3.11+
- Poetry (package manager)
- AWS credentials with read permissions

## Setup Workflow

### Step 1: Python

Verify Python 3.11+ is installed. If not, user must install Python first.

### Step 2: Poetry

Install Poetry if not available. Use pipx (recommended) or the official installer.

### Step 3: Dependencies

```bash
poetry install
```

### Step 4: AWS Credentials

Configure AWS credentials using any standard method (environment variables, ~/.aws/credentials, SSO, or IAM role).

**Required permissions**: See [docs/SETUP.md](../../../docs/SETUP.md) for the complete IAM policy.

### Step 5: Validate

```bash
poetry run python -m cloak.cli --validate-connection
```

### Step 6: Final Verification

Run the verification script again to confirm all components are ready.

## Success Criteria

Setup is complete when verify_setup.py shows `"ready": true`.

## Troubleshooting

See [docs/TROUBLESHOOTING.md](../../../docs/TROUBLESHOOTING.md) for common issues.

## Next Steps

Setup is complete! Here are some things you can try:

**S3 Storage Security**
- "Enumerate all S3 buckets in my account and check for public access"
- "Review bucket policies for overly permissive configurations"

**IAM Identity Assessment**
- "List all IAM users and show me which ones have console access"
- "Check IAM roles for excessive permissions"

**EC2 Network Security**
- "Find security groups with unrestricted inbound access (0.0.0.0/0)"
- "Review my VPC configurations"

**Lambda Function Security**
- "Enumerate Lambda functions and their resource-based policies"

Or invoke a skill directly for guided assessments: `/aws-s3`, `/aws-iam`, `/aws-ec2`, `/aws-lambda`
