# CLOAK Setup Guide

This guide covers installation and AWS configuration for CLOAK.

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Python | 3.11 or higher |
| Memory | 512 MB RAM |
| Disk | 100 MB for application, variable for database |
| Network | HTTPS access to AWS APIs |

**Supported:** Linux (Ubuntu 22.04+, RHEL 8+), macOS 12+. Windows 10/11 via WSL2.

## Installation

### Poetry (Development)

See [README.md](../README.md) for clone and quick start. Then:

```bash
poetry install
poetry run python -m cloak.cli --validate-connection
```

### pip (Production)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install git+https://github.com/openrec0n/cloak.git
python -m cloak.cli --validate-connection
```

## AWS Configuration

### IAM Policy

Create a dedicated IAM policy with only the permissions required by the techniques you use:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CLOAKEnumeration",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "iam:ListUsers",
        "iam:GetUser",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "lambda:ListFunctions",
        "lambda:GetPolicy",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Save as `cloak-policy.json`, then:

```bash
aws iam create-policy --policy-name CloakPolicy --policy-document file://cloak-policy.json
aws iam create-user --user-name cloak-scanner
aws iam attach-user-policy --user-name cloak-scanner --policy-arn arn:aws:iam::ACCOUNT_ID:policy/CloakPolicy
aws iam create-access-key --user-name cloak-scanner
```

Replace `ACCOUNT_ID` with your AWS account ID.

### Credentials

**Option 1: Environment variables**

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

**Option 2: AWS credentials file**

```bash
aws configure --profile cloak
export AWS_PROFILE=cloak
```

**Option 3: IAM role (EC2/ECS)**

Attach a role with the CLOAK policy to the instance or task; no extra configuration needed.

### Validate

For Poetry installations:
```bash
poetry run python -m cloak.cli --validate-connection
```

For pip installations (with venv activated):
```bash
python -m cloak.cli --validate-connection
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CLOAK_DATABASE_PATH` | SQLite database path | `data/cloak.db` |
| `CLOAK_LOG_DIRECTORY` | Log file directory | `data/logs` |
| `CLOAK_LOG_LEVEL` | Logging level | `INFO` |
| `CLOAK_DEFAULT_REGIONS` | AWS regions to scan | `us-east-1,us-west-2` |

## Troubleshooting

For AWS authentication errors (Unable to locate credentials, InvalidClientTokenId, ExpiredToken, SignatureDoesNotMatch) and permission issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Security

Use dedicated credentials with least-privilege permissions. Restrict file permissions on the data directory (e.g. `chmod 700 data/`).