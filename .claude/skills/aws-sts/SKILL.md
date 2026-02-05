---
name: aws-sts
description: Assume IAM roles and obtain temporary security credentials. Use when the user asks about role assumption, cross-account access, or obtaining temporary credentials.
---

# AWS STS Security Operations

Assume IAM roles and obtain temporary security credentials for security assessment.

## Quick Commands

```bash
# List techniques
python -m cloak.cli --list-techniques sts

# Get details
python -m cloak.cli --technique-info sts.assume_role

# Execute (with required role ARN)
python -m cloak.cli --technique sts.assume_role --config '{"role_arn": "arn:aws:iam::123456789012:role/MyRole"}' --execute
```

## Available Techniques

| Technique | Description |
|-----------|-------------|
| `assume_role` | Assume an IAM role and obtain temporary credentials |

## Security Notes

- Temporary credentials are stored in the database but **never** appear in summaries
- Use `--execution-info <id>` to retrieve credentials after execution
- Credentials are time-limited (default 1 hour, max 12 hours)

## Documentation

- Registry: `.claude/skills/cloak-techniques.json`
- Full docs: README.md, docs/SETUP.md, docs/TROUBLESHOOTING.md
