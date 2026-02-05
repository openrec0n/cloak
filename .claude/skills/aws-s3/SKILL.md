---
name: aws-s3
description: Enumerate S3 buckets, ACLs, and policies in AWS environments. Use when the user asks about S3 security assessment, bucket enumeration, storage misconfiguration detection, or S3 permissions review.
---

# AWS S3 Security Enumeration

Discover and assess S3 bucket security misconfigurations.

## Quick Commands

```bash
# List techniques
python -m cloak.cli --list-techniques s3

# Get details
python -m cloak.cli --technique-info s3.list_buckets

# Execute
python -m cloak.cli --technique s3.list_buckets --execute
```

## Documentation

- Registry: `.claude/skills/cloak-techniques.json`
- Full docs: README.md, docs/SETUP.md, docs/TROUBLESHOOTING.md
