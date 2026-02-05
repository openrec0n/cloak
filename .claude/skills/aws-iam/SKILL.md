---
name: aws-iam
description: Enumerate IAM users, roles, and policies in AWS environments. Use when the user asks about IAM security assessment, identity enumeration, privilege review, or IAM inventory.
---

# AWS IAM Security Enumeration

Discover and assess IAM configuration and access controls.

## Quick Commands

```bash
# List techniques
python -m cloak.cli --list-techniques iam

# Get details
python -m cloak.cli --technique-info iam.list_users

# Execute
python -m cloak.cli --technique iam.list_users --execute
```

## Documentation

- Registry: `.claude/skills/cloak-techniques.json`
- Full docs: README.md, docs/SETUP.md, docs/TROUBLESHOOTING.md
