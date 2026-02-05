---
name: aws-lambda
description: Enumerate Lambda functions and their policies in AWS environments. Use when the user asks about serverless security assessment, function inventory, or Lambda resource-based policy review.
---

# AWS Lambda Security Enumeration

Discover and assess Lambda functions and their resource-based policies.

## Quick Commands

```bash
# List techniques
python -m cloak.cli --list-techniques lambda

# Get details
python -m cloak.cli --technique-info lambda.list_functions

# Execute
python -m cloak.cli --technique lambda.list_functions --execute
```

## Documentation

- Registry: `.claude/skills/cloak-techniques.json`
- Full docs: README.md, docs/SETUP.md, docs/TROUBLESHOOTING.md
