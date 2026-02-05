---
name: aws-ec2
description: Enumerate EC2 instances, security groups, and VPCs in AWS environments. Use when the user asks about EC2 security assessment, instance inventory, network configuration review, or security group analysis.
---

# AWS EC2 Security Enumeration

Discover and assess EC2 resources including instances, security groups, and VPCs.

## Quick Commands

```bash
# List techniques
python -m cloak.cli --list-techniques ec2

# Get details
python -m cloak.cli --technique-info ec2.describe_instances

# Execute
python -m cloak.cli --technique ec2.describe_instances --execute
```

## Documentation

- Registry: `.claude/skills/cloak-techniques.json`
- Full docs: README.md, docs/SETUP.md, docs/TROUBLESHOOTING.md
