---
name: web-ui
description: Launch and use the CLOAK Web UI dashboard for browsing security assessment results. Use when the user asks to see full details, browse findings visually, view sensitive data like resource names/ARNs, or wants a dashboard overview of executions.
---

# CLOAK Web UI

The Web UI is the **primary way for users to view sensitive data** from security assessments. It renders full resource names, ARNs, account IDs, and configuration details in the browser -- entirely outside the AI context window -- making it the safest path for reviewing detailed findings.

## When to Suggest the Web UI

- **After any technique execution** -- always include the deep link in your response
- **When the user asks to "see" or "show" resource names, ARNs, or details** -- direct them to the Web UI instead of using `--execution-info`
- **When the user wants to compare findings across multiple executions** -- the dashboard aggregates stats across all executions
- **When the user asks for a summary or overview** -- the dashboard has charts, severity breakdowns, and service analytics

## Quick Commands

```bash
# Launch Web UI (foreground, opens browser automatically)
poetry run cloak --web-ui

# Launch on a custom port
poetry run cloak --web-ui --port 9090

# Launch in background (non-blocking, runs alongside technique execution)
poetry run cloak --web-ui --background

# Execute a technique and open results in Web UI
poetry run cloak --technique s3.list_buckets --execute --open-ui
```

## Deep Links

After each technique execution, provide the user with the appropriate deep link:

| View | URL Pattern |
|------|-------------|
| Dashboard | `http://localhost:8080/` |
| Execution detail | `http://localhost:8080/#/executions/<execution_id>` |
| All findings | `http://localhost:8080/#/findings` |
| Finding detail | `http://localhost:8080/#/findings/<finding_id>` |

## Workflow Integration

**Standard post-execution response pattern:**

After running a technique with `--execute`, always include the Web UI link:

> "I found 15 S3 buckets across 3 regions with 3 critical findings.
> View full details: http://localhost:8080/#/executions/<execution_id>"

**Instead of `--execution-info`:**

When the user asks to see sensitive details, prefer:
> "You can browse the full details including resource names and ARNs in the Web UI:
> http://localhost:8080/#/executions/<execution_id>"

Only use `--execution-info <id>` as a fallback when the Web UI is not running.

## Dashboard Features

- **Stats overview**: Total executions, findings, assets, success rate
- **Severity breakdown**: Visual chart of findings by severity level
- **Service analytics**: Executions and assets grouped by AWS service
- **Execution history**: Filterable list with status, technique, timestamps
- **Finding browser**: Filterable list with severity, type, resource info
- **Detail views**: Full execution config, assets, and findings with drill-down
