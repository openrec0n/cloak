# Troubleshooting Guide

Common issues and solutions when using CLOAK.

## Quick Diagnostics

```bash
python -m cloak.cli --validate-connection
python -m cloak.cli --list-services
sqlite3 data/cloak.db "PRAGMA integrity_check;"
tail -50 data/logs/cloak_*.log
```

## AWS Authentication

### Unable to locate credentials

- Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, or use `~/.aws/credentials`.
- Use a profile: `export AWS_PROFILE=my-profile`.

### InvalidClientTokenId

- Access key should start with `AKIA` or `ASIA`. Check it is correct and active: `aws iam list-access-keys --user-name YOUR_USER`.
- Create new keys if needed: `aws iam create-access-key --user-name YOUR_USER`.

### ExpiredToken

- Refresh temporary credentials: `aws sts get-session-token` or re-assume the role.
- For MFA: `aws sts get-session-token --serial-number arn:aws:iam::ACCOUNT:mfa/user --token-code 123456`.

### SignatureDoesNotMatch

- Sync system clock (e.g. `sudo ntpdate pool.ntp.org`).
- Ensure the secret key has no trailing spaces or newlines.

## Permission Issues

### AccessDenied for a technique

Verify the principal has the required permissions. Ask Claude code to disply a list of techniques and permissions required. 

### Region issues

- Check enabled regions: `aws ec2 describe-regions --query 'Regions[].RegionName'`.
- Run in a specific region: `--config '{"regions": ["us-east-1"]}'`.

## Database

### Database is locked

- Check for other processes: `lsof data/cloak.db`. Wait or stop other CLOAK processes, then retry.

### Database file not found

- Ensure `data/` exists: `mkdir -p data`. The database is created on first run (e.g. dry-run).

### Database malformed

- Check: `sqlite3 data/cloak.db "PRAGMA integrity_check;"`. Restore from backup if you have one.

## CLI

### Technique not found

- Use format `service.technique_name` (e.g. `s3.list_buckets`). List techniques: `python -m cloak.cli --list-techniques`.
- Regenerate registry: `python -m cloak.cli --generate-registry`.

### Invalid JSON config

- Use double quotes in JSON: `--config '{"bucket_name": "my-bucket"}'`. Prefer `--interactive` for parameterized techniques.

### Dry-run not showing resources

- Dry-run shows planned API calls, not actual resources. Use `--execute` to see results.

## Logging

- Ensure `data/logs` exists and is writable. Set `CLOAK_LOG_LEVEL=WARNING` to reduce verbosity. If sensitive data appears in logs, report the issue.

## FAQ

**Can I run multiple CLOAK instances?** Yes; use separate database files: `CLOAK_DATABASE_PATH=data/cloak_1.db python -m cloak.cli ...`.

**Why doesn’t dry-run show my resources?** Dry-run shows planned API calls. Use `--execute` for actual results.

**How do I reset all data?** Remove the database: `rm data/cloak.db`.

**AWS SSO?** Use `aws sso login --profile my-profile` and `export AWS_PROFILE=my-profile`, then `python -m cloak.cli --validate-connection`.

**Bug reports:** Include version (`python -m cloak.cli --version` or `--help`), Python version, OS, command run, and full error. Use the [bug report template](https://github.com/openrec0n/cloak/issues/new?template=bug_report.yml).
