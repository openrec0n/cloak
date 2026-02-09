# AGENTS.md - AI Development Context

This file provides context for AI coding agents (Claude Code, Cursor, GitHub Copilot, etc.) working on the CLOAK codebase. For user-facing guidance on using CLOAK with Claude, see [CLAUDE.md](CLAUDE.md).

## Project Overview

CLOAK is an AI-powered cloud security tool for AWS. It integrates with Claude Code/Desktop to provide natural language security assessment capabilities.

**Tech Stack:**
- Python 3.11+
- Poetry (package management)
- boto3 (AWS SDK)
- SQLAlchemy + SQLite (database)
- FastAPI + uvicorn (Web UI server)
- moto (AWS mocking for tests)
- pytest (testing)
- structlog (logging)

## Code Patterns

### Techniques

All techniques extend `BaseTechnique` from `cloak/techniques/base.py`:

```python
class MyTechnique(BaseTechnique):
    def metadata(self) -> TechniqueMetadata: ...
    def validate(self) -> ValidationResult: ...
    def dry_run(self) -> DryRunResult: ...
    def _execute_impl(self) -> tuple[list[Asset], list[Finding]]: ...
    def summarize(self, assets, findings) -> str: ...
```

### Critical Security Rule

**Summaries must NEVER contain sensitive data** (bucket names, ARNs, account IDs, etc.). Full data goes to SQLite; only aggregate counts go to summaries.

### Testing

- All AWS interactions must use moto mocking
- Target 15-20 tests per technique
- Use fixtures from `tests/conftest.py`

## Key Files

| File | Purpose |
|------|---------|
| `cloak/techniques/base.py` | BaseTechnique interface |
| `cloak/core/database.py` | Database layer |
| `cloak/core/registry.py` | Technique registry |
| `cloak/cli/runner.py` | CLI entry point |
| `cloak/web/server.py` | Web UI FastAPI server |
| `cloak/web/static/index.html` | Web UI single-page application |
| `docs/DEVELOPMENT.md` | Technique implementation guide |

## Commands

```bash
# Development
poetry install
poetry run pytest
poetry run pytest --cov=cloak
poetry run mypy cloak
poetry run ruff check cloak
poetry run black cloak tests

# CLI
poetry run python -m cloak.cli --list-services
poetry run python -m cloak.cli --list-techniques s3
poetry run python -m cloak.cli --technique s3.list_buckets --execute
poetry run python -m cloak.cli --generate-registry

# Web UI
poetry run python -m cloak.cli --web-ui                # Launch dashboard
poetry run python -m cloak.cli --web-ui --background    # Launch in background
poetry run python -m cloak.cli --web-ui --port 9090     # Custom port
```

## Code Style

- Type hints on all functions
- Max line length: 100 characters
- Use black for formatting
- Use ruff for linting
- Follow existing patterns in the codebase

## Adding Features

When adding new techniques:
1. Create implementation in `cloak/techniques/{service}/{technique}.py`
2. Add tests in `tests/test_techniques/test_{service}/`
3. Create skill docs in `.claude/skills/{service}/techniques/`
4. Update SKILL.md technique table
5. Regenerate registry: `poetry run python -m cloak.cli --generate-registry`

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the complete technique implementation guide.
