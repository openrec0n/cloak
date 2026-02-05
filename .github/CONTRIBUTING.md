# Contributing to CLOAK

Thank you for your interest in contributing. This guide keeps things simple.

## Quick Start

1. **Fork** the repository on GitHub (click the "Fork" button)
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/cloak.git
   cd cloak
   ```
3. **Add the upstream remote** (to stay in sync):
   ```bash
   git remote add upstream https://github.com/openrec0n/cloak.git
   ```
4. **Install dependencies**:
   ```bash
   poetry install
   poetry run pytest  # verify setup
   ```

## Making Changes

1. **Sync your fork** with upstream before starting:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```
2. **Create a branch** on your fork:
   ```bash
   git checkout -b feature/your-change  # or fix/your-bug-fix
   ```
3. **Make your changes** and add tests
4. **Run checks**:
   ```bash
   poetry run pytest && poetry run mypy cloak && poetry run ruff check cloak
   ```
5. **Format code**:
   ```bash
   poetry run black cloak tests
   ```
6. **Push to your fork**:
   ```bash
   git push origin feature/your-change
   ```
7. **Open a Pull Request** from your fork to the upstream repository with a clear description and any related issue numbers

## For AI-Assisted Development

See [AGENTS.md](../AGENTS.md) for development context, key files, and code patterns.

## Adding Techniques

See [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md) for the complete technique implementation guide. Reference existing techniques in `cloak/techniques/` for patterns.

## Code Style

- Type hints required on all functions
- Formatting: `poetry run black cloak tests`
- Linting: `poetry run ruff check cloak`
- Max line length: 100 characters

## Questions?

Open an issue - we're happy to help.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
