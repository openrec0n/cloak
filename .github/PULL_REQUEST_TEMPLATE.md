## Description

<!-- Provide a brief description of the changes in this PR -->

## Related Issues

<!-- Link to related issues, e.g., Fixes #123, Closes #456 -->

Fixes #

## Type of Change

<!-- Mark with 'x' the type of change -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] New technique (adds a new AWS/cloud enumeration technique)
- [ ] Documentation update
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Refactoring (no functional changes)
- [ ] Test updates

## Checklist

<!-- Ensure all items are completed before requesting review -->

- [ ] I have read the [CONTRIBUTING.md](.github/CONTRIBUTING.md) guidelines
- [ ] My code follows the code style of this project (black, ruff)
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] All new and existing tests pass locally (`poetry run pytest`)
- [ ] Type checking passes (`poetry run mypy cloak`)
- [ ] Linting passes (`poetry run ruff check cloak tests`)
- [ ] Code is formatted (`poetry run black cloak tests`)
- [ ] I have updated the documentation (if applicable)
- [ ] I have updated ROADMAP.md (if completing a task)
- [ ] I have updated CHANGELOG.md (for user-facing changes)
- [ ] If this is a new technique:
  - [ ] Follows technique implementation patterns (see AGENTS.md)
  - [ ] Has 15-20 comprehensive tests
  - [ ] Summary passes `validate_summary()` (no sensitive data)
  - [ ] Skill documentation created (`.claude/skills/`)
  - [ ] Technique registry regenerated (`python -m cloak.cli --generate-registry`)

## Testing

<!-- Describe how you tested your changes -->

**Test environment:**
- OS:
- Python version:
- CLOAK version:

**Test steps:**
1.
2.
3.

**Test results:**
```
<!-- Paste relevant test output -->
```

## Screenshots (if applicable)

<!-- Add screenshots to help explain your changes -->

## Additional Notes

<!-- Any additional information that reviewers should know -->
