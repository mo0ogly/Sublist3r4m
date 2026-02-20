# Contributing to Sublist3r4m

Thank you for your interest in contributing to Sublist3r4m!

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists in [GitHub Issues](https://github.com/mo0ogly/Sublist3r4m/issues)
2. If not, open a new issue using the **Bug Report** template
3. Include steps to reproduce, expected vs actual behavior, and your environment details

### Suggesting Features

1. Open a new issue using the **Feature Request** template
2. Describe the use case and expected behavior

### Submitting Code

1. **Fork** the repository
2. **Create a branch** from `master`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```
4. **Write your code** following existing patterns and conventions
5. **Run lint** and fix all errors:
   ```bash
   make lint
   ```
6. **Run tests** and ensure they all pass:
   ```bash
   make test
   ```
7. **Commit** with a clear, descriptive message
8. **Push** and open a **Pull Request** against `master`

## Code Standards

- Python 3.9+ only (no Python 2 compatibility code)
- All code must pass `ruff check .` with zero errors
- All tests must pass before merging
- New features should include unit tests
- All network calls in tests must be mocked

## Development Setup

```bash
git clone https://github.com/mo0ogly/Sublist3r4m.git
cd Sublist3r4m
pip install -e ".[dev]"
make test
```

## Development Commands

| Command | Description |
|---------|-------------|
| `make install` | Install with dev dependencies |
| `make test` | Run test suite with coverage |
| `make lint` | Run ruff linter |
| `make lint-fix` | Auto-fix lint errors |
| `make clean` | Remove build artifacts |
| `make docs` | Serve documentation locally |
| `make docs-build` | Build documentation site |

## Questions?

Open an issue or contact the maintainer.
