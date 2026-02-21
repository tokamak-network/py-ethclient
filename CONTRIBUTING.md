# Contributing to py-ethclient

Thank you for your interest in contributing to py-ethclient! This document provides guidelines for contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork and create a new branch
3. Set up the development environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run a specific test module
pytest tests/test_evm.py

# Run with verbose output
pytest -v
```

### Code Style

- Follow PEP 8 conventions
- Use type hints where practical
- Keep functions focused and readable

### Commit Messages

Use conventional commit format:

```
feat(module): add new feature
fix(module): fix specific bug
docs: update documentation
test: add or update tests
refactor(module): restructure code
```

## What to Contribute

### Good First Issues

- Adding missing EVM opcodes or precompiles
- Improving test coverage
- Documentation improvements
- Bug fixes

### Areas of Interest

- **EVM**: Additional opcodes, gas optimization
- **Networking**: Protocol improvements, peer management
- **Storage**: Query optimization, new backends
- **RPC**: Additional JSON-RPC methods
- **Sync**: Performance improvements

## Submitting Changes

1. Ensure all tests pass: `pytest`
2. Write tests for new functionality
3. Create a pull request with a clear description of changes

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include steps to reproduce for bug reports
- Provide relevant logs or error messages

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
