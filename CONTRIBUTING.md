# Contributing to Wardwire

Thank you for contributing to Wardwire! We welcome improvements to detectors, evaluation protocols, and UI capabilities.

## Development Workflow

1. **Prerequisites:** Python 3.12+, Node.js 20+, Docker & Docker Compose.
2. **Environment Initialization:**
   ```bash
   make init
   ```
3. **Run Test Suite:**
   ```bash
   make test
   ```
4. **Static Analysis & Linting:**
   ```bash
   make lint
   make typecheck
   ```
5. **Security Scanning:**
   ```bash
   make scan
   ```
6. **Evaluation & Benchmarks:**
   ```bash
   make eval
   make bench
   ```

## Commit Standards
Follow Conventional Commits:
- `feat:` for new capabilities or detectors
- `fix:` for bug fixes
- `test:` for test additions
- `docs:` for documentation updates

