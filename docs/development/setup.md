# Development Setup

**Complete guide for setting up FLEXT Auth development environment**

> **✅ Recent Progress**: Major documentation milestone completed. All source files now have comprehensive documentation. Setup workflow being improved.

---

## 🚨 Prerequisites

### System Requirements

- **Python 3.13+** (no backward compatibility)
- **Poetry 1.8+** for dependency management
- **Docker & Docker Compose** for services
- **Git** for version control
- **Make** for build automation

### FLEXT Ecosystem Dependencies

```bash
# Ensure sibling directories exist
ls ../flext-core        # flext-core foundation library
ls ../flext-observability  # observability integration

# If missing, clone the full ecosystem
git clone https://github.com/flext-sh/flext.git
cd flext/flext-auth
```

---

## 🔧 Environment Setup

### 1. Poetry Installation

```bash
# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
poetry --version  # Should show 1.8.0+
```

### 2. Python Environment

```bash
# Verify Python version
python3 --version  # Must be 3.13+

# Set Python for Poetry (if multiple versions)
poetry env use python3.13
```

### 3. Docker Setup

```bash
# Verify Docker installation
docker --version
docker-compose --version

# Start Docker daemon (if not running)
sudo systemctl start docker  # Linux
# or Docker Desktop on macOS/Windows
```

---

## 🚧 Current Development Workflow (With Issues)

### Recent Progress & Remaining Issues

**✅ Completed**:

1. **Complete Documentation**: All 23 source files comprehensively documented
2. **Design Patterns Coverage**: Comprehensive patterns documented across all layers
3. **English Standardization**: All documentation standardized in English
4. **Architectural Alignment**: Full Clean Architecture and DDD documentation

**🔄 In Progress**:

1. **Test Suite Stabilization**: Import errors being resolved
2. **Code Quality Improvements**: Linting violations being addressed
3. **FlextContainer Integration**: Dependency injection patterns implementation
4. **Documentation Infrastructure**: Complete docs structure updates

### Workaround Installation

```bash
# Clone repository
git clone https://github.com/flext-sh/flext.git
cd flext/flext-auth

# Install dependencies (basic installation works)
poetry install

# Try development setup (will show errors)
make setup  # Currently fails due to test issues

# Manual workaround
poetry install --with dev,test,docs
poetry run pre-commit install  # May work
```

### Current Quality Gate Status

```bash
# Check what works and what doesn't
poetry run ruff --version  # Should work
poetry run mypy --version  # Should work
poetry run pytest --version  # Should work

# Quality gates (currently failing)
make validate  # Shows 23 linting errors
make test      # Shows 13 test failures
make lint      # Shows specific linting issues
```

---

## 🎯 Target Development Workflow (Post-Fixes)

### Complete Setup (Future)

```bash
# One-command setup
make setup

# This will include:
# - poetry install --with dev,test,docs
# - pre-commit install
# - Database migration (if needed)
# - Quality gate verification
```

### Daily Development Cycle (Future)

```bash
# Start development session
make doctor         # Health check
docker-compose up -d  # Start services

# Development loop
git checkout -b feature/your-feature
# Make changes
make validate       # All quality gates pass
make test          # 95% coverage achieved
git commit -m "Your changes"

# End development session
docker-compose down
```

---

## 🐳 Docker Development Environment

### Services Configuration

```yaml
# docker-compose.yml includes:
services:
  postgres: # PostgreSQL 15 (port 5432)
  redis: # Redis 7 Alpine (port 6379)
  auth-api: # FLEXT Auth API (port 8000)
```

### Starting Services

```bash
# Start only dependencies
docker-compose up -d postgres redis

# Start all services (future)
docker-compose up -d

# View service status
docker-compose ps

# View logs
docker-compose logs -f postgres
docker-compose logs -f redis
docker-compose logs -f auth-api  # When available
```

### Service Access

```bash
# PostgreSQL access
docker-compose exec postgres psql -U flext -d flext_auth

# Redis access
docker-compose exec redis redis-cli

# API health check (future)
curl http://localhost:8000/health
```

---

## 🧪 Testing Environment

### Current Test Structure

```
tests/
├── unit/              # Some unit tests exist
├── test_*.py          # 20 test files (13 failing)
├── conftest.py        # Pytest configuration
└── (missing integration/, e2e/)
```

### Test Execution (Current Issues)

```bash
# All tests currently fail
make test  # Shows import errors

# Try individual test files
poetry run pytest tests/test_basic_functionality.py -v
# ImportError: cannot import name 'flext_auth_validate_jwt'

# Check specific test file
poetry run pytest tests/conftest.py --collect-only
```

### Target Test Structure (Future)

```
tests/
├── unit/
│   ├── core/          # Core functionality tests
│   ├── domain/        # Domain model tests
│   └── patterns/      # Pattern implementation tests
├── integration/       # Service integration tests
├── e2e/              # End-to-end workflow tests
├── conftest.py       # Test configuration
└── conftest_integration.py  # Integration fixtures
```

### Test Categories (Future)

```bash
# Run by category
pytest -m unit              # Unit tests
pytest -m integration       # Integration tests
pytest -m e2e               # End-to-end tests
pytest -m security          # Security tests
pytest -m "not slow"        # Fast tests only

# Coverage testing
pytest --cov=src --cov-report=html
make coverage-html
```

---

## 📊 Quality Standards

### Code Quality Tools

```bash
# Linting
poetry run ruff check src tests
poetry run ruff format src tests

# Type checking
poetry run mypy src --strict

# Security scanning
poetry run bandit -r src
poetry run pip-audit

# Pre-commit hooks
poetry run pre-commit run --all-files
```

### Quality Metrics (Targets)

- **Test Coverage**: 95% minimum (currently 0% due to failures)
- **Type Coverage**: 100% (strict MyPy)
- **Linting**: 0 errors (currently 23 errors)
- **Security**: 0 vulnerabilities
- **Line Length**: 79 characters (PEP8 strict)

### Quality Gates

```bash
# All must pass before commit
make validate  # Complete validation pipeline
make check     # Quick lint + type check
make test      # Full test suite with coverage
make security  # Security scanning
```

---

## 🔧 Development Tools

### IDE Setup

#### VS Code Configuration

```json
// .vscode/settings.json (suggested)
{
  "python.defaultInterpreterPath": ".venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.formatting.provider": "ruff",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests"],
  "mypy-type-checker.importStrategy": "fromEnvironment"
}
```

#### PyCharm Configuration

- **Interpreter**: Set to Poetry virtual environment
- **Code Style**: Configure for 79 character line length
- **Inspections**: Enable MyPy integration
- **Test Runner**: Configure for pytest

### Command Aliases

```bash
# Add to ~/.bashrc or ~/.zshrc
alias fa-test='make test'
alias fa-lint='make lint'
alias fa-validate='make validate'
alias fa-docker='docker-compose up -d'
alias fa-logs='docker-compose logs -f'
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Poetry Virtual Environment Issues

```bash
# Poetry not finding Python 3.13
poetry env use python3.13

# Virtual environment corrupted
poetry env remove python3.13
poetry install

# Dependencies not installing
poetry lock --no-update
poetry install --sync
```

#### 2. flext-core Import Issues

```bash
# Verify flext-core is accessible
cd ../flext-core && poetry install
cd ../flext-auth

# Check dependency paths
poetry show | grep flext-core
# Should show: flext-core @ file:///path/to/flext/flext-core
```

#### 3. Docker Issues

```bash
# Ports already in use
docker-compose down
sudo lsof -i :5432  # Check PostgreSQL port
sudo lsof -i :6379  # Check Redis port

# Permission issues
sudo usermod -aG docker $USER
newgrp docker
```

#### 4. Test Import Failures (Current)

```bash
# Known issue - see TODO.md
# Temporary workaround: focus on fixing imports
poetry run python -c "import flext_auth; print('Basic import works')"

# Check specific function availability
poetry run python -c "from flext_auth import FlextAuth; print('FlextAuth works')"
```

### Performance Issues

```bash
# Poetry too slow
poetry config virtualenvs.in-project true

# Docker too slow
docker system prune  # Clean up unused containers

# Test runs too slow
pytest -x  # Stop on first failure
pytest --lf  # Run only last failed
```

---

## 📚 Development Resources

### Documentation

- [Architecture Overview](../architecture/overview.md)
- [API Reference](../api/core.md)
- [Testing Guide](testing.md)
- [Contributing Guidelines](contributing.md)

### External Resources

- [flext-core Documentation](../../flext-core/docs/)
- [Clean Architecture Patterns](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Domain-Driven Design](https://martinfowler.com/bliki/DomainDrivenDesign.html)
- [CQRS Pattern](https://martinfowler.com/bliki/CQRS.html)

### Useful Commands Reference

```bash
# Project health
make doctor           # Complete health check
make diagnose         # Show diagnostics

# Development workflow
make setup           # Complete setup
make validate        # All quality gates
make test           # Run tests
make coverage-html  # Generate coverage report

# Docker management
docker-compose up -d postgres redis  # Start dependencies
docker-compose down                   # Stop all services
docker-compose logs -f               # Follow logs

# Git workflow
git checkout -b feature/name   # Create feature branch
git commit -m "Description"    # Commit changes
git push origin feature/name   # Push for review
```

---

**Development Status**: 🟡 **Partially Functional** - Basic setup works, quality gates fail  
**Expected Stable**: 2025-08-16 (Phase 1 completion)  
**Full Workflow**: 2025-09-13 (Phase 2 completion)

_This setup guide will be updated as critical issues are resolved and the development workflow stabilizes._
