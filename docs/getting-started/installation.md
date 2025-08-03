# Installation Guide

**Installing FLEXT Auth for Development and Production**

> **⚠️ Current Status**: FLEXT Auth is in beta with critical issues. This guide will be fully functional after Phase 1 completion (estimated 2025-08-16).

---

## 🚨 Prerequisites

### System Requirements

- **Python**: 3.13+ (no backward compatibility)
- **Operating System**: Linux, macOS, or Windows with WSL2
- **Memory**: Minimum 4GB RAM, 8GB recommended
- **Storage**: 2GB free space for dependencies and development tools

### Required Dependencies

- **Poetry**: For dependency management
- **Docker**: For development services (PostgreSQL, Redis)
- **Git**: For version control and flext-core integration

---

## 🔧 Development Installation

### 1. Clone Repository

```bash
# Clone the repository
git clone https://github.com/flext-sh/flext.git
cd flext/flext-auth

# Or if working with the full ecosystem
git clone https://github.com/flext-sh/flext.git
cd flext
```

### 2. Install Poetry (if not installed)

```bash
# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Add to PATH (follow installer instructions)
export PATH="$HOME/.local/bin:$PATH"

# Verify installation
poetry --version
```

### 3. Setup Development Environment

#### Current Workflow (With Known Issues)

```bash
# Install dependencies (may have issues)
poetry install

# Try to setup development environment (will fail)
make setup  # Currently fails due to test issues

# Workaround: Install dependencies manually
poetry install --with dev,test,docs
```

#### Future Workflow (Post-Fixes)

```bash
# Complete development setup
make setup                  # Install deps + pre-commit hooks
make validate              # Verify all quality gates pass
make test                  # Run test suite (95% coverage)
```

### 4. Local Dependencies Setup

FLEXT Auth depends on local flext-core and flext-observability:

```bash
# Ensure flext-core is available
ls ../flext-core  # Should exist in sibling directory

# Verify dependencies
poetry show | grep flext-core
poetry show | grep flext-observability
```

---

## 📦 Production Installation

> **⚠️ Warning**: Not recommended for production until critical issues are resolved.

### PyPI Installation (Future)

```bash
# Will be available after 1.0.0 release
pip install flext-auth

# With specific version
pip install flext-auth==1.0.0
```

### Requirements.txt Installation (Future)

```bash
# Add to requirements.txt
echo "flext-auth>=1.0.0" >> requirements.txt
pip install -r requirements.txt
```

### Poetry Installation (Future)

```bash
# Add to pyproject.toml
poetry add flext-auth

# With version constraint
poetry add "flext-auth>=1.0.0,<2.0.0"
```

---

## 🐳 Docker Installation

### Development with Docker Compose

```bash
# Start development services
docker-compose up -d postgres redis

# View services
docker-compose ps

# Access logs
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Full Application Stack (Future)

```bash
# Start complete stack
docker-compose up -d

# Includes:
# - PostgreSQL (port 5432)
# - Redis (port 6379)
# - FLEXT Auth API (port 8000)
```

### Production Docker (Future)

```bash
# Build production image
docker build -t flext-auth:latest .

# Run with environment variables
docker run -d \
  -p 8000:8000 \
  -e FLEXT_AUTH_JWT_SECRET_KEY="your-production-secret" \
  -e DATABASE_URL="postgresql://..." \
  flext-auth:latest
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Required for production
export FLEXT_AUTH_JWT_SECRET_KEY="your-32-char-secret-key-here"
export DATABASE_URL="postgresql://user:pass@localhost:5432/flext_auth"
export REDIS_URL="redis://localhost:6379/0"

# Optional configuration
export FLEXT_AUTH_DEBUG="false"
export FLEXT_AUTH_ENVIRONMENT="production"
export FLEXT_AUTH_LOG_LEVEL="INFO"
```

### Development Configuration

```bash
# Copy example environment file (when available)
cp .env.example .env

# Edit configuration
vim .env
```

### Configuration Files

```python
# config/development.py (future)
from flext_auth.config import FlextAuthConfig

config = FlextAuthConfig(
    debug=True,
    jwt_secret_key="dev-secret-key",
    database_url="postgresql://localhost:5432/flext_auth_dev"
)
```

---

## ✅ Verification

### Current Verification (With Issues)

```bash
# Check installation (will show issues)
poetry run python -c "import flext_auth; print('Imported successfully')"

# Try to run tests (currently failing)
make test  # Will show 13 test failures

# Check quality gates (currently failing)
make validate  # Will show 23 linting errors
```

### Future Verification (Post-Fixes)

```bash
# Verify installation
poetry run python -c "from flext_auth import flext_auth_quick_start; print('Installation successful')"

# Run health checks
make doctor  # Complete health check

# Verify all quality gates
make validate  # Should pass all checks

# Test basic functionality
poetry run python -c "
from flext_auth import FlextAuth
auth = FlextAuth()
print('FLEXT Auth ready!')
"
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Poetry Installation Fails

```bash
# Error: Cannot find Poetry
solution: Install Poetry using official installer
curl -sSL https://install.python-poetry.org | python3 -

# Error: Poetry not in PATH
solution: Add to shell profile
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### 2. flext-core Dependency Issues

```bash
# Error: Cannot find flext-core
solution: Ensure flext-core is in sibling directory
ls ../flext-core  # Should exist

# Error: flext-core import fails
solution: Install flext-core dependencies
cd ../flext-core && poetry install
```

#### 3. Test Import Failures (Current Issue)

```bash
# Error: ImportError in tests
status: Known issue - see docs/TODO.md
solution: Wait for Phase 1 completion or help fix issues
timeline: Expected resolution by 2025-08-16
```

#### 4. Docker Issues

```bash
# Error: PostgreSQL connection refused
solution: Ensure Docker is running
docker-compose up -d postgres

# Error: Port already in use
solution: Stop conflicting services
docker-compose down
sudo lsof -i :5432  # Find conflicting process
```

### Getting Help

1. **Check [TODO.md](../TODO.md)** for known issues
2. **Review error logs** for specific error messages
3. **Create GitHub issue** with error details
4. **Check ecosystem status** for related issues

---

## 🚀 Next Steps

### After Installation

1. **Read [Quick Start Guide](quickstart.md)** for basic usage
2. **Review [Configuration Guide](configuration.md)** for setup
3. **Check [Development Guide](../development/setup.md)** for development workflow
4. **Follow [TODO.md](../TODO.md)** for current project status

### Development Workflow

1. **Setup pre-commit hooks**: `pre-commit install`
2. **Run quality gates**: `make validate`
3. **Create feature branch**: `git checkout -b feature/your-feature`
4. **Make changes and test**: `make test`
5. **Submit pull request**: Following contribution guidelines

---

**Installation Status**: 🟡 **Partial** - Basic installation works, but quality gates fail  
**Expected Stable**: 2025-08-16 (Phase 1 completion)  
**Production Ready**: 2025-10-25 (1.0.0 release)

_This guide will be updated as critical issues are resolved and the installation process stabilizes._
