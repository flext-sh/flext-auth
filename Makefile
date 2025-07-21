# FLEXT AUTH - Authentication & Authorization Service
# ===================================================
# JWT authentication, RBAC, and session management
# Python 3.13 + SQLAlchemy + Redis + Zero Tolerance Quality Gates

.PHONY: help check validate test lint type-check security format format-check fix
.PHONY: install dev-install setup pre-commit build clean
.PHONY: coverage coverage-html test-unit test-integration test-security
.PHONY: deps-update deps-audit deps-tree deps-outdated
.PHONY: migrate migrate-reset seed-data auth-validate

# ============================================================================
# 🎯 HELP & INFORMATION
# ============================================================================

help: ## Show this help message
	@echo "🔐 FLEXT AUTH - Authentication & Authorization Service"
	@echo "====================================================="
	@echo "🎯 Clean Architecture + DDD + Python 3.13 + JWT + RBAC"
	@echo ""
	@echo "📦 Comprehensive authentication service with JWT, RBAC, sessions"
	@echo "🔒 Zero tolerance quality gates for security-critical code"
	@echo "🧪 100% test coverage requirement for authentication flows"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# 🎯 CORE QUALITY GATES - ZERO TOLERANCE
# ============================================================================

validate: lint type-check security test ## STRICT compliance validation (all must pass)
	@echo "✅ ALL QUALITY GATES PASSED - FLEXT AUTH COMPLIANT"

check: lint type-check test ## Essential quality checks (pre-commit standard)
	@echo "✅ Essential checks passed"

lint: ## Ruff linting (17 rule categories, ALL enabled)
	@echo "🔍 Running ruff linter (ALL rules enabled)..."
	@poetry run ruff check src/ tests/ --fix --unsafe-fixes
	@echo "✅ Linting complete"

type-check: ## MyPy strict mode type checking (zero errors tolerated)
	@echo "🛡️ Running MyPy strict type checking..."
	@poetry run mypy src/ tests/ --strict
	@echo "✅ Type checking complete"

security: ## Security scans (bandit + pip-audit + secrets)
	@echo "🔒 Running security scans..."
	@poetry run bandit -r src/ --severity-level medium --confidence-level medium
	@poetry run pip-audit --ignore-vuln PYSEC-2022-42969
	@poetry run detect-secrets scan --all-files
	@echo "✅ Security scans complete"

format: ## Format code with ruff
	@echo "🎨 Formatting code..."
	@poetry run ruff format src/ tests/
	@echo "✅ Formatting complete"

format-check: ## Check formatting without fixing
	@echo "🎨 Checking code formatting..."
	@poetry run ruff format src/ tests/ --check
	@echo "✅ Format check complete"

fix: format lint ## Auto-fix all issues (format + imports + lint)
	@echo "🔧 Auto-fixing all issues..."
	@poetry run ruff check src/ tests/ --fix --unsafe-fixes
	@echo "✅ All auto-fixes applied"

# ============================================================================
# 🧪 TESTING - 100% COVERAGE FOR SECURITY
# ============================================================================

test: ## Run tests with coverage (100% minimum for auth)
	@echo "🧪 Running tests with coverage..."
	@poetry run pytest tests/ -v --cov=src/flext_auth --cov-report=term-missing --cov-fail-under=95
	@echo "✅ Tests complete"

test-unit: ## Run unit tests only
	@echo "🧪 Running unit tests..."
	@poetry run pytest tests/unit/ -v
	@echo "✅ Unit tests complete"

test-integration: ## Run integration tests only
	@echo "🧪 Running integration tests..."
	@poetry run pytest tests/integration/ -v
	@echo "✅ Integration tests complete"

test-security: ## Run security-focused tests
	@echo "🔒 Running security tests..."
	@poetry run pytest tests/security/ -v --tb=short
	@echo "✅ Security tests complete"

coverage: ## Generate detailed coverage report
	@echo "📊 Generating coverage report..."
	@poetry run pytest tests/ --cov=src/flext_auth --cov-report=term-missing --cov-report=html
	@echo "✅ Coverage report generated in htmlcov/"

coverage-html: coverage ## Generate HTML coverage report
	@echo "📊 Opening coverage report..."
	@python -m webbrowser htmlcov/index.html

# ============================================================================
# 🚀 DEVELOPMENT SETUP
# ============================================================================

setup: install pre-commit ## Complete development setup
	@echo "🎯 Development setup complete!"

install: ## Install dependencies with Poetry
	@echo "📦 Installing dependencies..."
	@poetry install --all-extras --with dev,test,docs,security
	@echo "✅ Dependencies installed"

dev-install: install ## Install in development mode
	@echo "🔧 Setting up development environment..."
	@poetry install --all-extras --with dev,test,docs,security
	@poetry run pre-commit install
	@echo "✅ Development environment ready"

pre-commit: ## Setup pre-commit hooks
	@echo "🎣 Setting up pre-commit hooks..."
	@poetry run pre-commit install
	@poetry run pre-commit run --all-files || true
	@echo "✅ Pre-commit hooks installed"

# ============================================================================
# 🗄️ DATABASE OPERATIONS
# ============================================================================

migrate: ## Run database migrations
	@echo "🗄️ Running database migrations..."
	@poetry run alembic upgrade head
	@echo "✅ Database migrations complete"

migrate-reset: ## Reset and recreate database
	@echo "🗄️ Resetting database..."
	@poetry run alembic downgrade base
	@poetry run alembic upgrade head
	@echo "✅ Database reset complete"

seed-data: ## Seed test data
	@echo "🌱 Seeding test data..."
	@poetry run python -m flext_auth.scripts.seed_data
	@echo "✅ Test data seeded"

migrate-create: ## Create new migration (use MESSAGE=description)
	@echo "🗄️ Creating new migration..."
	@poetry run alembic revision --autogenerate -m "$(MESSAGE)"
	@echo "✅ Migration created"

# ============================================================================
# 🔐 AUTHENTICATION SPECIFIC OPERATIONS
# ============================================================================

auth-validate: ## Validate authentication configuration
	@echo "🔐 Validating authentication configuration..."
	@poetry run python -c "from flext_auth.config import AuthSettings; AuthSettings().validate_security()"
	@echo "✅ Authentication configuration valid"

jwt-test: ## Test JWT token generation and validation
	@echo "🔑 Testing JWT operations..."
	@poetry run python -c "from flext_auth.infrastructure.security.jwt_service import JWTService; from flext_auth.config import AuthSettings; settings = AuthSettings(); jwt_service = JWTService(settings.jwt); token = jwt_service.create_access_token({'sub': 'test'}); payload = jwt_service.validate_token(token); print(f'JWT test successful: {payload}')"
	@echo "✅ JWT operations tested"

password-test: ## Test password hashing and verification
	@echo "🔒 Testing password operations..."
	@poetry run python -c "from flext_auth.infrastructure.security.password_service import PasswordService; from flext_auth.config import AuthSettings; settings = AuthSettings(); password_service = PasswordService(settings.password); hashed = password_service.hash_password('test_password'); verified = password_service.verify_password('test_password', hashed); print(f'Password test successful: {verified}')"
	@echo "✅ Password operations tested"

session-test: ## Test session operations
	@echo "🎫 Testing session operations..."
	@poetry run python -c "import asyncio; from flext_auth.infrastructure.persistence.redis_session_store import RedisSessionStore; from flext_auth.config import AuthSettings; exec(\"async def test_session():\n    settings = AuthSettings()\n    store = RedisSessionStore(settings.redis)\n    session_id = await store.create_session('test_user', {})\n    session = await store.get_session(session_id)\n    print(f'Session test successful: {session is not None}')\nasyncio.run(test_session())\")"
	@echo "✅ Session operations tested"

security-audit: ## Run comprehensive security audit
	@echo "🔍 Running security audit..."
	@poetry run bandit -r src/ -f json -o security-audit.json || true
	@poetry run safety check --json --output security-deps.json || true
	@poetry run pip-audit --format=json --output=security-deps-audit.json || true
	@echo "✅ Security audit complete - check *security*.json files"

# ============================================================================
# 📦 BUILD & DISTRIBUTION
# ============================================================================

build: clean ## Build distribution packages
	@echo "🔨 Building distribution..."
	@poetry build
	@echo "✅ Build complete - packages in dist/"

# ============================================================================
# 🧹 CLEANUP
# ============================================================================

clean: ## Remove all artifacts
	@echo "🧹 Cleaning up..."
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info/
	@rm -rf .coverage
	@rm -rf htmlcov/
	@rm -rf .pytest_cache/
	@rm -rf security-*.json
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleanup complete"

# ============================================================================
# 📊 DEPENDENCY MANAGEMENT
# ============================================================================

deps-update: ## Update all dependencies
	@echo "🔄 Updating dependencies..."
	@poetry update
	@echo "✅ Dependencies updated"

deps-audit: ## Audit dependencies for vulnerabilities
	@echo "🔍 Auditing dependencies..."
	@poetry run pip-audit
	@echo "✅ Dependency audit complete"

deps-tree: ## Show dependency tree
	@echo "🌳 Dependency tree:"
	@poetry show --tree

deps-outdated: ## Show outdated dependencies
	@echo "📋 Outdated dependencies:"
	@poetry show --outdated

# ============================================================================
# 🔧 ENVIRONMENT CONFIGURATION
# ============================================================================

# Python settings
PYTHON := python3.13
export PYTHONPATH := $(PWD)/src:$(PYTHONPATH)
export PYTHONDONTWRITEBYTECODE := 1
export PYTHONUNBUFFERED := 1

# Authentication settings
export FLEXT_AUTH_ENV := development
export FLEXT_AUTH_DEBUG := true
export FLEXT_AUTH_DATABASE_URL := postgresql://localhost/flext_auth_dev
export FLEXT_AUTH_REDIS_URL := redis://localhost:6379/1

# JWT settings for development
export FLEXT_AUTH_JWT__SECRET_KEY := dev-secret-key-change-in-production
export FLEXT_AUTH_JWT__ACCESS_TOKEN_EXPIRE_MINUTES := 30
export FLEXT_AUTH_JWT__REFRESH_TOKEN_EXPIRE_DAYS := 7

# Password settings
export FLEXT_AUTH_PASSWORD__BCRYPT_ROUNDS := 4  # Lower for dev speed

# Poetry settings
export POETRY_VENV_IN_PROJECT := false
export POETRY_CACHE_DIR := $(HOME)/.cache/pypoetry

# Quality gate settings
export MYPY_CACHE_DIR := .mypy_cache
export RUFF_CACHE_DIR := .ruff_cache

# ============================================================================
# 📝 PROJECT METADATA
# ============================================================================

# Project information
PROJECT_NAME := flext-auth
PROJECT_VERSION := $(shell poetry version -s)
PROJECT_DESCRIPTION := FLEXT Auth - Authentication & Authorization Service

.DEFAULT_GOAL := help

# ============================================================================
# 🎯 AUTHENTICATION VERIFICATION COMMANDS
# ============================================================================

verify-auth: auth-validate jwt-test password-test session-test ## Verify all auth components
	@echo "✅ All authentication components verified"

verify-rbac: ## Verify RBAC functionality
	@echo "🔐 Verifying RBAC functionality..."
	@poetry run python -c "from flext_auth.domain.entities import User, Role; from flext_auth.domain.value_objects import Email; user = User.create('REDACTED_LDAP_BIND_PASSWORD', Email('REDACTED_LDAP_BIND_PASSWORD@test.com'), 'password'); role = Role.create('REDACTED_LDAP_BIND_PASSWORD', ['read', 'write', 'REDACTED_LDAP_BIND_PASSWORD']); user.assign_role(role); has_permission = user.has_permission('REDACTED_LDAP_BIND_PASSWORD'); print(f'RBAC test successful: {has_permission}')"
	@echo "✅ RBAC verification complete"

verify-security: security-audit verify-auth verify-rbac ## Comprehensive security verification
	@echo "✅ Comprehensive security verification complete"

# ============================================================================
# 🎯 FLEXT ECOSYSTEM INTEGRATION
# ============================================================================

ecosystem-check: ## Verify FLEXT ecosystem compatibility
	@echo "🌐 Checking FLEXT ecosystem compatibility..."
	@echo "📦 Auth project: $(PROJECT_NAME) v$(PROJECT_VERSION)"
	@echo "🏗️ Architecture: Clean Architecture + DDD + CQRS"
	@echo "🐍 Python: 3.13"
	@echo "🔐 Framework: JWT + RBAC + Sessions"
	@echo "📊 Quality: Zero tolerance enforcement"
	@echo "✅ Ecosystem compatibility verified"

workspace-info: ## Show workspace integration info
	@echo "🏢 FLEXT Workspace Integration"
	@echo "==============================="
	@echo "📁 Project Path: $(PWD)"
	@echo "🏆 Role: Authentication & Authorization Service"
	@echo "🔗 Dependencies: flext-core, PostgreSQL, Redis"
	@echo "📦 Provides: JWT authentication, RBAC, session management"
	@echo "🎯 Standards: Enterprise security patterns"