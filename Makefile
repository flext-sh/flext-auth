# =============================================================================
# FLEXT-AUTH - PROJECT MAKEFILE
# =============================================================================
# Enterprise Authentication & Authorization Service with Clean Architecture + DDD + Zero Tolerance Quality
# Python 3.13 + JWT + RBAC + Sessions + Modern Security
# =============================================================================

# Project Configuration
PROJECT_NAME := flext-auth
PROJECT_TYPE := auth-service
PYTHON_VERSION := 3.13
POETRY := poetry
SRC_DIR := src
TESTS_DIR := tests
DOCS_DIR := docs

# Quality Gates Configuration
MIN_COVERAGE := 95
MYPY_STRICT := true
RUFF_CONFIG := pyproject.toml
PEP8_LINE_LENGTH := 79

# Authentication Configuration
AUTH_ENV := development
AUTH_DEBUG := true
JWT_EXPIRE_MINUTES := 30
JWT_REFRESH_DAYS := 7

# Export environment variables
export PYTHON_VERSION
export MIN_COVERAGE
export MYPY_STRICT
export AUTH_ENV
export AUTH_DEBUG

# =============================================================================
# HELP & INFORMATION
# =============================================================================

.PHONY: help
help: ## Show available commands
	@echo "$(PROJECT_NAME) - Authentication & Authorization Service"
	@echo "======================================================="
	@echo ""
	@echo "📋 AVAILABLE COMMANDS:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-18s %s\\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "🔧 PROJECT INFO:"
	@echo "  Type: $(PROJECT_TYPE)"
	@echo "  Python: $(PYTHON_VERSION)"
	@echo "  Coverage: $(MIN_COVERAGE)%"
	@echo "  Environment: $(AUTH_ENV)"
	@echo "  Line Length: $(PEP8_LINE_LENGTH)"

.PHONY: info
info: ## Show project information
	@echo "Project Information"
	@echo "=================="
	@echo "Name: $(PROJECT_NAME)"
	@echo "Type: $(PROJECT_TYPE)"
	@echo "Python Version: $(PYTHON_VERSION)"
	@echo "Source Directory: $(SRC_DIR)"
	@echo "Tests Directory: $(TESTS_DIR)"
	@echo "Environment: $(AUTH_ENV)"
	@echo "JWT Token Expiry: $(JWT_EXPIRE_MINUTES) minutes"
	@echo "Refresh Token Expiry: $(JWT_REFRESH_DAYS) days"
	@echo "Quality Standards: Zero Tolerance"
	@echo "Architecture: Clean Architecture + DDD + JWT + RBAC"

# =============================================================================
# INSTALLATION & SETUP
# =============================================================================

.PHONY: install
install: ## Install project dependencies
	@echo "📦 Installing $(PROJECT_NAME) dependencies..."
	@$(POETRY) install

.PHONY: install-dev
install-dev: ## Install development dependencies
	@echo "📦 Installing development dependencies..."
	@$(POETRY) install --with dev,test,docs,security

.PHONY: setup
setup: ## Complete project setup
	@echo "🚀 Setting up $(PROJECT_NAME)..."
	@make install-dev
	@make pre-commit-install
	@make migrate
	@echo "✅ Setup complete"

.PHONY: pre-commit-install
pre-commit-install: ## Install pre-commit hooks
	@echo "🔧 Installing pre-commit hooks..."
	@$(POETRY) run pre-commit install
	@$(POETRY) run pre-commit autoupdate

# =============================================================================
# QUALITY GATES & VALIDATION
# =============================================================================

.PHONY: validate
validate: ## Run complete validation (quality gate)
	@echo "🔍 Running complete validation for $(PROJECT_NAME)..."
	@make lint
	@make type-check
	@make security
	@make test
	@make pep8-check
	@make auth-validate
	@echo "✅ Validation complete"

.PHONY: check
check: ## Quick health check
	@echo "🏥 Running health check..."
	@make lint
	@make type-check
	@echo "✅ Health check complete"

.PHONY: lint
lint: ## Run code linting
	@echo "🧹 Running linting..."
	@$(POETRY) run ruff check $(SRC_DIR) $(TESTS_DIR)

.PHONY: format
format: ## Format code
	@echo "🎨 Formatting code..."
	@$(POETRY) run ruff format $(SRC_DIR) $(TESTS_DIR)

.PHONY: format-check
format-check: ## Check code formatting
	@echo "🎨 Checking code formatting..."
	@$(POETRY) run ruff format --check $(SRC_DIR) $(TESTS_DIR)

.PHONY: type-check
type-check: ## Run type checking
	@echo "🔍 Running type checking..."
	@$(POETRY) run mypy $(SRC_DIR) --strict

.PHONY: security
security: ## Run security scanning
	@echo "🔒 Running security scanning..."
	@$(POETRY) run bandit -r $(SRC_DIR) --severity-level medium --confidence-level medium
	@$(POETRY) run pip-audit
	@$(POETRY) run detect-secrets scan --all-files

.PHONY: pep8-check
pep8-check: ## Check PEP8 compliance
	@echo "📏 Checking PEP8 compliance..."
	@$(POETRY) run ruff check $(SRC_DIR) $(TESTS_DIR) --select E,W
	@echo "✅ PEP8 check complete"

.PHONY: fix
fix: ## Auto-fix code issues
	@echo "🔧 Auto-fixing code issues..."
	@$(POETRY) run ruff check $(SRC_DIR) $(TESTS_DIR) --fix
	@make format

# =============================================================================
# TESTING
# =============================================================================

.PHONY: test
test: ## Run all tests with coverage
	@echo "🧪 Running tests with coverage..."
	@$(POETRY) run pytest $(TESTS_DIR) --cov=$(SRC_DIR) --cov-report=term-missing --cov-fail-under=$(MIN_COVERAGE)

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "🧪 Running unit tests..."
	@$(POETRY) run pytest $(TESTS_DIR)/unit/ -v

.PHONY: test-integration
test-integration: ## Run integration tests only
	@echo "🧪 Running integration tests..."
	@$(POETRY) run pytest $(TESTS_DIR)/integration/ -v

.PHONY: test-security
test-security: ## Run security-focused tests
	@echo "🔒 Running security tests..."
	@$(POETRY) run pytest $(TESTS_DIR)/security/ -v --tb=short

.PHONY: test-fast
test-fast: ## Run tests without coverage
	@echo "🧪 Running fast tests..."
	@$(POETRY) run pytest $(TESTS_DIR) -v

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	@echo "🧪 Running tests in watch mode..."
	@$(POETRY) run pytest-watch $(TESTS_DIR)

.PHONY: coverage
coverage: ## Generate coverage report
	@echo "📊 Generating coverage report..."
	@$(POETRY) run pytest $(TESTS_DIR) --cov=$(SRC_DIR) --cov-report=html --cov-report=xml

.PHONY: coverage-html
coverage-html: ## Generate HTML coverage report
	@echo "📊 Generating HTML coverage report..."
	@$(POETRY) run pytest $(TESTS_DIR) --cov=$(SRC_DIR) --cov-report=html
	@echo "📊 Coverage report: htmlcov/index.html"

# =============================================================================
# DATABASE OPERATIONS
# =============================================================================

.PHONY: migrate
migrate: ## Run database migrations
	@echo "🗄️ Running database migrations..."
	@$(POETRY) run alembic upgrade head

.PHONY: migrate-reset
migrate-reset: ## Reset and recreate database
	@echo "🗄️ Resetting database..."
	@$(POETRY) run alembic downgrade base
	@$(POETRY) run alembic upgrade head

.PHONY: migrate-create
migrate-create: ## Create new migration (use MESSAGE=description)
	@echo "🗄️ Creating new migration..."
	@$(POETRY) run alembic revision --autogenerate -m "$(MESSAGE)"

.PHONY: seed-data
seed-data: ## Seed test data
	@echo "🌱 Seeding test data..."
	@$(POETRY) run python -m flext_auth.scripts.seed_data

# =============================================================================
# AUTHENTICATION OPERATIONS
# =============================================================================

.PHONY: auth-validate
auth-validate: ## Validate authentication configuration
	@echo "🔐 Validating authentication configuration..."
	@$(POETRY) run python -c "from flext_auth.config import AuthSettings; AuthSettings().validate_security()"

.PHONY: jwt-test
jwt-test: ## Test JWT token generation and validation
	@echo "🔑 Testing JWT operations..."
	@$(POETRY) run python -c "from flext_auth.infrastructure.security.jwt_service import JWTService; from flext_auth.config import AuthSettings; settings = AuthSettings(); jwt_service = JWTService(settings.jwt); token = jwt_service.create_access_token({'sub': 'test'}); payload = jwt_service.validate_token(token); print(f'JWT test successful: {payload}')"

.PHONY: password-test
password-test: ## Test password hashing and verification
	@echo "🔒 Testing password operations..."
	@$(POETRY) run python -c "from flext_auth.infrastructure.security.password_service import PasswordService; from flext_auth.config import AuthSettings; settings = AuthSettings(); password_service = PasswordService(settings.password); hashed = password_service.hash_password('test_password'); verified = password_service.verify_password('test_password', hashed); print(f'Password test successful: {verified}')"

.PHONY: session-test
session-test: ## Test session operations
	@echo "🎫 Testing session operations..."
	@$(POETRY) run python -c "import asyncio; exec(\"async def test_session():\\n    from flext_auth.infrastructure.persistence.redis_session_store import RedisSessionStore\\n    from flext_auth.config import AuthSettings\\n    settings = AuthSettings()\\n    store = RedisSessionStore(settings.redis)\\n    session_id = await store.create_session('test_user', {})\\n    session = await store.get_session(session_id)\\n    print(f'Session test successful: {session is not None}')\\nasyncio.run(test_session())\")"

.PHONY: verify-auth
verify-auth: ## Verify all authentication components
	@echo "🔐 Verifying all authentication components..."
	@make auth-validate
	@make jwt-test
	@make password-test
	@make session-test
	@echo "✅ All authentication components verified"

.PHONY: verify-rbac
verify-rbac: ## Verify RBAC functionality
	@echo "🔐 Verifying RBAC functionality..."
	@$(POETRY) run python -c "from flext_auth.domain.entities import User, Role; from flext_auth.domain.value_objects import Email; user = User.create('REDACTED_LDAP_BIND_PASSWORD', Email('REDACTED_LDAP_BIND_PASSWORD@test.com'), 'password'); role = Role.create('REDACTED_LDAP_BIND_PASSWORD', ['read', 'write', 'REDACTED_LDAP_BIND_PASSWORD']); user.assign_role(role); has_permission = user.has_permission('REDACTED_LDAP_BIND_PASSWORD'); print(f'RBAC test successful: {has_permission}')"

.PHONY: security-audit
security-audit: ## Run comprehensive security audit
	@echo "🔍 Running security audit..."
	@$(POETRY) run bandit -r $(SRC_DIR) -f json -o security-audit.json || true
	@$(POETRY) run safety check --json --output security-deps.json || true
	@$(POETRY) run pip-audit --format=json --output=security-deps-audit.json || true
	@echo "✅ Security audit complete - check *security*.json files"

# =============================================================================
# BUILD & DISTRIBUTION
# =============================================================================

.PHONY: build
build: ## Build distribution packages
	@echo "🏗️ Building $(PROJECT_NAME)..."
	@$(POETRY) build

.PHONY: build-clean
build-clean: ## Clean build and rebuild
	@echo "🏗️ Clean build..."
	@make clean
	@make build

.PHONY: publish-test
publish-test: ## Publish to test PyPI
	@echo "📦 Publishing to test PyPI..."
	@$(POETRY) publish --repository testpypi

.PHONY: publish
publish: ## Publish to PyPI
	@echo "📦 Publishing to PyPI..."
	@$(POETRY) publish

# =============================================================================
# DOCUMENTATION
# =============================================================================

.PHONY: docs
docs: ## Build documentation
	@echo "📚 Building documentation..."
	@$(POETRY) run mkdocs build

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	@echo "📚 Serving documentation..."
	@$(POETRY) run mkdocs serve

.PHONY: docs-deploy
docs-deploy: ## Deploy documentation
	@echo "📚 Deploying documentation..."
	@$(POETRY) run mkdocs gh-deploy

# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "🔄 Updating dependencies..."
	@$(POETRY) update

.PHONY: deps-show
deps-show: ## Show dependency tree
	@echo "📋 Showing dependency tree..."
	@$(POETRY) show --tree

.PHONY: deps-audit
deps-audit: ## Audit dependencies for security
	@echo "🔍 Auditing dependencies..."
	@$(POETRY) run pip-audit

.PHONY: deps-export
deps-export: ## Export requirements.txt
	@echo "📄 Exporting requirements..."
	@$(POETRY) export -f requirements.txt --output requirements.txt
	@$(POETRY) export -f requirements.txt --dev --output requirements-dev.txt

# =============================================================================
# DEVELOPMENT TOOLS
# =============================================================================

.PHONY: shell
shell: ## Open Python shell with project loaded
	@echo "🐍 Opening Python shell..."
	@$(POETRY) run python

.PHONY: notebook
notebook: ## Start Jupyter notebook
	@echo "📓 Starting Jupyter notebook..."
	@$(POETRY) run jupyter lab

.PHONY: pre-commit
pre-commit: ## Run pre-commit hooks
	@echo "🔍 Running pre-commit hooks..."
	@$(POETRY) run pre-commit run --all-files

# =============================================================================
# MAINTENANCE & CLEANUP
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts and cache
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf build/
	@rm -rf dist/
	@rm -rf *.egg-info/
	@rm -rf .pytest_cache/
	@rm -rf htmlcov/
	@rm -rf .coverage
	@rm -rf .mypy_cache/
	@rm -rf .ruff_cache/
	@rm -rf security-*.json
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true

.PHONY: clean-all
clean-all: clean ## Deep clean including virtual environment
	@echo "🧹 Deep cleaning..."
	@rm -rf .venv/

.PHONY: reset
reset: clean-all ## Reset project to clean state
	@echo "🔄 Resetting project..."
	@make setup

# =============================================================================
# DIAGNOSTICS & TROUBLESHOOTING
# =============================================================================

.PHONY: diagnose
diagnose: ## Run project diagnostics
	@echo "🔬 Running project diagnostics..."
	@echo "Python version: $$(python --version)"
	@echo "Poetry version: $$($(POETRY) --version)"
	@echo "Authentication service status: $(PROJECT_NAME)"
	@echo "Project info:"
	@$(POETRY) show --no-dev
	@echo "Environment status:"
	@$(POETRY) env info

.PHONY: doctor
doctor: ## Check project health
	@echo "👩‍⚕️ Checking project health..."
	@make diagnose
	@make check
	@echo "✅ Health check complete"

# =============================================================================
# CONVENIENCE ALIASES
# =============================================================================

.PHONY: t
t: test ## Alias for test

.PHONY: l
l: lint ## Alias for lint

.PHONY: f
f: format ## Alias for format

.PHONY: tc
tc: type-check ## Alias for type-check

.PHONY: c
c: clean ## Alias for clean

.PHONY: i
i: install ## Alias for install

.PHONY: v
v: validate ## Alias for validate

.PHONY: av
av: auth-validate ## Alias for auth-validate

.PHONY: va
va: verify-auth ## Alias for verify-auth

# =============================================================================
# Default target
# =============================================================================

.DEFAULT_GOAL := help