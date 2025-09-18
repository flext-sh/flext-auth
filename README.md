# flext-auth

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Development Status](https://img.shields.io/badge/status-v0.9.9--dev-yellow.svg)](#current-status)
[![Test Coverage](https://img.shields.io/badge/coverage-mixed-orange.svg)](#testing)

**Authentication and authorization library** for the FLEXT ecosystem, providing **JWT tokens and session management** using **FLEXT architectural patterns**.

> **⚠️ STATUS**: Development version (v0.9.9) - 611 tests passing, 17 failed, 88 errors. Significant work needed for production readiness.

---

## 🎯 Purpose and Role in FLEXT Ecosystem

### **For the FLEXT Ecosystem**

flext-auth provides authentication services for FLEXT ecosystem projects, implementing JWT tokens, bcrypt password hashing, and session management while integrating with flext-core foundation patterns.

### **Key Responsibilities**

1. **User Authentication** - Username/password authentication with bcrypt hashing
2. **JWT Token Management** - Token generation, validation, and lifecycle management
3. **Session Management** - User session creation and validation with expiration
4. **Authorization Support** - Role-based access control foundation
5. **FLEXT Integration** - Uses FlextResult, FlextContainer, FlextModels patterns

### **Integration Points**

- **[flext-core](../flext-core/README.md)** → Foundation patterns (FlextResult, FlextContainer, FlextModels)
- **[flext-api](../flext-api/README.md)** → Authentication middleware for REST APIs
- **[flext-web](../flext-web/README.md)** → Web application authentication flows
- **All FLEXT Projects** → Authentication service provider for ecosystem

---

## 🏗️ Architecture and Patterns

### **FLEXT-Core Integration Status**

| Pattern             | Status | Description                                          |
| ------------------- | ------ | ---------------------------------------------------- |
| **FlextResult<T>**  | 🟢 95% | All auth operations return FlextResult               |
| **FlextService**    | 🟡 75% | Main FlextAuth service with DI                       |
| **FlextContainer**  | 🟢 90% | Dependency injection throughout                      |
| **Domain Patterns** | 🟢 85% | User, Session, Role entities with FlextModels.Entity |

> **Status**: 🔴 Critical · 1.0.0 Release Preparation | 🟡 Partial | 🟢 Complete

### **Implementation Scale**

```
src/flext_auth/ (2,169 lines total)
├── config.py           # FlextAuthConfig settings (681 lines)
├── auth.py             # FlextAuth service (555 lines)
├── models.py           # Domain models (498 lines)
├── cli.py             # Click CLI interface (262 lines)
├── constants.py       # Authentication constants (71 lines)
├── __init__.py        # API exports (46 lines)
├── quickstart.py      # Development utilities (45 lines)
└── __version__.py     # Version info (11 lines)
```

---

## 🚀 Quick Start

### **Installation**

```bash
cd flext-auth
poetry install
```

### **Basic Usage**

```python
from flext_auth import flext_auth_quick_start, FlextAuthModels

# Initialize authentication service
auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

# Create user request
user_request = FlextAuthModels.UserCreationRequest(
    username="demo",
    email="demo@example.com",
    password="secure123"
)

# Register user (returns FlextResult)
result = auth.register_user(
    username=user_request.username,
    email=user_request.email,
    password=user_request.password
)

if result.is_success:
    user = result.unwrap()
    print(f"User created: {user.username}")

    # Authenticate user
    auth_result = auth.authenticate_user("demo", "secure123")
    if auth_result.is_success:
        session_data = auth_result.unwrap()
        print("Authentication successful")
```

---

## 🔧 Development

### **Essential Commands**

```bash
make setup           # Development environment setup
make validate        # Complete validation (lint + type + test)
make test           # Run test suite (184 pass, 66 fail)
make lint           # Ruff code linting
make type-check     # MyPy type checking
make format         # Code formatting
```

### **Quality Gates**

- **Test Coverage**: 83% current (targeting 85%+)
- **Type Safety**: MyPy strict mode in progress
- **Security**: bcrypt + JWT token security
- **FLEXT-Core Compliance**: 85% integration

---

## 🧪 Testing

### **Test Structure**

- **Unit Tests**: Core authentication logic
- **Integration Tests**: Real authentication workflows
- **Security Tests**: Password hashing and token validation

### **Testing Commands**

```bash
make test                    # Full test suite
pytest tests/unit/          # Unit tests only
pytest -m auth              # Authentication tests
pytest --cov=src/flext_auth # Coverage report
```

### **Current Test Status** (September 17, 2025)

- **Total Collected**: 720 tests
- **Passing**: 611 tests (85%)
- **Failing**: 17 tests (2%)
- **Errors**: 88 tests (12%)
- **Skipped**: 4 tests (1%)
- **Primary Issues**: Test infrastructure, CLI integration, and configuration management

---

## 📊 Status and Metrics

### **Quality Standards** (September 17, 2025)

- **Test Pass Rate**: 85% passing (611/720), 12% errors need investigation
- **Type Safety**: MyPy and PyRight mostly clean, some remaining issues
- **Security**: bcrypt password hashing implemented, JWT token system functional
- **FLEXT-Core Compliance**: Strong integration with flext-core patterns (FlextResult, FlextContainer)

### **Current Capabilities**

- ✅ **User Registration**: Username/email validation, password hashing
- ✅ **Authentication**: bcrypt password verification
- ✅ **JWT Tokens**: Generation and validation
- ✅ **Session Management**: In-memory sessions with expiration
- ✅ **CLI Interface**: User management commands
- ✅ **Configuration**: Environment-specific settings

### **Development Areas**

- ⚠️ **Test Infrastructure**: Address 88 test errors (12% error rate) affecting reliability
- ⚠️ **Production Readiness**: Stabilize remaining 17 failing tests for production deployment
- ⚠️ **Modern Authentication (2025)**: WebAuthn/FIDO2 passwordless, OAuth2/OIDC integration
- ⚠️ **Enterprise Features**: Database persistence, Redis session storage, MFA/2FA
- ⚠️ **Security Hardening**: Account lockout policies, comprehensive audit logging

### **Ecosystem Integration**

- **Direct Dependencies**: **[flext-core](../flext-core/README.md)** (foundation patterns)
- **Service Dependencies**: Future integration with **[flext-db-oracle](../flext-db-oracle/README.md)**, **[flext-ldap](../flext-ldap/README.md)**
- **Integration Points**: Authentication provider for FLEXT ecosystem

---

## 🗺️ Roadmap

### **Current Version (v0.9.9)**

- Development version with core authentication working
- Test stabilization and quality improvements needed
- FLEXT-core integration patterns established

### **Next Version (v1.0.0)**

- Address 88 test errors and stabilize test infrastructure
- Fix remaining 17 failing tests to achieve production readiness
- Complete security hardening and production deployment preparation
- Implement persistent storage for users and sessions

### **Future Enhancements (v1.1+) - Modern Authentication 2025**

- **Passwordless Authentication**: WebAuthn/FIDO2 integration
- **Enterprise SSO**: OAuth2/OIDC provider and SAML 2.0
- **Multi-factor Authentication**: TOTP/HOTP with backup codes
- **Advanced Security**: Account lockout, audit logging, risk-based auth

---

## 📚 Documentation

- **[Getting Started](docs/getting-started.md)** - Installation and first authentication
- **[Architecture](docs/architecture.md)** - Design patterns and structure
- **[API Reference](docs/api-reference.md)** - Complete API documentation
- **[Configuration](docs/configuration.md)** - Settings and environment management
- **[Development](docs/development.md)** - Contributing and workflows
- **[Integration](docs/integration.md)** - FLEXT ecosystem integration patterns
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions

---

## 🤝 Contributing

### **FLEXT-Core Compliance Checklist**

- [ ] All operations return FlextResult[T] for error handling
- [ ] Use FlextContainer.get_global() for dependency injection
- [ ] Domain models extend FlextModels.Entity
- [ ] Follow railway-oriented programming patterns
- [ ] Maintain type safety with Python 3.13+ annotations

### **Quality Standards**

- Test coverage minimum 85% for new code
- All tests must pass before contribution
- Follow FLEXT ecosystem patterns
- Update documentation for new features

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🆘 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/flext-sh/flext/issues)
- **Security**: Report security issues privately to maintainers

---

**flext-auth v0.9.9** - Authentication service enabling secure access management across the FLEXT ecosystem.

**Mission**: Provide authentication services that integrate with FLEXT ecosystem patterns while implementing secure authentication methods for enterprise applications.
