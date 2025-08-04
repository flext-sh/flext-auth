# FLEXT Auth Domain Layer

**Business Logic & Domain Models for Enterprise Authentication**

This directory contains the core domain layer implementing Domain-Driven Design (DDD) patterns for the FLEXT Auth ecosystem. All models follow Clean Architecture principles with rich business logic, comprehensive validation, and event-driven capabilities.

---

## 🏛️ Architecture Overview

**Layer Responsibility**: Encapsulate authentication business logic, domain rules, and enterprise authentication concepts.

**Design Patterns**:

- **Rich Domain Model**: Entities contain both data and business logic
- **Entity Pattern**: Identity-based objects with lifecycle management
- **Value Object Pattern**: Immutable objects representing domain concepts
- **Aggregate Root Pattern**: Consistency boundaries for domain operations (TODO)
- **Domain Events Pattern**: Business events for cross-cutting concerns (TODO)
- **Specification Pattern**: Complex business rule validation
- **Factory Pattern**: Entity creation with proper validation

---

## 📁 Module Structure

### Core Domain Models

#### `entities.py` - Rich Domain Entities

**Primary Purpose**: Core business entities with authentication logic and domain rules

**Key Entities**:

- `FlextUser` - User account with authentication business logic
- `FlextSession` - Active user session with lifecycle management
- `FlextRole` - Role-based access control with permissions
- `FlextPermission` - Fine-grained permissions system
- `FlextLoginAttempt` - Login attempt tracking for security
- `FlextPasswordResetToken` - Password reset workflow tokens
- `FlextEmailVerificationToken` - Email verification workflow tokens

**Business Capabilities**:

- Account lockout after failed attempts
- Session validation and lifecycle management
- Role-based permission aggregation
- Security event tracking and audit trails
- Token-based workflow management

#### `value_objects.py` - Immutable Domain Values

**Primary Purpose**: Immutable value objects with comprehensive validation

**Key Value Objects**:

- `FlextUsername` - Username with format and length validation
- `FlextUserEmail` - Email with RFC-compliant validation
- `FlextPlainPassword` - Password with security policy validation
- `FlextSecurityContext` - Authentication context and permissions

**Validation Features**:

- Input sanitization and format checking
- Business rule enforcement
- Security policy compliance
- Immutable state guarantee

#### `__init__.py` - Domain Layer Gateway

**Primary Purpose**: Centralized access to all domain components

**Exports**:

- All domain entities and value objects
- Domain service interfaces
- Domain event definitions (TODO)
- Aggregate root patterns (TODO)

---

## 🔄 Business Workflows

### User Authentication Domain Logic

```python
from flext_auth.domain.entities import FlextUser
from flext_auth.domain.value_objects import FlextUsername, FlextUserEmail

# Rich domain model with business logic
user = FlextUser(
    username=FlextUsername("john_doe"),
    email=FlextUserEmail("john@example.com"),
    password_hash="$2b$12$secure_hash"
)

# Business logic execution
auth_result = user.authenticate(password="user_password", password_service=password_service)
if auth_result.success:
    session_result = user.create_session(ip_address="192.168.1.1")
```

### Session Management Domain Logic

```python
from flext_auth.domain.entities import FlextSession

# Session lifecycle management
session = FlextSession(
    user_id="user_123",
    access_token="jwt_token",
    expires_at=datetime.now(UTC) + timedelta(hours=24)
)

# Domain business rules
if session.is_valid():
    extension_result = session.extend_session(minutes=30)
    # Business logic ensures only valid sessions can be extended
```

### Role-Based Access Control Domain Logic

```python
from flext_auth.domain.entities import FlextRole, FlextPermission

# Domain-driven RBAC
permission = FlextPermission(
    id="read_users",
    name="Read Users",
    resource="user",
    action="read"
)

REDACTED_LDAP_BIND_PASSWORD_role = FlextRole(
    id="REDACTED_LDAP_BIND_PASSWORD",
    name="Administrator",
    permissions=[permission]
)

# Business rule validation
if REDACTED_LDAP_BIND_PASSWORD_role.has_permission("user", "read"):
    # Access granted based on domain rules
    pass
```

---

## 🛡️ Security & Validation

### Domain Security Rules

**User Account Security**:

- Password strength validation through value objects
- Account lockout after configurable failed attempts
- Status-based access control (active, inactive, locked, pending)
- Audit trail through domain events (TODO)

**Session Security**:

- Automatic expiration validation
- IP address and user agent tracking
- Concurrent session limits enforcement
- Secure session token generation

**Permission Security**:

- Fine-grained resource and action permissions
- Role hierarchy and inheritance (TODO)
- Permission aggregation and validation
- Context-aware access control

### Validation Patterns

**Value Object Validation**:

- Immutable construction with validation
- Format and business rule checking
- Security policy enforcement
- Error aggregation and reporting

**Entity Validation**:

- Domain rule validation on state changes
- Business invariant enforcement
- Cross-entity relationship validation
- Event-driven validation workflows (TODO)

---

## 🔄 Integration with FLEXT Ecosystem

### flext-core Integration

**Foundation Patterns**:

- `FlextEntity` - Base entity with identity and lifecycle
- `FlextValueObject` - Immutable value objects with validation
- `FlextResult[T]` - Type-safe error handling for all operations
- `FlextAggregateRoot` - Event sourcing capabilities (TODO)

**Configuration Integration**:

- Uses `FlextCoreSettings` for domain configuration
- Integrates with `FlextContainer` for dependency injection (TODO)
- Supports `FlextObservability` for domain event monitoring (TODO)

### Cross-Layer Integration

**Application Layer**:

- Domain entities used by application services
- Business logic encapsulated in domain layer
- Domain events consumed by application handlers (TODO)

**Infrastructure Layer**:

- Repository patterns for entity persistence
- Domain service implementations
- External system integration points

---

## 📊 TODO Items (Based on docs/TODO.md)

### High Priority Domain Enhancements

- [ ] **HIGH**: Migrate entities to `FlextAggregateRoot` for event sourcing (Issue #4)
- [ ] **HIGH**: Add domain events for all business operations (Issue #4)
- [ ] **HIGH**: Implement CQRS command handlers integration (Issue #5)
- [ ] **MEDIUM**: Add audit trails for security events (Issue #11)
- [ ] **MEDIUM**: Implement role hierarchy and inheritance (Issue #8)

### Domain Pattern Improvements

- [ ] **HIGH**: Add domain service abstractions for complex business logic
- [ ] **MEDIUM**: Implement specification pattern for complex validations
- [ ] **MEDIUM**: Add domain factory patterns for entity creation
- [ ] **LOW**: Add domain model validation caching for performance

---

## 🧪 Testing Domain Logic

### Domain Testing Patterns

```python
# Entity behavior testing
def test_user_authentication_business_logic():
    user = FlextUser(username="test", email="test@example.com")

    # Test business rule: account lockout after 5 failed attempts
    for _ in range(5):
        result = user.authenticate("wrong_password", mock_password_service)
        assert result.is_failure

    assert user.is_account_locked()
    assert user.failed_login_attempts == 5

# Value object validation testing
def test_username_validation_business_rules():
    # Test business rule: username length constraints
    with pytest.raises(ValueError):
        FlextUsername("ab")  # Too short

    with pytest.raises(ValueError):
        FlextUsername("x" * 51)  # Too long

    # Valid username passes all business rules
    username = FlextUsername("valid_user")
    assert str(username) == "valid_user"
```

### Security Testing

```python
# Security business rule testing
def test_session_security_business_rules():
    session = FlextSession(
        user_id="user_123",
        access_token="token",
        expires_at=datetime.now(UTC) - timedelta(hours=1)  # Expired
    )

    # Business rule: expired sessions are invalid
    assert not session.is_valid()

    # Business rule: cannot extend expired sessions
    result = session.extend_session()
    assert result.is_failure
```

---

## 📚 Documentation Standards

### Docstring Requirements

All domain classes must include:

- **Purpose**: Clear business purpose and responsibility
- **Business Rules**: Domain rules and constraints
- **Validation Logic**: Input validation and business rule enforcement
- **Security Considerations**: Security implications and protections
- **TODO Items**: Reference to docs/TODO.md items where applicable
- **Examples**: Usage examples demonstrating business logic

### Code Quality Standards

- **Type Safety**: Complete type annotations with `FlextResult[T]` returns
- **Immutability**: Value objects must be immutable
- **Validation**: All inputs validated with business rules
- **Error Handling**: Use `FlextResult` for all business operations
- **Security**: No sensitive data exposure in logs or errors

---

**Domain Layer Status**: ✅ **Comprehensive Documentation Complete**  
**Business Logic**: Rich domain models with authentication business rules  
**Integration**: Aligned with Clean Architecture and DDD patterns  
**Security**: Enterprise-grade security rules and validation  
**TODO Alignment**: All items properly referenced with issue numbers

This domain layer provides the foundation for all authentication business logic in the FLEXT ecosystem, following enterprise patterns and security best practices.
