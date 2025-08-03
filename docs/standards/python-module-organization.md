# Python Module Organization & Semantic Patterns

**FLEXT Auth Module Architecture & Organization Standards for FLEXT Ecosystem Integration**

This document defines the Python module organization patterns and semantic conventions for FLEXT Auth, based on flext-core architectural patterns and designed for seamless integration with the 32-project FLEXT ecosystem.

---

## 🚨 Current Module Analysis & Integration Status

**Module Organization Status**: 🔄 **REFACTORING REQUIRED**  
**FLEXT Conformance**: 58/100 - Significant reorganization needed  
**Target Architecture**: flext-core patterns with Clean Architecture layers

### Current Structure Assessment vs flext-core Standards

**✅ Well-Structured Modules (Following flext-core):**
- `src/flext_auth/domain/` - Clean DDD patterns (entities.py, value_objects.py)
- `src/flext_auth/application/` - Application services layer
- `src/flext_auth/services/` - Infrastructure services
- FlextResult[T] pattern extensively used (15+ files)

**⚠️ Modules Needing Refactoring to Match flext-core:**
- `src/flext_auth/auth.py` - Should be split into CQRS command handlers
- `src/flext_auth/user.py` - Repository should move to infrastructure layer
- `src/flext_auth/session.py` - Mixed concerns, needs separation
- `src/flext_auth/config.py` - Should follow FlextBaseSettings patterns

**❌ Missing Critical flext-core Integration Modules:**
- No FlextContainer dependency injection integration
- No CQRS command/handler structure following flext-core patterns
- No FlextAggregateRoot event sourcing implementation
- No unified public API gateway following flext-core conventions

---

## 🏗️ **Target Module Architecture (flext-core Aligned)**

### **Core Design Principles (Following flext-core Standards)**

1. **Single Source of Truth**: Each authentication pattern has one canonical implementation
2. **Explicit Dependencies**: Clear import paths with minimal coupling to flext-core foundation
3. **Type-Safe Everything**: Comprehensive type hints and MyPy compliance with FlextResult[T]
4. **Railway-Oriented**: FlextResult[T] threading through all authentication operations
5. **Ecosystem Consistency**: Authentication patterns work identically across 32 FLEXT projects
6. **FlextContainer Integration**: All services resolved through dependency injection
7. **Event Sourcing Ready**: Domain events for complete authentication audit trails

---

## 📁 **Module Structure & Responsibilities (flext-core Patterns)**

### **Foundation Layer (Following flext-core)**

```python
# Core foundation - used by everything (following flext-core patterns)
src/flext_auth/
├── __init__.py              # 🎯 Public API gateway (FlextAuth patterns)
├── auth_types.py            # 🎯 Authentication type system foundation
├── constants.py             # 🎯 Authentication constants and enums
└── version.py               # 🎯 Version management
```

**Responsibility**: Establish the foundational contracts that all other authentication modules depend on.

**Import Pattern**:
```python
# All ecosystem projects start here (following flext-core pattern)
from flext_auth import FlextAuth, flext_auth_quick_start
from flext_auth import flext_auth_hash_password, flext_auth_required
```

### **flext-core Integration Layer (CRITICAL MISSING)**

```python
# Integration with flext-core patterns (CURRENTLY MISSING)
├── container.py             # 🚀 FlextContainer service registration
├── result_types.py          # 🚀 Authentication-specific FlextResult types
├── exceptions.py            # 🚀 Authentication exception hierarchy
└── helpers.py               # 🚀 Utility functions and factory patterns
```

**Responsibility**: Provide seamless integration with flext-core patterns and DI container.

**Usage Pattern**:
```python
from flext_auth.container import register_flext_auth_services
from flext_auth.result_types import AuthenticationResult, RegistrationResult

# Container integration (TARGET IMPLEMENTATION)
from flext_core import get_flext_container
container = get_flext_container()
register_flext_auth_services(container)
```

### **Domain Layer (DDD with flext-core Event Sourcing)**

```python
# Domain-driven design following flext-core patterns
├── domain/
│   ├── __init__.py            # 🏛️ Domain exports
│   ├── entities.py            # 🏛️ FlextUser, FlextSession (FlextAggregateRoot)
│   ├── value_objects.py       # 🏛️ FlextUsername, FlextUserEmail, FlextPlainPassword
│   ├── events.py              # 🏛️ Domain events (UserRegistered, LoginAttempted)
│   ├── services.py            # 🏛️ Domain services (password policies, validation)
│   └── repositories.py        # 🏛️ Repository interfaces (abstract base classes)
```

**Responsibility**: Implement rich domain logic, business rules, and domain events following flext-core patterns.

**Domain Pattern (FlextAggregateRoot Integration)**:

```python
from flext_auth.domain import FlextUser, FlextUsername, FlextUserEmail
from flext_core import FlextAggregateRoot, FlextResult

class FlextUser(FlextAggregateRoot):  # ✅ Inherit from FlextAggregateRoot
    def __init__(self, username: FlextUsername, email: FlextUserEmail):
        super().__init__()  # Initialize event sourcing
        self.username = username
        self.email = email
        self.failed_login_attempts = 0
        
        # Emit domain event (flext-core pattern)
        self.raise_event(UserRegisteredEvent(self.id, username.value, email.value))

    def attempt_login(self, password: str) -> FlextResult[FlextSession]:
        """Business logic with domain events following flext-core patterns"""
        if self.is_locked():
            self.raise_event(LoginFailedEvent(self.id, "Account locked"))
            return FlextResult.fail("Account is locked due to too many failed attempts")

        if not self.verify_password(password):
            self.failed_login_attempts += 1
            self.raise_event(LoginFailedEvent(self.id, "Invalid password"))
            return FlextResult.fail("Invalid credentials")

        session = self.create_session()
        self.reset_failed_attempts()
        self.raise_event(UserLoggedInEvent(self.id, session.id))
        return FlextResult.ok(session)
```

### **CQRS & Application Layer (Following flext-core)**

```python
# CQRS implementation with command/query separation (flext-core patterns)
├── application/
│   ├── __init__.py            # 📤 Application exports
│   ├── commands/
│   │   ├── __init__.py        # Command exports
│   │   ├── base.py            # FlextAuthCommand base class
│   │   ├── authentication.py  # AuthenticateUserCommand, LoginCommand
│   │   ├── registration.py    # RegisterUserCommand, VerifyEmailCommand
│   │   └── session.py         # CreateSessionCommand, RevokeSessionCommand
│   ├── queries/
│   │   ├── __init__.py        # Query exports
│   │   ├── base.py            # FlextAuthQuery base class
│   │   ├── user.py            # GetUserQuery, GetUserPermissionsQuery
│   │   └── session.py         # GetActiveSessionsQuery, ValidateTokenQuery
│   ├── handlers/
│   │   ├── __init__.py        # Handler exports
│   │   ├── commands.py        # Command handlers implementation
│   │   ├── queries.py         # Query handlers implementation
│   │   └── events.py          # Domain event handlers
│   ├── services.py            # Application services orchestration
│   └── buses.py               # Command and query buses
```

**Responsibility**: Implement CQRS patterns for enterprise scalability and command/query separation.

**CQRS Pattern (flext-core Integration)**:

```python
from flext_auth.application.commands import AuthenticateUserCommand
from flext_auth.application.handlers import AuthenticateUserCommandHandler
from flext_core import FlextCommandHandler, FlextResult

class AuthenticateUserCommand(FlextCommand):
    username: str
    password: str
    ip_address: str
    user_agent: str | None = None

class AuthenticateUserCommandHandler(FlextCommandHandler[AuthenticateUserCommand, AuthenticationResult]):
    async def handle(self, command: AuthenticateUserCommand) -> FlextResult[AuthenticationResult]:
        # Implementation with domain events and flext-core patterns
        return (
            await self.user_repository.find_by_username(command.username)
            .flat_map(lambda user: user.attempt_login(command.password))
            .flat_map(lambda session: self._create_authentication_result(session))
        )
```

### **Infrastructure Layer (External Concerns)**

```python
# Infrastructure services and external integrations
src/flext_auth/
├── auth.py                  # 🚀 Main authentication orchestrator (FlextAuthService)
├── jwt.py                   # 🚀 JWT token operations (FlextJWTService)
├── user.py                  # 🚀 User repository implementation
├── session.py               # 🚀 Session repository implementation
├── config.py                # ⚙️ Configuration management
└── services/                # 🔧 Infrastructure services
    └── password_service.py   # 🔧 Password hashing/verification
```

**Responsibility**: Handle external system integration, persistence, and infrastructure concerns.

**Infrastructure Pattern**:

```python
from flext_auth.auth import FlextAuthService
from flext_auth.jwt import FlextJWTService
from flext_auth.services.password_service import FlextPasswordService

class FlextAuthService:
    """Main authentication service orchestrator"""

    def __init__(self,
                 user_repo: UserRepository,
                 session_repo: SessionRepository,
                 jwt_service: FlextJWTService,
                 password_service: FlextPasswordService):
        self.user_repo = user_repo
        self.session_repo = session_repo
        self.jwt_service = jwt_service
        self.password_service = password_service

    async def login(self, username: str, password: str) -> FlextResult[LoginResult]:
        """Complete login flow with all infrastructure coordination"""
        return (
            await self.user_repo.find_by_username(username)
            .flat_map_async(lambda user: self._authenticate_user(user, password))
            .flat_map_async(lambda user: self._create_session(user))
            .flat_map_async(lambda session: self._generate_jwt_tokens(session))
        )
```

### **Cross-Cutting Concerns**

```python
# Reusable patterns and utilities
src/flext_auth/
├── decorators.py            # 🔧 Authentication decorators
├── mixins.py                # 🔧 Reusable authentication behaviors
├── helpers.py               # 🔧 Utility functions (flext_auth_*)
├── fields.py                # 🔧 Authentication-specific fields
├── validation.py            # 🔧 Input validation system
├── exceptions.py            # 🔧 Authentication-specific exceptions
├── constants.py             # 🔧 Authentication constants
└── auth_types.py            # 🔧 Type definitions
```

**Responsibility**: Provide reusable authentication patterns and cross-cutting concerns.

**Cross-Cutting Pattern**:

```python
from flext_auth.decorators import flext_auth_required, flext_auth_role_required
from flext_auth.helpers import flext_auth_hash_password, flext_auth_validate_email

# Authentication decorators
@flext_auth_required
@flext_auth_role_required("REDACTED_LDAP_BIND_PASSWORD")
async def protected_REDACTED_LDAP_BIND_PASSWORD_endpoint(user: FlextUser):
    """Endpoint protected by authentication and authorization"""
    return {"message": f"Welcome REDACTED_LDAP_BIND_PASSWORD {user.username}"}

# Utility functions with semantic naming
password_hash = flext_auth_hash_password("SecurePassword123!")
is_valid_email = flext_auth_validate_email("user@example.com")
```

---

## 🎯 **Semantic Naming Conventions (flext-core Aligned)**

### **Public API Naming (FlextAuth prefix following flext-core)**

Following flext-core patterns, all public exports use the `FlextAuth` or `flext_auth_` prefix to avoid namespace conflicts across the 32-project ecosystem:

```python
# Core patterns (following flext-core naming)
FlextAuth                       # Main authentication service (primary interface)
FlextAuthService               # Core authentication service implementation
FlextAuthContainer             # Dependency injection container
FlextAuthConfig                # Configuration class (extends FlextBaseSettings)

# Domain entities and value objects (flext-core patterns)
FlextUser                      # User aggregate root (FlextAggregateRoot)
FlextSession                   # Session entity
FlextRole                      # Role domain entity
FlextPermission               # Permission domain entity
FlextUsername                 # Username value object (FlextValueObject)
FlextUserEmail                # Email value object (FlextValueObject)
FlextPlainPassword            # Password value object (FlextValueObject)
FlextSecurityContext          # Security context for authentication state

# Authentication results (FlextResult specializations)
FlextAuthenticationResult     # Authentication operation result
FlextRegistrationResult       # User registration result
FlextSessionResult            # Session creation result
FlextTokenValidationResult    # JWT validation result

# Commands and queries (CQRS following flext-core)
FlextAuthCommand              # Base command class (extends FlextCommand)
FlextAuthQuery               # Base query class (extends FlextQuery)
FlextAuthenticateUserCommand  # Authentication command
FlextRegisterUserCommand      # Registration command
FlextGetUserQuery            # User retrieval query
FlextValidateTokenQuery      # Token validation query

# Domain events (following flext-core FlextEvent)
FlextUserRegisteredEvent      # User registration event
FlextUserLoggedInEvent        # Successful login event
FlextLoginFailedEvent         # Failed login event
FlextAccountLockedEvent       # Account lockout event

# Helper functions (flext_auth_ prefix)
flext_auth_quick_start()      # Quick setup function (anti-boilerplate)
flext_auth_hash_password()    # Password hashing utility
flext_auth_generate_jwt()     # JWT generation utility
flext_auth_validate_email()   # Email validation utility
flext_auth_create_user()      # User creation helper
flext_auth_authenticate()     # Authentication helper
flext_auth_required          # Authentication decorator
```

**Rationale**: Clear semantic naming reduces cognitive load and provides self-documenting APIs.

### **Module-Level Naming**

```python
# Core authentication modules
auth.py                     # Main authentication orchestration
jwt.py                      # JWT token operations
user.py                     # User repository and operations
session.py                  # Session management and storage
config.py                   # Configuration and settings

# Domain modules
domain/entities.py          # Domain entities (User, Session, Role)
domain/value_objects.py     # Value objects (Username, Email, Context)

# Application modules
application/services.py     # Application service layer

# Infrastructure modules
services/password_service.py # Password hashing and verification

# Utility modules
helpers.py                  # Utility functions (flext_auth_*)
decorators.py              # Authentication decorators
mixins.py                  # Reusable behavior patterns
validation.py              # Input validation and rules
```

**Pattern**: Module names clearly indicate their primary responsibility and scope.

### **Internal Naming (\_xxx)**

```python
# Internal implementation details (not exported)
def _generate_session_token() -> str:
    """Internal session token generation"""

def _validate_session_expiry(session: FlextSession) -> bool:
    """Internal session validation"""

class _InternalPasswordHasher:
    """Internal password hashing implementation"""
```

**Rule**: Anything with `_` prefix is internal implementation and not part of public API.

---

## 📦 **Import Patterns & Best Practices**

### **Recommended Import Styles**

#### **1. Primary Pattern (Recommended for Most Use Cases)**

```python
# Import main interface - covers 95% of use cases
from flext_auth import FlextAuth, flext_auth_quick_start, flext_auth_hash_password

# Complete authentication setup
auth = flext_auth_quick_start()
result = await auth.authenticate("user", "password")

# Individual helper functions
password_hash = flext_auth_hash_password("SecurePassword123!")
```

#### **2. Specific Module Pattern (For Advanced Integration)**

```python
# Import from specific modules for framework integration
from flext_auth.decorators import flext_auth_required, flext_auth_role_required
from flext_auth.domain.entities import FlextUser, FlextSession
from flext_auth.application.services import AuthenticationApplicationService

# Advanced framework integration
@flext_auth_required
@flext_auth_role_required("REDACTED_LDAP_BIND_PASSWORD")
async def protected_endpoint(user: FlextUser):
    return {"user_id": user.id}
```

#### **3. Type Annotation Pattern**

```python
# Import types for annotations without runtime overhead
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_auth import FlextAuth, FlextUser, FlextSession

# Use in function signatures
def process_authentication(auth: 'FlextAuth', user: 'FlextUser') -> 'FlextResult[FlextSession]':
    pass
```

### **Framework Integration Patterns**

#### **FastAPI Integration**

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from flext_auth import flext_auth_quick_start, FlextAuth

app = FastAPI()
auth = flext_auth_quick_start()
security = HTTPBearer()

async def get_current_user(token = Depends(security)) -> FlextUser:
    """Dependency for authenticated user"""
    result = await auth.validate_jwt(token.credentials)
    if result.is_failure:
        raise HTTPException(401, result.error)
    return result.data

@app.get("/protected")
async def protected_route(user: FlextUser = Depends(get_current_user)):
    return {"message": f"Hello {user.username}"}
```

#### **Flask Integration**

```python
from flask import Flask, request, jsonify
from functools import wraps
from flext_auth import flext_auth_quick_start

app = Flask(__name__)
auth = flext_auth_quick_start()

def require_auth(f):
    """Authentication decorator for Flask"""
    @wraps(f)
    async def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        result = await auth.validate_jwt(token)
        if result.is_failure:
            return jsonify({"error": result.error}), 401
        request.current_user = result.data
        return await f(*args, **kwargs)
    return decorated

@app.route('/protected')
@require_auth
async def protected_route():
    return jsonify({"message": f"Hello {request.current_user.username}"})
```

### **Anti-Patterns (Forbidden)**

```python
# ❌ Don't import everything
from flext_auth import *

# ❌ Don't import internal modules
from flext_auth.auth import _InternalAuthHelper

# ❌ Don't bypass the main interface
from flext_auth.services.password_service import _hash_password_internal

# ❌ Don't alias core types inconsistently
from flext_auth import FlextAuth as Auth  # Confusing across ecosystem

# ❌ Don't duplicate authentication logic
class CustomAuth:  # Use FlextAuth instead
    def authenticate(self, user, password):
        # Custom implementation breaks ecosystem consistency
        pass
```

---

## 🏛️ **Domain-Driven Design Patterns**

### **Entity Patterns**

```python
from flext_core import FlextEntity, FlextResult
from flext_auth.domain.value_objects import FlextUsername, FlextUserEmail

class FlextUser(FlextEntity):
    """Rich user entity with authentication business logic"""
    username: FlextUsername
    email: FlextUserEmail
    password_hash: str
    is_active: bool = True
    failed_login_attempts: int = 0
    last_login: Optional[datetime] = None
    account_locked_until: Optional[datetime] = None
    roles: List[FlextRole] = field(default_factory=list)

    def authenticate(self, password: str, password_service: PasswordService) -> FlextResult[None]:
        """Authenticate user with business rules"""
        if self.is_account_locked():
            return FlextResult.fail("Account is locked")

        if not password_service.verify_password(password, self.password_hash):
            self.record_failed_login()
            return FlextResult.fail("Invalid credentials")

        self.record_successful_login()
        return FlextResult.ok(None)

    def is_account_locked(self) -> bool:
        """Check if account is locked due to failed attempts"""
        if self.account_locked_until is None:
            return False
        return datetime.utcnow() < self.account_locked_until

    def record_failed_login(self) -> None:
        """Record failed login attempt with auto-locking"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Configurable threshold
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
            self.add_domain_event(AccountLockedEvent(self.id))
        self.add_domain_event(LoginFailedEvent(self.id))

    def record_successful_login(self) -> None:
        """Record successful login and reset counters"""
        self.failed_login_attempts = 0
        self.last_login = datetime.utcnow()
        self.account_locked_until = None
        self.add_domain_event(UserLoggedInEvent(self.id))

class FlextSession(FlextEntity):
    """Session entity with lifecycle management"""
    user_id: str
    token: str
    expires_at: datetime
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True

    def is_expired(self) -> bool:
        """Check if session has expired"""
        return datetime.utcnow() > self.expires_at

    def extend_session(self, extension_minutes: int = 30) -> FlextResult[None]:
        """Extend session if valid"""
        if not self.is_active:
            return FlextResult.fail("Cannot extend inactive session")

        if self.is_expired():
            return FlextResult.fail("Cannot extend expired session")

        self.expires_at = datetime.utcnow() + timedelta(minutes=extension_minutes)
        self.last_accessed = datetime.utcnow()
        self.add_domain_event(SessionExtendedEvent(self.id))
        return FlextResult.ok(None)

    def revoke(self) -> FlextResult[None]:
        """Revoke session"""
        if not self.is_active:
            return FlextResult.fail("Session already inactive")

        self.is_active = False
        self.add_domain_event(SessionRevokedEvent(self.id))
        return FlextResult.ok(None)
```

### **Value Object Patterns**

```python
from flext_core import FlextValueObject
import re

class FlextUsername(FlextValueObject):
    """Username value object with validation"""
    value: str

    def __post_init__(self):
        if not self.value:
            raise ValueError("Username cannot be empty")
        if len(self.value) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(self.value) > 50:
            raise ValueError("Username cannot exceed 50 characters")
        if not re.match(r'^[a-zA-Z0-9_.-]+$', self.value):
            raise ValueError("Username contains invalid characters")

    def __str__(self) -> str:
        return self.value

class FlextUserEmail(FlextValueObject):
    """Email value object with comprehensive validation"""
    address: str

    def __post_init__(self):
        if not self.address:
            raise ValueError("Email cannot be empty")
        if not self._is_valid_format():
            raise ValueError("Invalid email format")
        if len(self.address) > 254:
            raise ValueError("Email address too long")

    def _is_valid_format(self) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, self.address) is not None

    @property
    def domain(self) -> str:
        """Extract domain from email"""
        return self.address.split('@')[1]

    @property
    def local_part(self) -> str:
        """Extract local part from email"""
        return self.address.split('@')[0]

class FlextSecurityContext(FlextValueObject):
    """Security context for authentication state"""
    user_id: str
    username: str
    roles: List[str]
    permissions: List[str]
    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def has_role(self, role: str) -> bool:
        """Check if user has specific role"""
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission"""
        return permission in self.permissions

    def has_any_role(self, roles: List[str]) -> bool:
        """Check if user has any of the specified roles"""
        return any(role in self.roles for role in roles)
```

### **Domain Service Patterns**

```python
from flext_core import FlextDomainService, FlextResult

class PasswordPolicyService(FlextDomainService):
    """Domain service for password policy enforcement"""

    def __init__(self, min_length: int = 8, require_special: bool = True):
        self.min_length = min_length
        self.require_special = require_special

    def validate_password_strength(self, password: str) -> FlextResult[PasswordStrengthResult]:
        """Validate password against security policy"""
        issues = []
        score = 0

        if len(password) < self.min_length:
            issues.append(f"Password must be at least {self.min_length} characters")
        else:
            score += 1

        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain uppercase letters")
        else:
            score += 1

        if not re.search(r'[a-z]', password):
            issues.append("Password must contain lowercase letters")
        else:
            score += 1

        if not re.search(r'\d', password):
            issues.append("Password must contain numbers")
        else:
            score += 1

        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain special characters")
        else:
            score += 1

        result = PasswordStrengthResult(
            is_valid=len(issues) == 0,
            score=score,
            max_score=5,
            issues=issues
        )

        return FlextResult.ok(result)

class SessionSecurityService(FlextDomainService):
    """Domain service for session security policies"""

    def __init__(self, max_concurrent_sessions: int = 5, session_timeout_minutes: int = 30):
        self.max_concurrent_sessions = max_concurrent_sessions
        self.session_timeout_minutes = session_timeout_minutes

    def validate_new_session(self, user: FlextUser, existing_sessions: List[FlextSession]) -> FlextResult[None]:
        """Validate if new session can be created"""
        active_sessions = [s for s in existing_sessions if s.is_active and not s.is_expired()]

        if len(active_sessions) >= self.max_concurrent_sessions:
            return FlextResult.fail(f"Maximum concurrent sessions ({self.max_concurrent_sessions}) exceeded")

        return FlextResult.ok(None)

    def create_secure_session(self, user: FlextUser) -> FlextResult[FlextSession]:
        """Create session with security policies applied"""
        expires_at = datetime.utcnow() + timedelta(minutes=self.session_timeout_minutes)
        session_token = self._generate_secure_token()

        session = FlextSession(
            user_id=user.id,
            token=session_token,
            expires_at=expires_at
        )

        return FlextResult.ok(session)
```

---

## 🔄 **Railway-Oriented Programming Patterns**

### **Authentication Flow Patterns**

```python
from flext_core import FlextResult

async def complete_authentication_flow(
    username: str,
    password: str,
    auth_service: FlextAuthService
) -> FlextResult[AuthenticationResult]:
    """Complete authentication flow with railway pattern"""
    return (
        await auth_service.validate_credentials(username, password)
        .flat_map_async(lambda user: auth_service.check_account_status(user))
        .flat_map_async(lambda user: auth_service.authenticate_user(user, password))
        .flat_map_async(lambda user: auth_service.create_session(user))
        .flat_map_async(lambda session: auth_service.generate_tokens(session))
        .map(lambda tokens: AuthenticationResult(session=tokens.session, tokens=tokens))
    )

async def registration_workflow(
    user_data: dict,
    auth_service: FlextAuthService
) -> FlextResult[FlextUser]:
    """User registration workflow with validation chain"""
    return (
        FlextResult.ok(user_data)
        .flat_map(lambda data: validate_registration_data(data))
        .flat_map_async(lambda data: check_username_availability(data['username']))
        .flat_map_async(lambda data: check_email_availability(data['email']))
        .flat_map(lambda data: hash_password(data))
        .flat_map_async(lambda data: create_user_entity(data))
        .flat_map_async(lambda user: save_user(user))
        .map(lambda user: send_welcome_email(user))  # Side effect, don't break chain
    )

async def password_change_workflow(
    user_id: str,
    old_password: str,
    new_password: str,
    auth_service: FlextAuthService
) -> FlextResult[None]:
    """Password change workflow with security validation"""
    return (
        await auth_service.get_user(user_id)
        .flat_map_async(lambda user: auth_service.verify_current_password(user, old_password))
        .flat_map(lambda user: validate_new_password_policy(new_password))
        .flat_map_async(lambda user: auth_service.update_password(user, new_password))
        .flat_map_async(lambda user: auth_service.revoke_all_sessions(user))  # Security: force re-login
        .map(lambda user: send_password_changed_notification(user))
    )
```

### **Error Aggregation Patterns**

```python
def validate_login_request(request: dict) -> FlextResult[LoginRequest]:
    """Validate login request with error aggregation"""
    errors = []

    # Validate username
    if not request.get('username'):
        errors.append("Username is required")
    elif len(request['username']) < 3:
        errors.append("Username must be at least 3 characters")

    # Validate password
    if not request.get('password'):
        errors.append("Password is required")
    elif len(request['password']) < 8:
        errors.append("Password must be at least 8 characters")

    # Validate additional fields
    if 'remember_me' in request and not isinstance(request['remember_me'], bool):
        errors.append("Remember me must be a boolean value")

    if errors:
        return FlextResult.fail(f"Validation errors: {'; '.join(errors)}")

    return FlextResult.ok(LoginRequest(
        username=request['username'],
        password=request['password'],
        remember_me=request.get('remember_me', False)
    ))

def validate_registration_data(data: dict) -> FlextResult[dict]:
    """Comprehensive registration validation"""
    validation_results = []

    # Validate each field independently
    validation_results.append(validate_username(data.get('username')))
    validation_results.append(validate_email(data.get('email')))
    validation_results.append(validate_password(data.get('password')))
    validation_results.append(validate_confirm_password(data.get('password'), data.get('confirm_password')))

    # Aggregate all validation errors
    errors = [result.error for result in validation_results if result.is_failure]

    if errors:
        return FlextResult.fail(f"Registration validation failed: {'; '.join(errors)}")

    return FlextResult.ok(data)
```

### **Resource Management Patterns**

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def authentication_transaction(auth_service: FlextAuthService):
    """Context manager for authentication operations with rollback"""
    transaction = await auth_service.begin_transaction()
    try:
        yield transaction
        await transaction.commit()
    except Exception as e:
        await transaction.rollback()
        raise e

async def secure_user_operation(
    user_id: str,
    operation: Callable[[FlextUser], FlextResult[T]],
    auth_service: FlextAuthService
) -> FlextResult[T]:
    """Execute user operation with proper resource management"""
    async with authentication_transaction(auth_service) as tx:
        return (
            await auth_service.get_user_with_lock(user_id, tx)
            .flat_map(lambda user: operation(user))
            .flat_map_async(lambda result: auth_service.save_user(user, tx).map(lambda _: result))
        )
```

---

## 🔧 **Configuration Patterns**

### **Hierarchical Authentication Configuration**

```python
from flext_core import FlextBaseSettings
from typing import Optional

class JWTSettings(FlextBaseSettings):
    """JWT token configuration"""
    secret_key: str = field(repr=False)  # Hidden in logs
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    algorithm: str = "HS256"
    issuer: Optional[str] = None
    audience: Optional[str] = None

    class Config:
        env_prefix = "JWT_"

    def validate_secret_key(self) -> bool:
        """Validate secret key strength"""
        return len(self.secret_key) >= 32

class SecuritySettings(FlextBaseSettings):
    """Security policy configuration"""
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_special: bool = True
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_timeout_minutes: int = 1440  # 24 hours
    max_concurrent_sessions: int = 5
    require_email_verification: bool = True

    class Config:
        env_prefix = "SECURITY_"

class DatabaseSettings(FlextBaseSettings):
    """Database configuration for authentication"""
    url: str = "postgresql://localhost/flext_auth"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30

    class Config:
        env_prefix = "DATABASE_"

class CacheSettings(FlextBaseSettings):
    """Cache configuration for sessions and tokens"""
    redis_url: str = "redis://localhost:6379/0"
    session_cache_ttl: int = 3600
    token_cache_ttl: int = 1800

    class Config:
        env_prefix = "CACHE_"

class FlextAuthConfig(FlextBaseSettings):
    """Complete authentication configuration"""
    app_name: str = "FLEXT Auth"
    debug: bool = False
    environment: str = "development"

    # Nested configuration
    jwt: JWTSettings = field(default_factory=JWTSettings)
    security: SecuritySettings = field(default_factory=SecuritySettings)
    database: DatabaseSettings = field(default_factory=DatabaseSettings)
    cache: CacheSettings = field(default_factory=CacheSettings)

    class Config:
        env_prefix = "FLEXT_AUTH_"
        env_nested_delimiter = "__"

    def is_production(self) -> bool:
        """Check if running in production"""
        return self.environment.lower() == "production"

    def validate_production_config(self) -> FlextResult[None]:
        """Validate configuration for production deployment"""
        issues = []

        if not self.jwt.validate_secret_key():
            issues.append("JWT secret key must be at least 32 characters")

        if self.debug and self.is_production():
            issues.append("Debug mode must be disabled in production")

        if self.security.max_login_attempts < 3:
            issues.append("Max login attempts should be at least 3 for security")

        if issues:
            return FlextResult.fail(f"Production validation failed: {'; '.join(issues)}")

        return FlextResult.ok(None)
```

### **Environment-Specific Configuration**

```python
# Environment variables:
# FLEXT_AUTH_ENVIRONMENT=production
# FLEXT_AUTH_DEBUG=false
# FLEXT_AUTH_JWT__SECRET_KEY=your-super-secret-production-key-here
# FLEXT_AUTH_JWT__ACCESS_TOKEN_EXPIRE_MINUTES=15
# FLEXT_AUTH_SECURITY__MAX_LOGIN_ATTEMPTS=3
# FLEXT_AUTH_SECURITY__LOCKOUT_DURATION_MINUTES=60
# FLEXT_AUTH_DATABASE__URL=postgresql://user:pass@prod-db/flext_auth
# FLEXT_AUTH_CACHE__REDIS_URL=redis://prod-cache:6379/0

class EnvironmentConfigFactory:
    """Factory for environment-specific configurations"""

    @staticmethod
    def create_development_config() -> FlextAuthConfig:
        """Development configuration with relaxed security"""
        return FlextAuthConfig(
            environment="development",
            debug=True,
            jwt=JWTSettings(
                secret_key="development-secret-key-not-for-production",
                access_token_expire_minutes=60  # Longer for development
            ),
            security=SecuritySettings(
                max_login_attempts=10,  # More lenient for development
                lockout_duration_minutes=5
            )
        )

    @staticmethod
    def create_production_config() -> FlextResult[FlextAuthConfig]:
        """Production configuration with strict validation"""
        config = FlextAuthConfig(
            environment="production",
            debug=False
        )

        # Validate production requirements
        validation_result = config.validate_production_config()
        if validation_result.is_failure:
            return validation_result

        return FlextResult.ok(config)

    @staticmethod
    def create_test_config() -> FlextAuthConfig:
        """Test configuration optimized for testing"""
        return FlextAuthConfig(
            environment="test",
            debug=True,
            jwt=JWTSettings(
                secret_key="test-secret-key-for-testing-only",
                access_token_expire_minutes=5  # Short for testing
            ),
            security=SecuritySettings(
                max_login_attempts=3,
                lockout_duration_minutes=1  # Fast recovery for tests
            ),
            database=DatabaseSettings(
                url="sqlite:///test_auth.db"  # In-memory for tests
            )
        )
```

---

## 🧪 **Testing Patterns**

### **Test Organization Following Core Standards**

```python
# Test structure mirrors source structure
tests/
├── unit/                    # Unit tests (isolated components)
│   ├── domain/              # Domain layer tests
│   │   ├── test_entities.py     # Entity behavior tests
│   │   └── test_value_objects.py # Value object tests
│   ├── application/         # Application layer tests
│   │   └── test_services.py     # Application service tests
│   ├── infrastructure/      # Infrastructure tests
│   │   ├── test_auth_service.py # Main auth service
│   │   ├── test_jwt_service.py  # JWT operations
│   │   └── test_repositories.py # Repository implementations
│   └── helpers/             # Helper function tests
│       └── test_helpers.py      # flext_auth_* function tests
├── integration/             # Integration tests
│   ├── test_auth_workflows.py   # Complete auth workflows
│   ├── test_database.py         # Database integration
│   └── test_middleware.py       # Framework integration
├── e2e/                     # End-to-end tests
│   └── test_auth_flows.py       # Complete user scenarios
├── security/                # Security-focused tests
│   ├── test_password_security.py # Password policies
│   ├── test_session_security.py  # Session security
│   └── test_jwt_security.py      # JWT security
├── conftest.py              # Test configuration and fixtures
└── shared_test_domain.py    # Shared test domain models
```

### **Domain Testing Patterns**

```python
import pytest
from flext_auth.domain.entities import FlextUser
from flext_auth.domain.value_objects import FlextUsername, FlextUserEmail

class TestFlextUser:
    """Test user entity behavior"""

    def test_user_authentication_success(self, mock_password_service):
        """Test successful user authentication"""
        user = FlextUser(
            username=FlextUsername("testuser"),
            email=FlextUserEmail("test@example.com"),
            password_hash="hashed_password"
        )

        mock_password_service.verify_password.return_value = True

        result = user.authenticate("correct_password", mock_password_service)

        assert result.is_success
        assert user.failed_login_attempts == 0
        assert user.last_login is not None
        assert len(user.domain_events) == 1
        assert user.domain_events[0]["type"] == "UserLoggedIn"

    def test_user_authentication_failure(self, mock_password_service):
        """Test failed authentication with attempt tracking"""
        user = FlextUser(
            username=FlextUsername("testuser"),
            email=FlextUserEmail("test@example.com"),
            password_hash="hashed_password"
        )

        mock_password_service.verify_password.return_value = False

        result = user.authenticate("wrong_password", mock_password_service)

        assert result.is_failure
        assert result.error == "Invalid credentials"
        assert user.failed_login_attempts == 1
        assert len(user.domain_events) == 1
        assert user.domain_events[0]["type"] == "LoginFailed"

    def test_account_lockout_after_max_attempts(self, mock_password_service):
        """Test account lockout after exceeding max attempts"""
        user = FlextUser(
            username=FlextUsername("testuser"),
            email=FlextUserEmail("test@example.com"),
            password_hash="hashed_password",
            failed_login_attempts=4  # One away from lockout
        )

        mock_password_service.verify_password.return_value = False

        result = user.authenticate("wrong_password", mock_password_service)

        assert result.is_failure
        assert user.failed_login_attempts == 5
        assert user.is_account_locked()
        assert user.account_locked_until is not None

        # Check domain events
        events = user.domain_events
        assert len(events) == 2
        assert any(event["type"] == "LoginFailed" for event in events)
        assert any(event["type"] == "AccountLocked" for event in events)

class TestFlextUsername:
    """Test username value object validation"""

    def test_valid_username_creation(self):
        """Test creation of valid username"""
        username = FlextUsername("valid_user123")
        assert str(username) == "valid_user123"

    def test_username_too_short(self):
        """Test username length validation"""
        with pytest.raises(ValueError, match="must be at least 3 characters"):
            FlextUsername("ab")

    def test_username_invalid_characters(self):
        """Test username character validation"""
        with pytest.raises(ValueError, match="contains invalid characters"):
            FlextUsername("user@name!")

    @pytest.mark.parametrize("username", [
        "user123", "user_name", "user.name", "user-name", "USER123"
    ])
    def test_valid_username_formats(self, username):
        """Test various valid username formats"""
        result = FlextUsername(username)
        assert str(result) == username
```

### **Authentication Flow Testing**

```python
import pytest
from unittest.mock import AsyncMock, MagicMock
from flext_auth import FlextAuth, flext_auth_quick_start

class TestAuthenticationFlows:
    """Test complete authentication workflows"""

    @pytest.fixture
    def auth_service(self):
        """Provide configured auth service for testing"""
        return flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    @pytest.mark.asyncio
    async def test_complete_login_flow(self, auth_service):
        """Test complete login workflow"""
        # Setup: Register a user first
        register_result = await auth_service.register(
            "testuser",
            "test@example.com",
            "SecurePassword123!"
        )
        assert register_result.is_success

        # Test: Login with correct credentials
        login_result = await auth_service.login("testuser", "SecurePassword123!")

        assert login_result.is_success
        assert "access_token" in login_result.data
        assert "refresh_token" in login_result.data
        assert "user" in login_result.data
        assert login_result.data["user"]["username"] == "testuser"

    @pytest.mark.asyncio
    async def test_login_with_invalid_credentials(self, auth_service):
        """Test login failure with invalid credentials"""
        # Setup: Register a user first
        await auth_service.register("testuser", "test@example.com", "SecurePassword123!")

        # Test: Login with wrong password
        login_result = await auth_service.login("testuser", "WrongPassword")

        assert login_result.is_failure
        assert "Invalid credentials" in login_result.error

    @pytest.mark.asyncio
    async def test_jwt_token_validation(self, auth_service):
        """Test JWT token validation workflow"""
        # Setup: Register and login user
        await auth_service.register("testuser", "test@example.com", "SecurePassword123!")
        login_result = await auth_service.login("testuser", "SecurePassword123!")
        token = login_result.data["access_token"]

        # Test: Validate token
        validation_result = await auth_service.validate_jwt(token)

        assert validation_result.is_success
        assert validation_result.data["username"] == "testuser"
        assert "user_id" in validation_result.data

    @pytest.mark.asyncio
    async def test_session_management(self, auth_service):
        """Test session creation and management"""
        # Setup: Register and login user
        await auth_service.register("testuser", "test@example.com", "SecurePassword123!")
        login_result = await auth_service.login("testuser", "SecurePassword123!")

        # Test: Get user sessions
        sessions_result = await auth_service.get_user_sessions(login_result.data["user"]["id"])

        assert sessions_result.is_success
        assert len(sessions_result.data) >= 1  # At least the current session

        # Test: Logout (revoke session)
        logout_result = await auth_service.logout(login_result.data["session"]["id"])

        assert logout_result.is_success
```

### **Security Testing Patterns**

```python
class TestSecurityFeatures:
    """Test security-specific functionality"""

    @pytest.mark.asyncio
    async def test_password_hashing_security(self):
        """Test password hashing security"""
        from flext_auth import flext_auth_hash_password, flext_auth_verify_password

        password = "SecureTestPassword123!"

        # Test: Hash password
        hash_result = flext_auth_hash_password(password)
        assert hash_result != password  # Should be hashed
        assert len(hash_result) > 50    # Should be substantial hash

        # Test: Verify correct password
        verify_result = flext_auth_verify_password(password, hash_result)
        assert verify_result is True

        # Test: Verify incorrect password
        verify_wrong = flext_auth_verify_password("WrongPassword", hash_result)
        assert verify_wrong is False

    @pytest.mark.asyncio
    async def test_account_lockout_security(self, auth_service):
        """Test account lockout after failed attempts"""
        # Setup: Register user
        await auth_service.register("testuser", "test@example.com", "SecurePassword123!")

        # Test: Multiple failed login attempts
        for i in range(5):  # Trigger lockout
            result = await auth_service.login("testuser", "WrongPassword")
            assert result.is_failure

        # Test: Account should be locked
        final_attempt = await auth_service.login("testuser", "SecurePassword123!")  # Even correct password
        assert final_attempt.is_failure
        assert "locked" in final_attempt.error.lower()

    @pytest.mark.asyncio
    async def test_jwt_token_expiration(self, auth_service):
        """Test JWT token expiration security"""
        import time
        from unittest.mock import patch

        # Setup: Login user with short token expiry
        await auth_service.register("testuser", "test@example.com", "SecurePassword123!")
        login_result = await auth_service.login("testuser", "SecurePassword123!")
        token = login_result.data["access_token"]

        # Test: Token should be valid initially
        validation_result = await auth_service.validate_jwt(token)
        assert validation_result.is_success

        # Test: Simulate token expiration
        with patch('time.time', return_value=time.time() + 3600):  # 1 hour later
            expired_validation = await auth_service.validate_jwt(token)
            assert expired_validation.is_failure
            assert "expired" in expired_validation.error.lower()
```

---

## 📏 **Code Quality Standards**

### **Type Annotation Requirements**

```python
# ✅ Complete type annotations for all public functions
from typing import Dict, List, Optional, Union
from flext_core import FlextResult

def authenticate_user(
    username: str,
    password: str,
    config: FlextAuthConfig
) -> FlextResult[AuthenticationResult]:
    """Authenticate user with complete type safety"""
    return FlextResult.ok(AuthenticationResult(...))

# ✅ Generic type usage for reusable patterns
T = TypeVar('T')
U = TypeVar('U')

def transform_auth_result(
    result: FlextResult[T],
    transformer: Callable[[T], U]
) -> FlextResult[U]:
    """Transform authentication result with type safety"""
    return result.map(transformer)

# ✅ Protocol definitions for dependency injection
from typing import Protocol

class PasswordServiceProtocol(Protocol):
    """Protocol for password service implementations"""

    def hash_password(self, password: str) -> str:
        """Hash password securely"""
        ...

    def verify_password(self, password: str, hash: str) -> bool:
        """Verify password against hash"""
        ...

# ❌ Missing type annotations (forbidden)
def authenticate_user(username, password):  # Missing types
    return "success"  # Should return FlextResult
```

### **Error Handling Standards**

```python
# ✅ Always use FlextResult for error handling in authentication
def validate_credentials(username: str, password: str) -> FlextResult[ValidatedCredentials]:
    if not username:
        return FlextResult.fail("Username is required")
    if not password:
        return FlextResult.fail("Password is required")
    return FlextResult.ok(ValidatedCredentials(username, password))

# ✅ Chain authentication operations safely
async def complete_auth_flow(username: str, password: str) -> FlextResult[AuthToken]:
    return (
        validate_credentials(username, password)
        .flat_map_async(lambda creds: authenticate_user(creds))
        .flat_map_async(lambda user: create_session(user))
        .flat_map_async(lambda session: generate_jwt(session))
    )

# ✅ Handle security-specific errors appropriately
def authenticate_with_security_context(credentials: LoginCredentials) -> FlextResult[FlextSecurityContext]:
    if credentials.is_suspicious():
        return FlextResult.fail("Authentication blocked due to suspicious activity")

    return validate_and_authenticate(credentials)

# ❌ Never raise exceptions in authentication business logic
def authenticate_user_bad(username: str, password: str) -> bool:
    if not username:
        raise ValueError("Username required")  # Breaks railway pattern
    # ... authentication logic
```

### **Security Documentation Standards**

```python
def flext_auth_hash_password(
    password: str,
    rounds: int = 12,
    salt: Optional[bytes] = None
) -> str:
    """
    Hash password using bcrypt with configurable rounds.

    This function provides secure password hashing using the bcrypt algorithm
    with configurable cost factor. Higher rounds increase security but require
    more computational resources.

    Security Considerations:
        - Uses cryptographically secure random salt if not provided
        - Minimum 4 rounds, maximum 20 rounds for performance/security balance
        - Default 12 rounds provides good security for most applications
        - Production environments should use at least 12 rounds

    Args:
        password: Plain text password to hash (will be cleared from memory)
        rounds: Bcrypt cost factor (4-20), higher is more secure but slower
        salt: Optional salt bytes, auto-generated if not provided

    Returns:
        str: Bcrypt hash string suitable for storage and verification

    Security Warning:
        Never log or store the plain text password. This function
        automatically clears sensitive data from memory when possible.

    Example:
        >>> password_hash = flext_auth_hash_password("SecurePassword123!")
        >>> is_valid = flext_auth_verify_password("SecurePassword123!", password_hash)
        >>> assert is_valid is True

    Raises:
        ValueError: If rounds is outside acceptable range (4-20)
        ValueError: If password is empty or None
    """
    # Implementation with security best practices
    pass
```

---

## 🌐 **Ecosystem Integration Guidelines**

### **Cross-Project Authentication Standards**

```python
# ✅ Standard ecosystem authentication integration
from flext_core import FlextContainer, get_flext_container
from flext_auth import FlextAuth, FlextAuthMiddleware

# Register authentication service in ecosystem container
container = get_flext_container()
auth_service = FlextAuth(config=auth_config)
container.register("auth_service", auth_service)

# Use in other FLEXT projects
def integrate_with_flext_api():
    """Example integration with flext-api project"""
    from fastapi import FastAPI, Depends

    app = FastAPI()
    auth = container.get("auth_service").unwrap()

    # Add authentication middleware
    app.add_middleware(FlextAuthMiddleware, auth_service=auth)

    @app.get("/protected")
    async def protected_endpoint(user: FlextUser = Depends(auth.get_current_user)):
        return {"message": f"Hello {user.username}"}

# ✅ Consistent error handling across ecosystem
def sync_user_across_services(user_id: str) -> FlextResult[SyncResult]:
    """Sync user data across multiple FLEXT services"""
    return (
        container.get("auth_service")
        .flat_map(lambda auth: auth.get_user(user_id))
        .flat_map(lambda user: sync_to_ldap_service(user))
        .flat_map(lambda user: sync_to_oracle_service(user))
        .flat_map(lambda user: update_singer_permissions(user))
    )
```

### **Singer Ecosystem Integration**

```python
# ✅ Authentication for Singer taps and targets
from flext_auth import FlextAuth
from singer_sdk import TapBaseClass, TargetBaseClass

class FlextTapWithAuth(TapBaseClass):
    """Base tap class with FLEXT authentication"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.auth_service = FlextAuth(config.get("auth", {}))

    async def authenticate(self) -> FlextResult[FlextSecurityContext]:
        """Authenticate tap for data extraction"""
        credentials = self.config.get("credentials", {})
        return await self.auth_service.authenticate_service(
            service_name="singer_tap",
            credentials=credentials
        )

    def get_records(self, stream_name: str):
        """Get records with authentication context"""
        auth_result = asyncio.run(self.authenticate())
        if auth_result.is_failure:
            raise Exception(f"Authentication failed: {auth_result.error}")

        security_context = auth_result.data
        return self._extract_with_context(stream_name, security_context)

# ✅ FlexCore Go-Python bridge integration
class FlextAuthBridge:
    """Bridge for Go services to use Python authentication"""

    def __init__(self, auth_service: FlextAuth):
        self.auth_service = auth_service

    def validate_token_for_go(self, token: str) -> dict:
        """Validate JWT token for Go service consumption"""
        result = asyncio.run(self.auth_service.validate_jwt(token))

        return {
            "valid": result.is_success,
            "user_id": result.data.get("user_id") if result.is_success else None,
            "username": result.data.get("username") if result.is_success else None,
            "roles": result.data.get("roles", []) if result.is_success else [],
            "error": result.error if result.is_failure else None
        }

    def authenticate_for_go(self, username: str, password: str) -> dict:
        """Authenticate user for Go service consumption"""
        result = asyncio.run(self.auth_service.login(username, password))

        return {
            "success": result.is_success,
            "access_token": result.data.get("access_token") if result.is_success else None,
            "refresh_token": result.data.get("refresh_token") if result.is_success else None,
            "user": result.data.get("user") if result.is_success else None,
            "error": result.error if result.is_failure else None
        }
```

---

## 📋 **Module Creation Checklist**

### **Authentication Module Creation Checklist**

- [ ] **Naming**: Follows flext*auth*_or FlextAuth_ conventions
- [ ] **Location**: Placed in appropriate architectural layer (domain/application/infrastructure)
- [ ] **Dependencies**: Only imports from flext-core and same/lower layers
- [ ] **Types**: Complete type annotations with FlextResult return types
- [ ] **Security**: Follows authentication security best practices
- [ ] **Error Handling**: Uses FlextResult for all error conditions
- [ ] **Documentation**: Comprehensive docstrings with security considerations
- [ ] **Tests**: 95% coverage including security test scenarios
- [ ] **Public API**: Added to `__init__.py` with semantic naming
- [ ] **Examples**: Working examples demonstrating secure usage
- [ ] **Integration**: Validated with ecosystem projects and Go bridge

### **Quality Gate Checklist (Authentication-Specific)**

- [ ] **Linting**: `make lint` passes (Ruff with all rules)
- [ ] **Type Check**: `make type-check` passes (strict MyPy)
- [ ] **Tests**: `make test` passes (95% coverage including security tests)
- [ ] **Security**: `make security` passes (Bandit + pip-audit + auth-specific scans)
- [ ] **Authentication Tests**: All auth flows tested with positive/negative cases
- [ ] **Security Tests**: Password policies, session security, JWT validation tested
- [ ] **Integration Tests**: Framework integration (FastAPI, Flask) tested
- [ ] **Performance**: Authentication operations meet performance targets (<100ms)
- [ ] **Ecosystem Integration**: Works with FlexCore, Singer projects, other services

---

## 🔄 **Migration Path from Current to Target (flext-core Alignment)**

### **Phase 1: Foundation Restructuring (Week 1)**

**Current → Target Mapping:**

```python
# CURRENT STRUCTURE (needs flext-core alignment)
src/flext_auth/
├── auth.py                    # → application/handlers/commands.py + container.py
├── user.py                    # → infrastructure/repositories/user.py + domain/repositories.py
├── session.py                 # → infrastructure/repositories/session.py + domain/entities.py
├── config.py                  # → config/settings.py (FlextBaseSettings)
├── jwt.py                     # → infrastructure/services/jwt.py
└── domain/                    # ✅ Keep but enhance with FlextAggregateRoot and events

# TARGET STRUCTURE (Phase 1 - flext-core aligned)
src/flext_auth/
├── __init__.py                # ✅ Enhanced public API (FlextAuth patterns)
├── container.py               # 🆕 FlextContainer integration (CRITICAL)
├── result_types.py            # 🆕 Authentication-specific FlextResult types
├── config/                    # 🆕 FlextBaseSettings structured configuration
├── domain/                    # ✅ Enhanced with FlextAggregateRoot and events
├── application/               # 🆕 CQRS structure (commands, queries, handlers)
└── infrastructure/            # 🆕 Repository and service implementations
```

**Migration Steps:**

1. **Create FlextContainer integration** in container.py (CRITICAL)
2. **Implement FlextAggregateRoot** in domain entities with event sourcing
3. **Create CQRS command/query structure** following flext-core patterns
4. **Move services to infrastructure layer** with proper interfaces
5. **Update configuration** to use FlextBaseSettings patterns
6. **Maintain backward compatibility** in __init__.py during transition

### **Phase 2: CQRS Implementation (Week 2)**

**Command/Query Structure Creation:**

```python
# Create CQRS structure following flext-core
mkdir -p src/flext_auth/application/{commands,queries,handlers}

# Move authentication logic to command handlers
src/flext_auth/auth.py → src/flext_auth/application/handlers/commands.py

# Create specific commands (FlextCommand pattern)
# AuthenticateUserCommand, RegisterUserCommand, etc.

# Create specific queries (FlextQuery pattern)
# GetUserQuery, ValidateTokenQuery, etc.
```

### **Phase 3: Infrastructure Reorganization (Week 3)**

**Repository and Service Migration:**

```python
# Migrate repositories with interfaces
src/flext_auth/user.py → src/flext_auth/infrastructure/repositories/user.py
src/flext_auth/session.py → src/flext_auth/infrastructure/repositories/session.py

# Create repository interfaces (abstract base classes)
src/flext_auth/domain/repositories.py # Following flext-core patterns

# Migrate services
src/flext_auth/jwt.py → src/flext_auth/infrastructure/services/jwt.py
src/flext_auth/services/password_service.py → src/flext_auth/infrastructure/services/password.py
```

### **Phase 4: Integration and Testing (Week 4)**

**Framework Integration and Validation:**

```python
# Create framework integrations
src/flext_auth/integrations/fastapi.py
src/flext_auth/integrations/flask.py

# Validate ecosystem integration
# Test with FlexCore Go service
# Test with FLEXT Service
# Test with Singer projects

# Validate flext-core pattern compliance
# FlextContainer resolution
# FlextResult chaining
# Event sourcing functionality
```

---

## 📋 **flext-core Compliance Checklist**

### **Critical Integration Requirements**

**FlextContainer Integration:**
- [ ] **Service registration module** - `register_flext_auth_services()`
- [ ] **Repository interfaces** - Abstract base classes for all repositories
- [ ] **Refactor FlextAuth constructor** - Replace manual instantiation with DI
- [ ] **Container configuration** - Service lifecycle management (singleton/transient)
- [ ] **Service locator helpers** - `get_auth_service()` for external use

**Domain Events Integration:**
- [ ] **Migrate FlextUser to FlextAggregateRoot** - Inherit from base class
- [ ] **Migrate FlextSession to FlextAggregateRoot** - Add event sourcing
- [ ] **Create all domain events** - Authentication, session, security events
- [ ] **Implement event handlers** - Audit, notification, monitoring handlers
- [ ] **Add event store integration** - Event persistence and replay

**CQRS Implementation:**
- [ ] **Create command classes** - All write operations as commands
- [ ] **Create query classes** - All read operations as queries
- [ ] **Implement command handlers** - Separate handlers for each command
- [ ] **Implement query handlers** - Separate handlers for each query
- [ ] **Create command and query buses** - Orchestration and routing

### **Quality Gate Validation**

```bash
# flext-core compliance validation commands
make lint                    # Ruff linting (0 errors required)
make type-check             # MyPy type checking (FlextResult compliance)
make test-integration       # flext-core integration validation
make container-test         # FlextContainer integration tests
make event-test             # Domain event sourcing tests
make cqrs-test              # CQRS pattern tests
```

---

**Last Updated**: August 3, 2025  
**Target Audience**: FLEXT Auth developers and FLEXT ecosystem integrators  
**Scope**: Python module organization for enterprise authentication service  
**Status**: Implementation Guide for 0.9.0 → 1.0.0 Architectural Refactoring  
**flext-core Compliance**: Target 100% (currently 58/100)
