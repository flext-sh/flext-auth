# flext-core Integration Requirements

**Critical Integration Patterns Required for FLEXT Ecosystem Compatibility**

This document outlines the mandatory flext-core integration patterns that must be implemented for FLEXT Auth to be compatible with the FLEXT ecosystem and serve as the authentication foundation for all 32 FLEXT projects.

---

## 🚨 Current Integration Status

**Integration Compliance**: 58/100 - **MAJOR REFACTORING REQUIRED**  
**Critical Blockers**: 3 patterns completely missing  
**Production Readiness**: ❌ **INCOMPATIBLE** with FLEXT ecosystem

### Integration Score Breakdown

**✅ Successfully Integrated (158 points / 270 total):**

- **FlextResult Pattern**: ✅ 95% (38/40 points) - Well implemented throughout
- **Clean Architecture**: ✅ 90% (36/40 points) - Good layer separation
- **Configuration Management**: ⚠️ 70% (28/40 points) - Uses some FlextCoreSettings patterns
- **DDD Entities**: ⚠️ 60% (24/40 points) - Rich entities but missing events
- **Testing Strategy**: ⚠️ 75% (32/40 points) - Good structure but architectural gaps

**❌ Missing Critical Integration (112 points / 270 total):**

- **FlextContainer (DI)**: ❌ 0% (0/50 points) - **CRITICAL BLOCKER**
- **Event Sourcing**: ❌ 0% (0/30 points) - **CRITICAL BLOCKER**
- **CQRS Commands**: ❌ 0% (0/32 points) - **CRITICAL BLOCKER**

### Ecosystem Impact

Due to missing critical patterns, FLEXT Auth cannot be used by:

- ❌ **FlexCore (Go service)** - Cannot inject authentication services
- ❌ **FLEXT Service (Go/Python)** - No domain events for audit
- ❌ **All 32 FLEXT projects** - No CQRS commands for enterprise operations
- ❌ **Production deployments** - Hardcoded configurations incompatible

---

## 🔴 CRITICAL: FlextContainer Integration

### Current State: ANTI-PATTERN (Manual Instantiation)

```python
# src/flext_auth/__init__.py:285-309 - CURRENT IMPLEMENTATION (WRONG)
class FlextAuth:
    def __init__(self, config: FlextAuthConfig | None = None):
        # ANTI-PATTERN: Manual service instantiation
        self._user_repository = InMemoryUserRepository()          # ❌ Manual
        self._session_repository = InMemorySessionRepository()    # ❌ Manual
        self._password_service = FlextPasswordService(rounds=12)  # ❌ Manual
        self._jwt_service = FlextJWTService(secret_key="hardcoded")  # ❌ Manual + Security Risk

        # Parameter Object Pattern (only good thing)
        dependencies = FlextAuthServiceDependencies(...)
        self._auth_service = FlextAuthService(dependencies)       # ❌ Still manual
```

### Required Implementation: FlextContainer Pattern

```python
# TARGET IMPLEMENTATION - FlextContainer Integration
from flext_core import get_flext_container, FlextContainer

class FlextAuth:
    def __init__(self, container: FlextContainer | None = None):
        # CORRECT: Use dependency injection
        self._container = container or get_flext_container()

        # Resolve all services from container
        self._user_repository = self._container.resolve("user_repository").unwrap()
        self._session_repository = self._container.resolve("session_repository").unwrap()
        self._password_service = self._container.resolve("password_service").unwrap()
        self._jwt_service = self._container.resolve("jwt_service").unwrap()
        self._auth_service = self._container.resolve("auth_service").unwrap()

# Service Registration Module (NEW REQUIREMENT)
def register_flext_auth_services(container: FlextContainer) -> None:
    """Register all FLEXT Auth services with the global container."""

    # Register repositories with interface binding
    container.register_singleton(
        "user_repository",
        InMemoryUserRepository,
        interface=UserRepositoryInterface
    )

    container.register_singleton(
        "session_repository",
        InMemorySessionRepository,
        interface=SessionRepositoryInterface
    )

    # Register services with dependency injection
    container.register_singleton("password_service", FlextPasswordService)
    container.register_singleton("jwt_service", FlextJWTService)

    # Register main auth service with all dependencies
    container.register_transient("auth_service", FlextAuthService)

    # Register command handlers for CQRS
    container.register_transient("authenticate_user_handler", AuthenticateUserCommandHandler)
    container.register_transient("register_user_handler", RegisterUserCommandHandler)
```

### Integration Points Required

**1. Service Locator Pattern:**

```python
# Global service registration (required in __init__.py)
from flext_core import get_flext_container

# Auto-register services when module is imported
container = get_flext_container()
register_flext_auth_services(container)

# Helper function for external projects
def get_auth_service() -> FlextAuthService:
    """Get the registered authentication service."""
    container = get_flext_container()
    return container.resolve("auth_service").unwrap()
```

**2. Configuration Injection:**

```python
# Configuration through DI (required)
@dataclass
class FlextAuthConfiguration:
    jwt_secret: SecretStr = Field(..., min_length=32)
    database_url: str = Field(...)
    redis_url: str = Field(...)
    bcrypt_rounds: int = Field(default=12, ge=10, le=16)

# Register configuration
container.register_singleton("auth_config", FlextAuthConfiguration)
```

**3. Interface Abstraction:**

```python
# Repository interfaces (REQUIRED)
class UserRepositoryInterface(ABC):
    @abstractmethod
    async def find_by_username(self, username: str) -> FlextResult[FlextUser | None]: ...

    @abstractmethod
    async def save(self, user: FlextUser) -> FlextResult[FlextUser]: ...

class SessionRepositoryInterface(ABC):
    @abstractmethod
    async def create_session(self, user_id: str) -> FlextResult[FlextSession]: ...

    @abstractmethod
    async def find_active_sessions(self, user_id: str) -> FlextResult[list[FlextSession]]: ...
```

---

## 🔴 CRITICAL: Domain Events Integration

### Current State: NO EVENT SOURCING

```python
# src/flext_auth/domain/entities.py - CURRENT (MISSING EVENTS)
class FlextUser:  # ❌ Should inherit from FlextAggregateRoot
    def __init__(self, username: str, email: str):
        self.id = str(uuid4())
        self.username = username
        self.email = email
        self.failed_attempts = 0
        # ❌ NO EVENT SOURCING CAPABILITY

    def login(self, password: str) -> FlextResult[bool]:
        if self.is_locked:
            return FlextResult.fail("Account locked")

        if not self.verify_password(password):
            self.failed_attempts += 1  # ❌ State change without event
            return FlextResult.fail("Invalid password")

        self.failed_attempts = 0  # ❌ State change without event
        return FlextResult.ok(True)
        # ❌ NO DOMAIN EVENTS EMITTED
```

### Required Implementation: FlextAggregateRoot Pattern

```python
# TARGET IMPLEMENTATION - Event Sourcing with flext-core
from flext_core import FlextAggregateRoot, FlextEvent

# Domain Events (REQUIRED)
@dataclass
class UserRegisteredEvent(FlextEvent):
    user_id: str
    username: str
    email: str
    timestamp: datetime

@dataclass
class UserLoggedInEvent(FlextEvent):
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str | None
    timestamp: datetime

@dataclass
class LoginFailedEvent(FlextEvent):
    user_id: str
    reason: str
    ip_address: str
    attempts_count: int
    timestamp: datetime

@dataclass
class AccountLockedEvent(FlextEvent):
    user_id: str
    locked_until: datetime
    reason: str
    timestamp: datetime

# Entity with Event Sourcing (REQUIRED)
class FlextUser(FlextAggregateRoot):  # ✅ Inherit from FlextAggregateRoot
    def __init__(self, username: str, email: str):
        super().__init__()  # Initialize event sourcing
        self.id = str(uuid4())
        self.username = username
        self.email = email
        self.failed_attempts = 0
        self.is_locked = False
        self.locked_until: datetime | None = None

        # Emit domain event
        self.raise_event(UserRegisteredEvent(
            user_id=self.id,
            username=username,
            email=email,
            timestamp=datetime.now(UTC)
        ))

    def login(self, password: str, ip_address: str, user_agent: str | None = None) -> FlextResult[FlextSession]:
        # Check if account is locked
        if self.is_locked and self.locked_until and datetime.now(UTC) < self.locked_until:
            self.raise_event(LoginFailedEvent(
                user_id=self.id,
                reason="Account locked",
                ip_address=ip_address,
                attempts_count=self.failed_attempts,
                timestamp=datetime.now(UTC)
            ))
            return FlextResult.fail("Account is locked")

        # Verify password
        if not self.verify_password(password):
            self.failed_attempts += 1

            # Emit failed login event
            self.raise_event(LoginFailedEvent(
                user_id=self.id,
                reason="Invalid password",
                ip_address=ip_address,
                attempts_count=self.failed_attempts,
                timestamp=datetime.now(UTC)
            ))

            # Lock account if too many attempts
            if self.failed_attempts >= 5:
                self.is_locked = True
                self.locked_until = datetime.now(UTC) + timedelta(minutes=30)

                self.raise_event(AccountLockedEvent(
                    user_id=self.id,
                    locked_until=self.locked_until,
                    reason="Too many failed login attempts",
                    timestamp=datetime.now(UTC)
                ))

            return FlextResult.fail("Invalid credentials")

        # Successful login
        self.failed_attempts = 0
        self.is_locked = False
        self.locked_until = None

        # Create session
        session = FlextSession.create_for_user(self.id, ip_address, user_agent)

        # Emit successful login event
        self.raise_event(UserLoggedInEvent(
            user_id=self.id,
            session_id=session.id,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=datetime.now(UTC)
        ))

        return FlextResult.ok(session)
```

### Event Handler Integration

```python
# Event Handlers for Cross-Cutting Concerns (REQUIRED)
from flext_core import FlextEventHandler

class SecurityAuditEventHandler(FlextEventHandler):
    """Handle security events for audit logging."""

    def __init__(self, audit_service: AuditService):
        self.audit_service = audit_service

    async def handle(self, event: FlextEvent) -> FlextResult[None]:
        """Log security events to audit trail."""
        if isinstance(event, (UserLoggedInEvent, LoginFailedEvent, AccountLockedEvent)):
            return await self.audit_service.log_security_event(event)
        return FlextResult.ok(None)

class NotificationEventHandler(FlextEventHandler):
    """Handle user notification events."""

    def __init__(self, notification_service: NotificationService):
        self.notification_service = notification_service

    async def handle(self, event: FlextEvent) -> FlextResult[None]:
        """Send notifications for important events."""
        if isinstance(event, AccountLockedEvent):
            return await self.notification_service.send_account_locked_notification(event)
        return FlextResult.ok(None)

# Event Handler Registration (REQUIRED)
def register_event_handlers(container: FlextContainer) -> None:
    """Register all event handlers with the container."""
    container.register_transient("security_audit_handler", SecurityAuditEventHandler)
    container.register_transient("notification_handler", NotificationEventHandler)
```

---

## 🔴 CRITICAL: CQRS Implementation

### Current State: MIXED OPERATIONS (ANTI-PATTERN)

```python
# src/flext_auth/auth.py - CURRENT (WRONG PATTERN)
class FlextAuthService:
    # ❌ Mixed read/write operations in same service
    async def authenticate_user(self, username: str, password: str) -> FlextResult[dict]:
        # This mixes command (state change) and query (data retrieval)
        user = await self.user_repository.find_by_username(username)  # Query
        if user and user.verify_password(password):
            session = await self.create_session(user)  # Command
            token = self.generate_jwt_token(user)  # Query
            return FlextResult.ok({"user": user.to_dict(), "token": token})
        return FlextResult.fail("Authentication failed")

    async def register_user(self, data: FlextUserRegistrationData) -> FlextResult[FlextUser]:
        # Mixed validation (query) and creation (command)
        existing = await self.user_repository.find_by_username(data.username)  # Query
        if existing:
            return FlextResult.fail("User already exists")

        user = FlextUser.create(data.username, data.email, data.password)  # Command
        await self.user_repository.save(user)  # Command
        return FlextResult.ok(user)
```

### Required Implementation: CQRS Pattern

```python
# TARGET IMPLEMENTATION - CQRS with flext-core patterns
from flext_core import FlextCommand, FlextQuery, FlextCommandHandler, FlextQueryHandler

# Commands (Write Operations) - REQUIRED
@dataclass
class AuthenticateUserCommand(FlextCommand):
    username: str
    password: str
    ip_address: str
    user_agent: str | None = None

@dataclass
class RegisterUserCommand(FlextCommand):
    username: str
    email: str
    password: str
    role: str = "USER"

@dataclass
class ChangePasswordCommand(FlextCommand):
    user_id: str
    current_password: str
    new_password: str

@dataclass
class RevokeSessionCommand(FlextCommand):
    session_id: str
    user_id: str

# Queries (Read Operations) - REQUIRED
@dataclass
class GetUserQuery(FlextQuery):
    user_id: str

@dataclass
class ValidateTokenQuery(FlextQuery):
    token: str

@dataclass
class GetUserPermissionsQuery(FlextQuery):
    user_id: str

@dataclass
class GetActiveSessionsQuery(FlextQuery):
    user_id: str

# Command Handlers - REQUIRED
class AuthenticateUserCommandHandler(FlextCommandHandler[AuthenticateUserCommand, AuthenticationResult]):
    def __init__(self, user_repository: UserRepositoryInterface, session_repository: SessionRepositoryInterface):
        self.user_repository = user_repository
        self.session_repository = session_repository

    async def handle(self, command: AuthenticateUserCommand) -> FlextResult[AuthenticationResult]:
        # Pure command handling - only state changes
        user_result = await self.user_repository.find_by_username(command.username)
        if not user_result.is_success or not user_result.data:
            return FlextResult.fail("User not found")

        user = user_result.data
        login_result = user.login(command.password, command.ip_address, command.user_agent)
        if not login_result.is_success:
            await self.user_repository.save(user)  # Save failed attempt count
            return FlextResult.fail(login_result.error)

        session = login_result.data
        await self.user_repository.save(user)  # Save successful login state
        await self.session_repository.save(session)

        return FlextResult.ok(AuthenticationResult(
            user_id=user.id,
            session_id=session.id,
            success=True
        ))

class RegisterUserCommandHandler(FlextCommandHandler[RegisterUserCommand, FlextUser]):
    def __init__(self, user_repository: UserRepositoryInterface):
        self.user_repository = user_repository

    async def handle(self, command: RegisterUserCommand) -> FlextResult[FlextUser]:
        # Check uniqueness
        existing_result = await self.user_repository.find_by_username(command.username)
        if existing_result.is_success and existing_result.data:
            return FlextResult.fail("Username already exists")

        existing_email_result = await self.user_repository.find_by_email(command.email)
        if existing_email_result.is_success and existing_email_result.data:
            return FlextResult.fail("Email already exists")

        # Create user (triggers UserRegisteredEvent)
        user = FlextUser(command.username, command.email)
        user.set_password(command.password)

        save_result = await self.user_repository.save(user)
        return save_result

# Query Handlers - REQUIRED
class GetUserQueryHandler(FlextQueryHandler[GetUserQuery, FlextUser]):
    def __init__(self, user_repository: UserRepositoryInterface):
        self.user_repository = user_repository

    async def handle(self, query: GetUserQuery) -> FlextResult[FlextUser]:
        return await self.user_repository.find_by_id(query.user_id)

class ValidateTokenQueryHandler(FlextQueryHandler[ValidateTokenQuery, TokenValidationResult]):
    def __init__(self, jwt_service: FlextJWTService):
        self.jwt_service = jwt_service

    async def handle(self, query: ValidateTokenQuery) -> FlextResult[TokenValidationResult]:
        return self.jwt_service.validate_token(query.token)

# Command and Query Buses - REQUIRED
class FlextAuthCommandBus:
    def __init__(self, container: FlextContainer):
        self.container = container

    async def execute(self, command: FlextCommand) -> FlextResult:
        handler_name = f"{command.__class__.__name__.replace('Command', '').lower()}_handler"
        handler = self.container.resolve(handler_name).unwrap()
        return await handler.handle(command)

class FlextAuthQueryBus:
    def __init__(self, container: FlextContainer):
        self.container = container

    async def execute(self, query: FlextQuery) -> FlextResult:
        handler_name = f"{query.__class__.__name__.replace('Query', '').lower()}_handler"
        handler = self.container.resolve(handler_name).unwrap()
        return await handler.handle(query)
```

### CQRS Integration with Main Service

```python
# Refactored Main Service - CQRS Orchestration (REQUIRED)
class FlextAuthService:
    """Main authentication service orchestrating CQRS operations."""

    def __init__(self, command_bus: FlextAuthCommandBus, query_bus: FlextAuthQueryBus):
        self.command_bus = command_bus
        self.query_bus = query_bus

    async def authenticate_user(self, username: str, password: str, ip_address: str = "127.0.0.1", user_agent: str | None = None) -> FlextResult[dict]:
        """Authenticate user using CQRS pattern."""
        # Execute command
        command = AuthenticateUserCommand(username, password, ip_address, user_agent)
        auth_result = await self.command_bus.execute(command)

        if not auth_result.is_success:
            return FlextResult.fail(auth_result.error)

        # Execute queries for response data
        user_query = GetUserQuery(auth_result.data.user_id)
        user_result = await self.query_bus.execute(user_query)

        if not user_result.is_success:
            return FlextResult.fail("Failed to retrieve user data")

        # Generate JWT token
        token_data = {
            "user_id": auth_result.data.user_id,
            "session_id": auth_result.data.session_id,
            "username": user_result.data.username
        }

        return FlextResult.ok({
            "user": user_result.data.to_dict(),
            "session_id": auth_result.data.session_id,
            "access_token": "jwt_token_here",  # Generate actual token
            "success": True
        })

    async def register_user(self, data: FlextUserRegistrationData) -> FlextResult[FlextUser]:
        """Register user using CQRS pattern."""
        command = RegisterUserCommand(data.username, data.email, data.password, data.role)
        return await self.command_bus.execute(command)
```

---

## 📋 Integration Implementation Checklist

### Phase 1: FlextContainer Integration (Week 1)

- [ ] **Create service registration module** - `register_flext_auth_services()`
- [ ] **Implement repository interfaces** - Abstract base classes for all repositories
- [ ] **Refactor FlextAuth constructor** - Replace manual instantiation with DI
- [ ] **Add container configuration** - Service lifecycle management
- [ ] **Create service locator helpers** - `get_auth_service()` for external use
- [ ] **Update all service dependencies** - Constructor injection throughout
- [ ] **Add container tests** - Verify service registration and resolution

### Phase 2: Domain Events Integration (Week 2)

- [ ] **Migrate FlextUser to FlextAggregateRoot** - Inherit from base class
- [ ] **Migrate FlextSession to FlextAggregateRoot** - Add event sourcing
- [ ] **Create all domain events** - Authentication, session, security events
- [ ] **Implement event handlers** - Audit, notification, monitoring handlers
- [ ] **Add event store integration** - Event persistence and replay
- [ ] **Register event handlers** - Container registration for all handlers
- [ ] **Add event integration tests** - Verify event emission and handling

### Phase 3: CQRS Implementation (Week 3)

- [ ] **Create command classes** - All write operations as commands
- [ ] **Create query classes** - All read operations as queries
- [ ] **Implement command handlers** - Separate handlers for each command
- [ ] **Implement query handlers** - Separate handlers for each query
- [ ] **Create command and query buses** - Orchestration and routing
- [ ] **Refactor main service** - Use CQRS buses instead of direct operations
- [ ] **Add CQRS integration tests** - Verify command/query separation

### Phase 4: Integration Testing (Week 4)

- [ ] **Create integration test suite** - Full flext-core pattern validation
- [ ] **Add performance benchmarks** - Verify container and CQRS performance
- [ ] **Test ecosystem compatibility** - Integration with other FLEXT projects
- [ ] **Add monitoring integration** - flext-observability event tracking
- [ ] **Create migration documentation** - Guide for upgrading existing code
- [ ] **Validate production readiness** - Full ecosystem deployment testing

---

## 🚀 Integration Validation

### Success Criteria

**FlextContainer Integration:**

- ✅ All services resolved from container without manual instantiation
- ✅ Service interfaces properly abstracted and mockable
- ✅ Configuration injected through container
- ✅ Service lifecycle properly managed (singleton/transient)

**Domain Events Integration:**

- ✅ All domain operations emit appropriate events
- ✅ Event handlers process cross-cutting concerns
- ✅ Event store persists all domain events
- ✅ Event replay capability for debugging

**CQRS Integration:**

- ✅ Clear separation between commands and queries
- ✅ Command handlers modify state only
- ✅ Query handlers read data only
- ✅ Buses properly route commands and queries to handlers

### Integration Testing

```python
# Integration test example (REQUIRED)
class TestFlextCoreIntegration:
    def test_container_integration(self):
        """Verify FlextContainer integration works correctly."""
        container = get_flext_container()

        # Test service resolution
        auth_service = container.resolve("auth_service").unwrap()
        assert isinstance(auth_service, FlextAuthService)

        # Test dependency injection
        user_repo = container.resolve("user_repository").unwrap()
        assert isinstance(user_repo, UserRepositoryInterface)

    def test_domain_events_integration(self):
        """Verify domain events are emitted and handled."""
        container = get_flext_container()
        auth_service = container.resolve("auth_service").unwrap()

        # Create user (should emit UserRegisteredEvent)
        result = await auth_service.register_user(test_data)
        assert result.is_success

        # Verify event was emitted
        events = result.data.uncommitted_events
        assert any(isinstance(e, UserRegisteredEvent) for e in events)

    def test_cqrs_integration(self):
        """Verify CQRS patterns work correctly."""
        container = get_flext_container()
        command_bus = container.resolve("command_bus").unwrap()
        query_bus = container.resolve("query_bus").unwrap()

        # Execute command
        command = AuthenticateUserCommand("test_user", "password", "127.0.0.1")
        result = await command_bus.execute(command)
        assert result.is_success

        # Execute query
        query = GetUserQuery(result.data.user_id)
        user_result = await query_bus.execute(query)
        assert user_result.is_success
```

---

This integration with flext-core is **MANDATORY** for FLEXT Auth to serve as the authentication foundation for the FLEXT ecosystem. Without these patterns, the project cannot integrate with other FLEXT services and is unsuitable for production use.
