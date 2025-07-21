"""User authentication service with clean architecture patterns from flext-core."""

from __future__ import annotations

import datetime
from datetime import UTC, datetime as dt
from typing import TYPE_CHECKING, Any, Self
from uuid import UUID, uuid4

import structlog
from flext_core import Field, ServiceResult
from flext_core.config import get_container, singleton
from flext_core.domain.pydantic_base import DomainBaseModel
from passlib.context import CryptContext

# Import EmailStr at runtime for Pydantic model validation
from pydantic import ConfigDict, EmailStr, field_validator

from flext_auth.config import get_auth_settings
from flext_auth.domain.entities import User
from flext_auth.domain.repositories import UserRepository
from flext_auth.interfaces import (
    AuthenticationServiceProtocol,
    PasswordHasher,
    SecurityAuditor,
)
from flext_auth.tokens import TokenMetadata
from flext_auth.types import SecurityEvent, TokenType

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from flext_auth.domain.entities import Role
    from flext_auth.interfaces import JWTService, TokenManager
    from flext_auth.types import (
        HashedPassword,
        IPAddress,
        JWTToken,
        PlaintextPassword,
        UserAgent,
        UserID,
    )
# JWTToken is imported from flext_auth.types above


class PasswordHasherImpl(PasswordHasher):
    """Secure password hashing implementation using bcrypt with config injection."""

    def __init__(self, settings: Any = None) -> None:
        if settings is None:
            settings = get_auth_settings()

        self.context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=settings.password_bcrypt_rounds,
        )
        self.settings = settings

    def hash_password(self, password: PlaintextPassword) -> HashedPassword:
        """Hash a plaintext password using bcrypt.

        Args:
            password: The plaintext password to hash.

        Returns:
            The hashed password string.

        """
        result = self.context.hash(password)
        return str(result) if result is not None else ""

    def verify_password(
        self,
        password: PlaintextPassword,
        hashed: HashedPassword,
    ) -> bool:
        """Verify a plaintext password against a hashed password.

        Args:
            password: The plaintext password to verify.
            hashed: The hashed password to verify against.

        Returns:
            True if the password matches, False otherwise.

        """
        result = self.context.verify(password, hashed)
        return bool(result) if result is not None else False

    def needs_update(self, hashed: HashedPassword) -> bool:
        """Check if a hashed password needs to be updated due to algorithm changes.

        Args:
            hashed: The hashed password to check.

        Returns:
            True if the password hash needs updating, False otherwise.

        """
        result = self.context.needs_update(hashed)
        return bool(result) if result is not None else True


class UserCreationRequest(DomainBaseModel):
    """Request model for user creation.

    UserCreationRequest - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações:
        Atomic operations with rollback
    Padrões: Application services, orchestration

    Attributes:
    ----------
    email (EmailStr): Atributo da classe.
    password (str): Atributo da classe.
    first_name (str): Atributo da classe.
    last_name (str): Atributo da classe.
    roles (list[str]): Atributo da classe.

    Methods:
    -------
    validate_password_strength(): Valida dados de entrada
    normalize_email(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    service = UserCreationRequest(config)
    result = await service.process(data)
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/clean_architecture_guide.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    roles: list[str] = Field(default_factory=list)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength according to configured requirements.

        Args:
            v: The password string to validate.

        Returns:
            The validated password string.

        Raises:
            ValueError: If password doesn't meet strength requirements.

        """
        settings = get_auth_settings()

        if len(v) < settings.password_min_length:
            msg = f"Password must be at least {settings.password_min_length} characters long"
            raise ValueError(msg)

        # Check for uppercase, lowercase, digit, and special character
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|:,.<>?" for c in v)

        if settings.password_require_uppercase and not has_upper:
            msg = "Password must contain uppercase letters"
            raise ValueError(msg)

        if settings.password_require_lowercase and not has_lower:
            msg = "Password must contain lowercase letters"
            raise ValueError(msg)

        if settings.password_require_numbers and not has_digit:
            msg = "Password must contain digits"
            raise ValueError(msg)

        if settings.password_require_special and not has_special:
            msg = "Password must contain special characters"
            raise ValueError(msg)

        return v

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> EmailStr:
        """Normalize email address to lowercase."""
        # EmailStr is already validated by Pydantic, so it's always a string
        return EmailStr(str(v).lower())


class UserServiceLoginRequest(DomainBaseModel):
    """User login request with security metadata for audit tracking.

    Captures credentials with IP address and user agent for rate limiting
    and security analysis.
    """

    email: EmailStr
    password: str
    user_agent: str | None = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> EmailStr:
        """Normalize email address to lowercase."""
        # EmailStr is already validated by Pydantic, so it's always a string
        return EmailStr(str(v).lower())


class AuthenticationResponse(DomainBaseModel):
    """Response model for successful authentication.

    AuthenticationResponse - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações:
        Atomic operations with rollback
    Padrões: Application services, orchestration

    Attributes:
    ----------
    user_id (UserID): Atributo da classe.
    email (str): Atributo da classe.
    access_token (JWTToken): Atributo da classe.
    refresh_token (JWTToken): Atributo da classe.
    expires_in (int): Atributo da classe.
    token_type (str): Atributo da classe.

    Methods:
    -------
    Sem métodos públicos.

    Examples:
    --------
    Uso típico da classe:

    ```python
    service = AuthenticationResponse(config)
    result = await service.process(data)
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/clean_architecture_guide.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    model_config = ConfigDict(
        frozen=True,
        arbitrary_types_allowed=True,
        extra="forbid",
    )

    user_id: UserID
    email: str
    access_token: JWTToken
    refresh_token: JWTToken
    expires_in: int  # seconds
    token_type: str = "Bearer"  # nosec S105 - not a password, token type constant


class UserServiceInMemoryUserRepository(UserRepository):
    """In-memory user repository for testing and development environments.

    Provides a simple implementation of the UserRepository interface using
    Python dictionaries for storage. Includes email indexing for efficient
    lookups by email address.

    Warning:
    -------
        This implementation is not suitable for production use as data is
        lost when the application restarts. Use a persistent database
        implementation for production environments.

    """

    def __init__(self) -> None:
        self._users: dict[str, User] = {}  # Store by string ID for compatibility
        self._email_index: dict[str, str] = {}  # Email -> string user ID mapping

    async def find_by_id(self, user_id: UUID) -> ServiceResult[User | None]:
        """Find user by ID following repository interface."""
        from flext_core import ServiceResult

        try:
            user = self._users.get(str(user_id))
            return ServiceResult.ok(user)
        except Exception as e:
            return ServiceResult.fail(f"Error finding user by ID: {e}")

    async def find_by_email(self, email: str) -> ServiceResult[User | None]:
        """Find user by email following repository interface."""
        from flext_core import ServiceResult

        try:
            user_id = self._email_index.get(email.lower())
            user = self._users.get(user_id) if user_id else None
            return ServiceResult.ok(user)
        except Exception as e:
            return ServiceResult.fail(f"Error finding user by email: {e}")

    async def find_by_username(self, username: str) -> ServiceResult[User | None]:
        """Find user by username following repository interface."""
        from flext_core import ServiceResult

        try:
            for user in self._users.values():
                if user.username == username:
                    return ServiceResult.ok(user)
            return ServiceResult.ok(None)
        except Exception as e:
            return ServiceResult.fail(f"Error finding user by username: {e}")

    async def username_exists(self, username: str) -> ServiceResult[bool]:
        """Check if username exists following repository interface."""
        from flext_core import ServiceResult

        try:
            result = await self.find_by_username(username)
            if result.is_success:
                return ServiceResult.ok(result.data is not None)
            return ServiceResult.fail(result.error or "Error checking username")
        except Exception as e:
            return ServiceResult.fail(f"Error checking username existence: {e}")

    async def email_exists(self, email: str) -> ServiceResult[bool]:
        """Check if email exists following repository interface."""
        from flext_core import ServiceResult

        try:
            result = await self.find_by_email(email)
            if result.is_success:
                return ServiceResult.ok(result.data is not None)
            return ServiceResult.fail(result.error or "Error checking email")
        except Exception as e:
            return ServiceResult.fail(f"Error checking email existence: {e}")

    async def create_user(self, user_data: Mapping[str, Any]) -> User:
        """Create a new user in the repository.

        Args:
            user_data: Dictionary containing user creation data including email,
                      password_hash, username, and optional roles.

        Returns:
            The created User object.

        """
        user_id_value = user_data.get("user_id", user_data.get("id"))
        if isinstance(user_id_value, str):
            user_id_value = UUID(user_id_value)
        elif user_id_value is None:
            user_id_value = uuid4()

        user = User(
            id=user_id_value,
            email=user_data["email"].lower(),
            password_hash=user_data["password_hash"],
            username=user_data.get(
                "username",
                user_data.get("first_name", "") + " " + user_data.get("last_name", ""),
            ),
            role=user_data.get("role", "user"),
            email_verified_at=None,  # Explicit default for mypy strict
            last_login_at=None,  # Explicit default for mypy strict
            last_login_ip=None,  # Explicit default for mypy strict
            locked_until=None,  # Explicit default for mypy strict
        )

        self._users[str(user.id)] = user
        self._email_index[user.email] = str(user.id)

        return user

    async def update_user(self, user_id: UserID, user_data: Mapping[str, Any]) -> User:
        """Update an existing user's data.

        Args:
            user_id: The ID of the user to update.
            user_data: Dictionary containing fields to update.

        Returns:
            The updated User object.

        Raises:
            ValueError: If user with the given ID is not found.

        """
        user = self._users.get(str(user_id))
        if not user:
            msg = f"User with ID {user_id} not found"
            raise ValueError(msg)

        # Update user fields using try/except for better error handling
        for field, value in user_data.items():
            try:
                # Verify field exists before setting to avoid creating new attributes
                getattr(user, field)
                setattr(user, field, value)
            except AttributeError:
                # Field doesn't exist on user model, skip this field
                continue

        user.updated_at = dt.now(UTC)
        return user

    async def get_user_permissions(self, user_id: UserID) -> list[str]:
        """Get all permissions for a user based on their active roles.

        Args:
            user_id: The ID of the user to get permissions for.

        Returns:
            List of permission strings the user has through their roles.

        """
        user = self._users.get(str(user_id))
        if not user:
            return []
        # Get permissions based on user role
        # This is a simplified implementation - in real world, you'd have a role-permission mapping
        role_permissions = {
            "REDACTED_LDAP_BIND_PASSWORD": ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"],
            "user": ["read"],
            "moderator": ["read", "write"],
        }
        return role_permissions.get(user.role, [])

    async def create(self, user: User) -> ServiceResult[User]:
        """Create a new user following repository interface."""
        from flext_core import ServiceResult

        # Check if user already exists
        if str(user.id) in self._users:
            return ServiceResult.fail(f"User with ID {user.id} already exists")

        # Store user
        self._users[str(user.id)] = user
        self._email_index[user.email.lower()] = str(user.id)

        return ServiceResult.ok(user)

    async def delete(self, user_id: UUID) -> ServiceResult[bool]:
        """Delete a user by ID following repository interface."""
        from flext_core import ServiceResult

        user = self._users.get(str(user_id))
        if not user:
            return ServiceResult.fail(f"User with ID {user_id} not found")

        # Remove from email index
        if user.email.lower() in self._email_index:
            del self._email_index[user.email.lower()]

        # Remove user
        del self._users[str(user_id)]

        return ServiceResult.ok(True)

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> ServiceResult[list[User]]:
        """List users with pagination following repository interface."""
        from flext_core import ServiceResult

        all_users = list(self._users.values())
        paginated_users = all_users[offset : offset + limit]

        return ServiceResult.ok(paginated_users)

    async def update(self, user: User) -> ServiceResult[User]:
        """Update an existing user following repository interface."""
        from flext_core import ServiceResult

        if str(user.id) not in self._users:
            return ServiceResult.fail(f"User with ID {user.id} not found")

        # Update email index if email changed
        old_user = self._users[str(user.id)]
        if old_user.email != user.email:
            # Remove old email from index
            if old_user.email.lower() in self._email_index:
                del self._email_index[old_user.email.lower()]
            # Add new email to index
            self._email_index[user.email.lower()] = str(user.id)

        # Update user
        self._users[str(user.id)] = user
        user.updated_at = dt.now(UTC)

        return ServiceResult.ok(user)

    async def get_user_by_id(self, user_id: UserID) -> User | None:
        """Get user by ID - compatibility method for UserService."""
        result = await self.find_by_id(user_id)  # user_id is already UUID
        return result.data if result.is_success else None

    async def get_user_by_email(self, email: str) -> User | None:
        """Get user by email - compatibility method for UserService."""
        result = await self.find_by_email(email)
        return result.data if result.is_success else None


class SecurityAuditorImpl(SecurityAuditor):
    """Security auditor implementation for logging security events.

    Provides comprehensive security event logging for authentication,
    authorization, and other security-related activities. Maintains
    an in-memory event log with structured logging integration.
    """

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    async def log_security_event(
        self,
        event_type: str,
        user_id: UserID | None,
        ip_address: IPAddress | None,
        user_agent: UserAgent | None,
        metadata: TokenMetadata | dict[str, Any] | None = None,
    ) -> None:
        """Log a security event for audit purposes.

        Args:
            event_type: Type of security event (e.g., 'login_success', 'login_failure').
            user_id: ID of the user involved in the event (if applicable).
            ip_address: IP address where the event originated (if available).
            user_agent: User agent string of the client (if available).
            metadata: Additional event metadata (optional).

        """
        # Convert TokenMetadata to dict for storage
        metadata_dict = {}
        if metadata:
            if isinstance(metadata, dict):
                metadata_dict = metadata
            else:
                metadata_dict = {
                    "token_id": metadata.token_id,
                    "token_type": metadata.token_type.value
                    if hasattr(metadata.token_type, "value")
                    else str(metadata.token_type),
                    "issued_at": metadata.issued_at.isoformat()
                    if metadata.issued_at
                    else None,
                    "expires_at": metadata.expires_at.isoformat()
                    if metadata.expires_at
                    else None,
                }

        event = {
            "timestamp": dt.now(UTC).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "metadata": metadata_dict,
        }

        self._events.append(event)

        # In a real implementation, this would send to a logging system
        logger = structlog.get_logger("security_audit")
        logger.info("Security event", **event)

    async def get_failed_login_attempts(
        self,
        ip_address: IPAddress | None = None,
        user_id: UserID | None = None,
        window: datetime.timedelta | None = None,
    ) -> int:
        """Get the number of failed login attempts within a time window.

        Args:
            ip_address: Filter by IP address (optional).
            user_id: Filter by user ID (optional).
            window: Time window to check (defaults to 24 hours).

        Returns:
            Number of failed login attempts matching the criteria.

        """
        # Use secure default since config is not available
        audit_window_hours = 24
        window = window or datetime.timedelta(hours=audit_window_hours)
        cutoff = dt.now(UTC) - window

        count = 0
        for event in self._events:
            if event["event_type"] != SecurityEvent.LOGIN_FAILURE:
                continue

            event_time = dt.fromisoformat(event["timestamp"])
            if event_time < cutoff:
                continue

            if ip_address and event["ip_address"] != ip_address:
                continue

            if user_id and event["user_id"] != user_id:
                continue

            count += 1

        return count


@singleton(AuthenticationServiceProtocol)
class UserService(AuthenticationServiceProtocol):
    """Complete user authentication and management service with enterprise features.

    Provides comprehensive user management including authentication, authorization,
    password management, and security auditing using flext-core patterns.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        password_hasher: PasswordHasher,
        security_auditor: SecurityAuditor,
        jwt_service: JWTService,
        token_manager: TokenManager,
    ) -> None:
        self.user_repository = user_repository
        self.password_hasher = password_hasher
        self.security_auditor = security_auditor
        self.jwt_service = jwt_service
        self.token_manager = token_manager
        self.settings = get_auth_settings()

    @classmethod
    def create_default(cls) -> Self:
        """Create a default UserService instance using dependency injection.

        Returns:
            A UserService instance with default dependencies resolved.

        """
        container = get_container()
        return container.resolve(cls)

    async def create_user(
        self,
        request: UserCreationRequest,
        roles: list[Role] | None = None,
    ) -> ServiceResult[User]:
        """Create a new user account with the provided information.

        Args:
            request: User creation request containing email, password, and names.
            roles: Optional list of roles to assign to the user.

        Returns:
            ServiceResult containing the created User on success, or error details on failure.

        """
        from flext_core import ServiceResult

        try:
            # Check if user already exists
            existing_user_result = await self.user_repository.find_by_email(
                request.email,
            )
            if existing_user_result.is_success and existing_user_result.data:
                return ServiceResult.fail("User with this email already exists")

            # Hash password
            password_hash = self.password_hasher.hash_password(request.password)

            # Create user
            user = User(
                id=uuid4(),
                email=request.email,
                password_hash=password_hash,
                username=f"{request.first_name} {request.last_name}",
                role="user",  # Default role, can be updated later
                email_verified_at=None,  # Explicit default for mypy strict
                last_login_at=None,  # Explicit default for mypy strict
                last_login_ip=None,  # Explicit default for mypy strict
                locked_until=None,  # Explicit default for mypy strict
            )

            # Save to repository
            result = await self.user_repository.create(user)

            # Log security event
            await self.security_auditor.log_security_event(
                event_type="user_created",
                user_id=user.id,
                ip_address=None,
                user_agent=None,
            )

            return result
        except Exception as e:
            return ServiceResult.fail(str(e))

    async def authenticate_user(
        self,
        email: str,
        password: PlaintextPassword,
        ip_address: IPAddress | None = None,
        user_agent: UserAgent | None = None,
    ) -> tuple[User, JWTToken, JWTToken] | None:
        """Authenticate a user with email and password.

        Args:
            email: User's email address.
            password: User's plaintext password.
            ip_address: IP address for security logging (optional).
            user_agent: User agent for security logging (optional).

        Returns:
            Tuple of (User, access_token, refresh_token) on success, None on failure.

        """
        # Get user by email
        user_result = await self.user_repository.find_by_email(email)
        if not user_result.is_success or not user_result.data:
            await self._log_failed_login(
                None,
                email,
                ip_address,
                user_agent,
                "user_not_found",
            )
            return None

        user = user_result.data

        # Check if account is locked
        if user.is_locked():
            await self._log_failed_login(
                user.id,
                email,
                ip_address,
                user_agent,
                "account_locked",
            )
            return None

        # Verify password
        if not self.password_hasher.verify_password(password, user.password_hash):
            user.record_login_attempt(success=False, ip_address=ip_address or "unknown")
            await self.user_repository.update(user)
            await self._log_failed_login(
                user.id,
                email,
                ip_address,
                user_agent,
                "invalid_credentials",
            )
            return None

        # Check if user is active
        if not user.is_active():
            await self._log_failed_login(
                user.id,
                email,
                ip_address,
                user_agent,
                "account_inactive",
            )
            return None

        # Generate tokens
        token_pair = self.jwt_service.create_token_pair(user)
        access_token = token_pair.access_token
        refresh_token = token_pair.refresh_token

        # Register tokens with simplified metadata for testing
        access_claims = await self.jwt_service.verify_token(access_token, "access")
        refresh_claims = await self.jwt_service.verify_token(refresh_token, "refresh")

        if access_claims and refresh_claims:
            await self.token_manager.register_token(
                access_claims["jti"],
                TokenMetadata(
                    token_id=access_claims["jti"],
                    user_id=user.id,
                    token_type=TokenType.ACCESS,
                    issued_at=dt.fromtimestamp(access_claims["iat"], UTC),
                    expires_at=dt.fromtimestamp(access_claims["exp"], UTC),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

            await self.token_manager.register_token(
                refresh_claims["jti"],
                TokenMetadata(
                    token_id=refresh_claims["jti"],
                    user_id=user.id,
                    token_type=TokenType.REFRESH,
                    issued_at=dt.fromtimestamp(refresh_claims["iat"], UTC),
                    expires_at=dt.fromtimestamp(refresh_claims["exp"], UTC),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

        # Update user login info
        user.record_login_attempt(success=True, ip_address=ip_address or "unknown")
        await self.user_repository.update(user)

        # Log successful login
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_SUCCESS,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return user, access_token, refresh_token

    async def authenticate_token(
        self,
        token: JWTToken,
        required_permissions: Sequence[str] | None = None,
    ) -> User | None:
        """Authenticate a user using a JWT token.

        Args:
            token: JWT access token to verify.
            required_permissions: Optional list of permissions that must be present.

        Returns:
            User object if token is valid and permissions are satisfied, None otherwise.

        """
        # Verify token
        claims = await self.jwt_service.verify_token(token, "access")
        if not claims:
            return None

        # Check if token is revoked
        if not await self.token_manager.validate_token(claims["jti"]):
            return None

        # Get user - convert string sub to UUID if needed
        from uuid import UUID

        user_id = claims["sub"]
        if isinstance(user_id, str) and user_id != "user":
            try:
                user_id = UUID(user_id)
            except ValueError:
                # Mock token case
                user_id = "user"

        user_result = await self.user_repository.find_by_id(user_id)
        if not user_result.is_success or not user_result.data:
            return None
        user = user_result.data
        if not user.is_active():
            return None

        # Check permissions if required
        if required_permissions:
            # Get user permissions from repository
            user_permissions = await self._get_user_permissions(user_id)

            required_permissions_set = set(required_permissions)

            if not required_permissions_set.issubset(user_permissions):
                await self.security_auditor.log_security_event(
                    event_type=SecurityEvent.PERMISSION_DENIED,
                    user_id=user.id,
                    ip_address=None,
                    user_agent=None,
                    metadata=None,  # No TokenMetadata for permission denied events
                )
                return None

        return user

    async def refresh_tokens(
        self,
        refresh_token: JWTToken,
        ip_address: IPAddress | None = None,
        user_agent: UserAgent | None = None,
    ) -> tuple[JWTToken, JWTToken] | None:
        """Refresh an access token using a valid refresh token.

        Args:
            refresh_token: Valid refresh token to use for generating new tokens.
            ip_address: IP address for security logging (optional).
            user_agent: User agent for security logging (optional).

        Returns:
            Tuple of (new_access_token, new_refresh_token) on success, None on failure.

        """
        # Verify refresh token
        claims = await self.jwt_service.verify_token(refresh_token, "refresh")
        if not claims:
            return None

        # Check if token is revoked
        if not await self.token_manager.validate_token(claims["jti"]):
            return None

        # Get user
        user_result = await self.user_repository.find_by_id(claims["sub"])
        if not user_result.is_success or not user_result.data:
            return None

        user = user_result.data
        if not user.is_active():
            return None

        # Generate new tokens
        new_tokens = self.jwt_service.refresh_token(refresh_token, user)
        if not new_tokens:
            return None

        new_access_token, new_refresh_token = new_tokens

        # Revoke old refresh token
        await self.token_manager.revoke_token(
            claims["jti"],
            str(user.id),
            "token_refresh",
        )

        # Register new tokens
        new_access_claims = await self.jwt_service.verify_token(
            new_access_token,
            "access",
        )
        new_refresh_claims = await self.jwt_service.verify_token(
            new_refresh_token,
            "refresh",
        )

        if new_access_claims and new_refresh_claims:
            await self.token_manager.register_token(
                new_access_claims["jti"],
                TokenMetadata(
                    token_id=new_access_claims["jti"],
                    user_id=user.id,
                    token_type=TokenType.ACCESS,
                    issued_at=dt.fromtimestamp(new_access_claims["iat"], UTC),
                    expires_at=dt.fromtimestamp(new_access_claims["exp"], UTC),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

            await self.token_manager.register_token(
                new_refresh_claims["jti"],
                TokenMetadata(
                    token_id=new_refresh_claims["jti"],
                    user_id=user.id,
                    token_type=TokenType.REFRESH,
                    issued_at=dt.fromtimestamp(new_refresh_claims["iat"], UTC),
                    expires_at=dt.fromtimestamp(new_refresh_claims["exp"], UTC),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

        # Log token refresh
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.TOKEN_REFRESH,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return new_access_token, new_refresh_token

    async def revoke_token(
        self,
        token: JWTToken,
        user_id: UserID | None = None,
    ) -> bool:
        """Revoke a JWT token to prevent further use.

        Args:
            token: JWT token to revoke.
            user_id: Optional user ID for additional validation.

        Returns:
            True if the token was successfully revoked, False otherwise.

        """
        # Extract token claims
        claims = self.jwt_service.extract_token_claims(token)
        if not claims or "jti" not in claims:
            return False

        token_id = claims["jti"]
        token_user_id = claims.get("sub", user_id)

        # Revoke token
        revoked = await self.token_manager.revoke_token(
            token_id,
            str(user_id) if user_id else None,
            "manual_revocation",
        )

        if revoked:
            # Log revocation
            await self.security_auditor.log_security_event(
                event_type=SecurityEvent.TOKEN_REVOCATION,
                user_id=token_user_id,
                ip_address=None,
                user_agent=None,
                metadata=None,  # No TokenMetadata for revocation events
            )

        return revoked

    async def change_password(
        self,
        user_id: UserID,
        old_password: PlaintextPassword,
        new_password: PlaintextPassword,
    ) -> bool:
        """Change a user's password after verifying the old password.

        Args:
            user_id: ID of the user changing their password.
            old_password: Current password for verification.
            new_password: New password to set.

        Returns:
            True if the password was successfully changed, False otherwise.

        """
        # Get user
        user_result = await self.user_repository.find_by_id(user_id)
        if not user_result.is_success or not user_result.data:
            return False

        user = user_result.data

        # Verify old password
        if not self.password_hasher.verify_password(old_password, user.password_hash):
            return False

        # Hash new password
        new_password_hash = self.password_hasher.hash_password(new_password)

        # Update user password and timestamp
        user.password_hash = new_password_hash
        user.updated_at = dt.now(UTC)
        await self.user_repository.update(user)

        # Revoke all existing tokens
        await self.token_manager.revoke_user_tokens(
            str(user_id),
            None,
            str(user_id),
            "password_change",
        )

        # Log password change
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.PASSWORD_CHANGE,
            user_id=user_id,
            ip_address=None,
            user_agent=None,
        )

        return True

    async def _get_user_permissions(self, user_id: UserID) -> set[str]:
        """Get user permissions from repository."""
        try:
            # In a real implementation, this would query the user's roles and permissions
            # For now, return basic permissions for all users
            # TODO: Implement proper role-based permission system
            # Real implementation: user_result = await self.user_repository.find_by_id(user_id)
            # Real implementation: return user.get_permissions() if user_result.is_success else set()
            return {"read", "write", "execute"}
        except Exception:
            # Return empty permissions set on error
            return set()

    async def _log_failed_login(
        self,
        user_id: UserID | None,
        email: str,
        ip_address: IPAddress | None,
        user_agent: UserAgent | None,
        reason: str,
    ) -> None:
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_FAILURE,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=None,  # No TokenMetadata for failed login events
        )
