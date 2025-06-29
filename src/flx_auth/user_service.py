"""User authentication service with password hashing and security features."""

from __future__ import annotations

import datetime
from datetime import UTC
from datetime import datetime as dt
from typing import TYPE_CHECKING, Any, Self
from uuid import UUID, uuid4

import structlog
from flx_core.config.domain_config import MIN_PASSWORD_LENGTH, get_domain_constants
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from flx_auth.interfaces import (
    AuthenticationServiceProtocol,
    PasswordHasher,
    SecurityAuditor,
    UserRepository,
)
from flx_auth.jwt_service import JWTConfig, JWTService
from flx_auth.models import User, UserRoleEnum
from flx_auth.tokens import TokenBlacklist, TokenManager, TokenMetadata
from flx_auth.types import (
    HashedPassword,
    IPAddress,
    JWTToken,
    PlaintextPassword,
    SecurityEvent,
    TokenType,
    UserAgent,
    UserID,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


class PasswordHasherImpl(PasswordHasher):
    """Secure password hashing implementation using bcrypt."""

    def __init__(self, rounds: int | None = None) -> None:
        """Initialize password hasher with bcrypt rounds."""
        constants = get_domain_constants()
        actual_rounds = (
            rounds if rounds is not None else constants.DEFAULT_BCRYPT_ROUNDS
        )
        self.context = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto",
            bcrypt__rounds=actual_rounds,
        )

    def hash_password(self, password: PlaintextPassword) -> HashedPassword:
        """Hash a plaintext password using bcrypt."""
        result = self.context.hash(password)
        return str(result) if result is not None else ""

    def verify_password(
        self, password: PlaintextPassword, hashed: HashedPassword
    ) -> bool:
        """Verify a password against its hash."""
        result = self.context.verify(password, hashed)
        return bool(result) if result is not None else False

    def needs_update(self, hashed: HashedPassword) -> bool:
        """Check if password hash needs updating."""
        result = self.context.needs_update(hashed)
        return bool(result) if result is not None else True


class UserCreationRequest(BaseModel):
    """UserCreationRequest - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações: Atomic operations with rollback
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
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    """Request model for user creation."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    first_name: str = Field(min_length=1, max_length=50)
    last_name: str = Field(min_length=1, max_length=50)
    roles: list[str] = Field(default_factory=list)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets complexity requirements.

        Checks minimum length and character requirements: uppercase, lowercase,
        digit, and special character for enterprise security compliance.
        """
        if len(v) < MIN_PASSWORD_LENGTH:
            msg = "Password must be at least 8 characters long"
            raise ValueError(msg)

        # Check for uppercase, lowercase, digit, and special character
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v)

        if not (has_upper and has_lower and has_digit and has_special):
            msg = "Password must contain uppercase, lowercase, digit, and special character"
            raise ValueError(msg)

        return v

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> EmailStr:
        """Normalize email address to standard format.

        Converts email address to lowercase and removes leading/trailing
        whitespace to ensure consistent storage and comparison of email
        addresses across the system.

        Args:
        ----
            v: Email address to normalize

        Returns:
        -------
            Normalized email address in lowercase without whitespace


        """
        return v.lower().strip()


class UserServiceLoginRequest(BaseModel):
    """User login request with security metadata for audit tracking.

    Captures credentials with IP address and user agent for rate limiting
    and security analysis.
    """

    email: EmailStr
    password: str
    ip_address: str | None = None
    user_agent: str | None = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> EmailStr:
        """Normalize email address to lowercase and remove whitespace.

        Ensures consistent email storage and comparison by converting to lowercase
        and removing leading/trailing whitespace for authentication reliability.

        Args:
        ----
            v: Email address to normalize

        Returns:
        -------
            Normalized email address in lowercase without whitespace.


        """
        return v.lower().strip()


class AuthenticationResponse(BaseModel):
    """AuthenticationResponse - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações: Atomic operations with rollback
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
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    """Response model for successful authentication."""

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
        """Initialize in-memory storage with user and email indexes."""
        self._users: dict[UserID, User] = {}
        self._email_index: dict[str, UserID] = {}

    async def get_user_by_id(self, user_id: UserID) -> User | None:
        """Retrieve user by their unique identifier.

        Args:
        ----
            user_id: Unique user identifier

        Returns:
        -------
            User object if found, None otherwise


        """
        return self._users.get(user_id)

    async def get_user_by_email(self, email: str) -> User | None:
        """Retrieve user by their email address with case-insensitive lookup.

        Uses the email index for efficient lookups and automatically
        converts email to lowercase for consistent matching.

        Args:
        ----
            email: User's email address

        Returns:
        -------
            User object if found, None otherwise


        """
        user_id = self._email_index.get(email.lower())
        return self._users.get(user_id) if user_id else None

    async def create_user(self, user_data: Mapping[str, Any]) -> User:
        """Create a new user in the repository with email indexing.

        Creates a User entity from the provided data and stores it in both
        the main user storage and the email index for efficient lookups.

        Args:
        ----
            user_data: Dictionary containing user information

        Returns:
        -------
            Created User entity


        """
        user_id_value = user_data.get("user_id", user_data.get("id"))
        if isinstance(user_id_value, str):
            user_id_value = UUID(user_id_value)
        elif user_id_value is None:
            user_id_value = uuid4()

        user = User(
            user_id=user_id_value,
            email=user_data["email"].lower(),
            password_hash=user_data["password_hash"],
            username=user_data.get(
                "username",
                user_data.get("first_name", "") + " " + user_data.get("last_name", ""),
            ),
            roles=frozenset(user_data.get("roles", [])),
        )

        self._users[str(user.user_id)] = user
        self._email_index[user.email] = str(user.user_id)

        return user

    async def update_user(self, user_id: UserID, user_data: Mapping[str, Any]) -> User:
        """Update existing user information with timestamp tracking.

        Updates specified fields on the user entity and automatically
        sets the updated_at timestamp to track when changes were made.

        Args:
        ----
            user_id: Unique identifier of user to update
            user_data: Dictionary of fields and values to update

        Returns:
        -------
            Updated User entity if found, None if user doesn't exist


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
        """Get all permissions for a user based on their roles.

        Retrieves the complete list of permissions granted to a user
        through their assigned roles.

        Args:
        ----
            user_id: Unique user identifier

        Returns:
        -------
            List of permission strings, empty list if user not found

        """
        user = self._users.get(str(user_id))
        if not user:
            return []
        # Get permissions from all active roles
        permissions: set[str] = set()
        for role in user.get_active_roles():
            permissions.update(role.permissions)
        return list(permissions)


class SecurityAuditorImpl(SecurityAuditor):
    """Security auditor implementation for logging security events.

    Provides comprehensive security event logging for authentication,
    authorization, and other security-related activities. Maintains
    an in-memory event log with structured logging integration.
    """

    def __init__(self) -> None:
        """Initialize security auditor for logging security events.

        Sets up the security auditor with in-memory storage for security
        events, enabling comprehensive audit logging for authentication
        and authorization activities.


        """
        self._events: list[dict[str, Any]] = []

    async def log_security_event(
        self,
        event_type: str,
        user_id: UserID | None,
        ip_address: IPAddress | None,
        user_agent: UserAgent | None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        """Log a security-related event with full context and metadata.

        Records security events with timestamp, user context, and network
        information for comprehensive security auditing and analysis.

        Args:
        ----
            event_type: Type of security event (login, logout, etc.)
            user_id: User identifier if applicable
            ip_address: Client IP address if available
            user_agent: Client user agent if available
            metadata: Additional event-specific data


        """
        event = {
            "timestamp": dt.now(UTC).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "metadata": metadata or {},
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
        """Count failed login attempts within a time window for rate limiting.

        Analyzes security events to count failed login attempts filtered by
        IP address, user ID, or both within a specified time window.

        Args:
        ----
            ip_address: Filter by specific IP address
            user_id: Filter by specific user ID
            window: Time window to search (default: 1 hour)

        Returns:
        -------
            Number of failed login attempts matching the criteria

        """
        constants = get_domain_constants()
        window = window or datetime.timedelta(hours=constants.AUDIT_WINDOW_HOURS)
        cutoff = dt.now(UTC) - window

        count = 0
        for event in self._events:
            if event["event_type"] != SecurityEvent.LOGIN_FAILURE.value:
                continue

            event_time = datetime.datetime.fromisoformat(event["timestamp"])
            if event_time < cutoff:
                continue

            if ip_address and event["ip_address"] != ip_address:
                continue

            if user_id and event["user_id"] != user_id:
                continue

            count += 1

        return count


class UserService(AuthenticationServiceProtocol):
    """Complete user authentication and management service with enterprise features.

    Provides comprehensive user management including authentication, authorization,
    password management, and security auditing. Integrates JWT token management,
    password hashing, and security event logging for enterprise-grade security.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        jwt_service: JWTService,
        token_manager: TokenManager,
        password_hasher: PasswordHasher | None = None,
        security_auditor: SecurityAuditor | None = None,
    ) -> None:
        """Initialize user service with dependency injection pattern.

        Sets up the user service with all required dependencies for user
        management, authentication, and security auditing. Uses default
        implementations for optional dependencies if not provided.

        Args:
        ----
            user_repository: Repository for user data persistence
            jwt_service: Service for JWT token operations
            token_manager: Manager for token lifecycle and validation
            password_hasher: Password hashing implementation (defaults to bcrypt)
            security_auditor: Security event logging implementation


        """
        self.user_repository = user_repository
        self.jwt_service = jwt_service
        self.token_manager = token_manager
        self.password_hasher = password_hasher or PasswordHasherImpl()
        self.security_auditor = security_auditor or SecurityAuditorImpl()

    @classmethod
    def create_default(cls) -> Self:
        """Create user service with default dependencies."""
        return cls(
            user_repository=UserServiceInMemoryUserRepository(),
            jwt_service=JWTService(JWTConfig()),
            token_manager=TokenManager(TokenBlacklist()),
        )

    async def create_user(
        self, request: UserCreationRequest, roles: list[UserRoleEnum] | None = None
    ) -> User:
        """Create a new user account with validation and security logging.

        Validates the user creation request, checks for duplicate emails,
        hashes the password securely, and creates the user with appropriate
        roles. Logs the user creation event for security auditing.

        Args:
        ----
            request: User creation request with validated data
            roles: Optional list of roles to assign to the user

        Returns:
        -------
            Created User entity with assigned roles

        Raises:
        ------
            ValueError: If user with email already exists


        """
        # Check if user already exists
        existing_user = await self.user_repository.get_user_by_email(request.email)
        if existing_user:
            msg = "User with this email already exists"
            raise ValueError(msg)

        # Hash password
        password_hash = self.password_hasher.hash_password(request.password)

        # Create user
        user = User(
            user_id=uuid4(),
            email=request.email,
            password_hash=password_hash,
            username=f"{request.first_name} {request.last_name}",
            roles=frozenset(
                role.value if isinstance(role, UserRoleEnum) else role
                for role in (roles or [])
            ),
        )

        # Save to repository
        result = await self.user_repository.create_user(
            {
                "user_id": str(user.user_id),
                "email": user.email,
                "password_hash": user.password_hash,
                "username": user.username,
                "roles": list(user.roles),
            },
        )

        # Log security event
        await self.security_auditor.log_security_event(
            event_type="user_created",
            user_id=str(user.user_id),
            ip_address=None,
            user_agent=None,
        )

        return result

    async def authenticate_user(
        self,
        email: str,
        password: PlaintextPassword,
        ip_address: IPAddress | None = None,
        user_agent: UserAgent | None = None,
    ) -> tuple[User, JWTToken, JWTToken] | None:
        """Authenticate user with email and password."""
        # Get user by email
        user = await self.user_repository.get_user_by_email(email)
        if not user:
            await self._log_failed_login(
                None,
                email,
                ip_address,
                user_agent,
                "user_not_found",
            )
            return None

        # Check if account is locked
        if user.is_locked:
            await self._log_failed_login(
                str(user.user_id),
                email,
                ip_address,
                user_agent,
                "account_locked",
            )
            return None

        # Verify password
        if not self.password_hasher.verify_password(password, user.password_hash):
            user.record_failed_attempt()
            await self.user_repository.update_user(
                str(user.user_id),
                {"failed_attempts": user.failed_attempts},
            )
            await self._log_failed_login(
                str(user.user_id),
                email,
                ip_address,
                user_agent,
                "invalid_credentials",
            )
            return None

        # Check if user is active
        if not user.is_active:
            await self._log_failed_login(
                str(user.user_id),
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

        # Register tokens
        access_claims = await self.jwt_service.verify_token(access_token, "access")
        refresh_claims = await self.jwt_service.verify_token(refresh_token, "refresh")

        if access_claims and refresh_claims:
            await self.token_manager.register_token(
                access_claims["jti"],
                TokenMetadata(
                    token_id=access_claims["jti"],
                    user_id=str(user.user_id),
                    token_type=TokenType.ACCESS,
                    issued_at=dt.fromtimestamp(access_claims["iat"]),
                    expires_at=dt.fromtimestamp(access_claims["exp"]),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

            await self.token_manager.register_token(
                refresh_claims["jti"],
                TokenMetadata(
                    token_id=refresh_claims["jti"],
                    user_id=str(user.user_id),
                    token_type=TokenType.REFRESH,
                    issued_at=dt.fromtimestamp(refresh_claims["iat"]),
                    expires_at=dt.fromtimestamp(refresh_claims["exp"]),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

        # Update user login info
        user.record_login()
        await self.user_repository.update_user(
            str(user.user_id),
            {
                "last_login": user.last_login,
                "failed_attempts": user.failed_attempts,
            },
        )

        # Log successful login
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_SUCCESS.value,
            user_id=str(user.user_id),
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return user, access_token, refresh_token

    async def authenticate_token(
        self, token: JWTToken, required_permissions: Sequence[str] | None = None
    ) -> User | None:
        """Authenticate user using JWT token with permission validation.

        Validates the JWT token, checks if it's been revoked, retrieves the
        associated user, and optionally validates required permissions.

        Args:
        ----
            token: JWT access token to validate
            required_permissions: Optional list of required permissions

        Returns:
        -------
            Authenticated User if token is valid and permissions match, None otherwise


        """
        # Verify token
        claims = await self.jwt_service.verify_token(token, "access")
        if not claims:
            return None

        # Check if token is revoked
        if not await self.token_manager.validate_token(claims["jti"]):
            return None

        # Get user
        user = await self.user_repository.get_user_by_id(claims["sub"])
        if not user or not user.is_active:
            return None

        # Check permissions if required
        if required_permissions:
            # Get user permissions from all roles
            user_permissions: set[str] = set()
            for role in user.get_active_roles():
                user_permissions.update(role.permissions)

            required_permissions_set = set(required_permissions)

            if not required_permissions_set.issubset(user_permissions):
                await self.security_auditor.log_security_event(
                    event_type=SecurityEvent.PERMISSION_DENIED.value,
                    user_id=str(user.user_id),
                    ip_address=None,
                    user_agent=None,
                    metadata={"required_permissions": list(required_permissions)},
                )
                return None

        return user

    async def refresh_tokens(
        self,
        refresh_token: JWTToken,
        ip_address: IPAddress | None = None,
        user_agent: UserAgent | None = None,
    ) -> tuple[JWTToken, JWTToken] | None:
        """Refresh access and refresh tokens."""
        # Verify refresh token
        claims = await self.jwt_service.verify_token(refresh_token, "refresh")
        if not claims:
            return None

        # Check if token is revoked
        if not await self.token_manager.validate_token(claims["jti"]):
            return None

        # Get user
        user = await self.user_repository.get_user_by_id(claims["sub"])
        if not user or not user.is_active:
            return None

        # Generate new tokens
        new_tokens = self.jwt_service.refresh_token(refresh_token, user)
        if not new_tokens:
            return None

        new_access_token, new_refresh_token = new_tokens

        # Revoke old refresh token
        await self.token_manager.revoke_token(
            claims["jti"],
            str(user.user_id),
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
                    user_id=str(user.user_id),
                    token_type=TokenType.ACCESS,
                    issued_at=dt.fromtimestamp(new_access_claims["iat"]),
                    expires_at=dt.fromtimestamp(new_access_claims["exp"]),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

            await self.token_manager.register_token(
                new_refresh_claims["jti"],
                TokenMetadata(
                    token_id=new_refresh_claims["jti"],
                    user_id=str(user.user_id),
                    token_type=TokenType.REFRESH,
                    issued_at=dt.fromtimestamp(new_refresh_claims["iat"]),
                    expires_at=dt.fromtimestamp(new_refresh_claims["exp"]),
                    ip_address=ip_address,
                    user_agent=user_agent,
                ),
            )

        # Log token refresh
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.TOKEN_REFRESH.value,
            user_id=str(user.user_id),
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return new_access_token, new_refresh_token

    async def revoke_token(
        self, token: JWTToken, user_id: UserID | None = None
    ) -> bool:
        """Revoke a JWT token with security event logging.

        Extracts token information, revokes it through the token manager,
        and logs the revocation event for security auditing.

        Args:
        ----
            token: JWT token to revoke
            user_id: Optional user ID for additional validation

        Returns:
        -------
            True if token was successfully revoked, False otherwise


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
            user_id,
            "manual_revocation",
        )

        if revoked:
            # Log revocation
            await self.security_auditor.log_security_event(
                event_type=SecurityEvent.TOKEN_REVOCATION.value,
                user_id=token_user_id,
                ip_address=None,
                user_agent=None,
                metadata={"token_id": token_id},
            )

        return revoked

    async def change_password(
        self,
        user_id: UserID,
        old_password: PlaintextPassword,
        new_password: PlaintextPassword,
    ) -> bool:
        """Change user password with validation and token revocation.

        Validates the old password, updates to the new password with secure
        hashing, revokes all existing tokens, and logs the password change
        event for security auditing.

        Args:
        ----
            user_id: User identifier
            old_password: Current password for validation
            new_password: New password to set

        Returns:
        -------
            True if password was successfully changed, False otherwise


        """
        # Get user
        user = await self.user_repository.get_user_by_id(user_id)
        if not user:
            return False

        # Verify old password
        if not self.password_hasher.verify_password(old_password, user.password_hash):
            return False

        # Hash new password
        new_password_hash = self.password_hasher.hash_password(new_password)

        # Update user password and timestamp
        await self.user_repository.update_user(
            user_id,
            {
                "password_hash": new_password_hash,
                "updated_at": dt.now(UTC),
            },
        )

        # Revoke all existing tokens
        await self.token_manager.revoke_user_tokens(
            user_id,
            None,
            user_id,
            "password_change",
        )

        # Log password change
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.PASSWORD_CHANGE.value,
            user_id=user_id,
            ip_address=None,
            user_agent=None,
        )

        return True

    async def _log_failed_login(
        self,
        user_id: UserID | None,
        email: str,
        ip_address: IPAddress | None,
        user_agent: UserAgent | None,
        reason: str,
    ) -> None:
        """Log failed login attempt with detailed context for security analysis.

        Records failed login attempts with user context, network information,
        and failure reason for security monitoring and rate limiting.

        Args:
        ----
            user_id: User identifier if available
            email: Email address used in login attempt
            ip_address: Client IP address
            user_agent: Client user agent
            reason: Specific reason for login failure


        """
        await self.security_auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_FAILURE.value,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"email": email, "reason": reason},
        )
