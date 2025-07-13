"""Protocol interfaces for authentication system using Python 3.13 patterns."""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Protocol
from typing import runtime_checkable

if TYPE_CHECKING:
    import datetime
    from collections.abc import Mapping
    from collections.abc import Sequence
    from typing import Any

    from flext_auth.domain.entities import User as DomainUser
    from flext_auth.models import User
    from flext_auth.types import IPAddress
    from flext_auth.types import JWTClaims
    from flext_auth.types import JWTToken
    from flext_auth.types import PlaintextPassword
    from flext_auth.types import SecurityHeaders
    from flext_auth.types import TokenMetadata
    from flext_auth.types import TokenType
    from flext_auth.types import UserAgent
    from flext_auth.types import UserID
    from flext_auth.types import UserPermissions

# Forward reference for TokenPair


@runtime_checkable
class PasswordHasher(Protocol):
    """PasswordHasher - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    hash_password(): Método específico da classe
    verify_password(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = PasswordHasher()
    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001_clean_architecture_ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    def hash_password(self, password: PlaintextPassword) -> str:
        """Hash a plaintext password using secure algorithms.

        Args:
            password: The plaintext password to hash.

        Returns:
            str: The hashed password string.

        Raises:
            ValueError: If password is invalid or hashing fails.

        """
        ...

    def verify_password(self, password: PlaintextPassword, hashed: str) -> bool:
        """Verify a plaintext password against its hash.

        Args:
            password: The plaintext password to verify.
            hashed: The hashed password to compare against.

        Returns:
            bool: True if the password matches the hash.

        Raises:
            ValueError: If verification fails or inputs are invalid.

        """
        ...


@runtime_checkable
class TokenValidator(Protocol):
    """TokenValidator - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    validate_token(): Valida dados de entrada
    is_token_revoked(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = TokenValidator()
    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001_clean_architecture_ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    async def validate_token(
        self, token: JWTToken, token_type: TokenType,
    ) -> JWTClaims | None:
        """Validate a JWT token and extract its claims.

        Args:
            token: The JWT token to validate.
            token_type: Expected type of the token.

        Returns:
            JWTClaims | None: Token claims if valid, None if invalid.

        Raises:
            TokenValidationError: If token validation fails.

        """
        ...

    async def is_token_revoked(self, token: JWTToken) -> bool:
        """Check if a token has been revoked.

        Args:
            token: The JWT token to check.

        Returns:
            bool: True if the token is revoked.

        Raises:
            TokenValidationError: If token check fails.

        """
        ...


@runtime_checkable
class UserRepository(Protocol):
    """UserRepository - Repository Pattern.

    Implementa padrão Repository para abstração de acesso a dados.
    Fornece interface unificada para operações de persistência.

    Arquitetura: Repository Pattern + Unit of Work
    Persistência: SQLAlchemy 2.0 com async support
    Padrões: Generic repositories, query abstraction

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    get_user_by_id(): Obtém dados
    get_user_by_email(): Obtém dados
    create_user(): Cria nova instância
    update_user(): Atualiza dados existentes
    get_user_permissions(): Obtém dados

    Examples:
    --------
    Uso típico da classe:

    ```python
    repo = UserRepository(session)
    entity = await repo.get_by_id(id)
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001_clean_architecture_ddd.md)

    Note:
    ----
    Esta classe segue os padrões Repository Pattern estabelecidos no projeto.

    """

    async def get_user_by_id(self, user_id: UserID) -> User | None:
        """Retrieve a user by their unique identifier.

        Args:
            user_id: The unique identifier of the user.

        Returns:
            User | None: The user if found, None otherwise.

        Raises:
            RepositoryError: If database access fails.

        """
        ...

    async def get_user_by_email(self, email: str) -> User | None:
        """Retrieve a user by their email address.

        Args:
            email: The email address of the user.

        Returns:
            User | None: The user if found, None otherwise.

        Raises:
            RepositoryError: If database access fails.

        """
        ...

    async def create_user(self, user_data: Mapping[str, Any]) -> User:
        """Create a new user with the provided data.

        Args:
            user_data: Dictionary containing user information.

        Returns:
            User: The newly created user.

        Raises:
            RepositoryError: If user creation fails.
            ValidationError: If user data is invalid.

        """
        ...

    async def update_user(self, user_id: UserID, user_data: Mapping[str, Any]) -> User:
        """Update an existing user with new data.

        Args:
            user_id: The unique identifier of the user to update.
            user_data: Dictionary containing updated user information.

        Returns:
            User: The updated user.

        Raises:
            RepositoryError: If user update fails.
            ValidationError: If user data is invalid.
            UserNotFoundError: If user does not exist.

        """
        ...

    async def get_user_permissions(self, user_id: UserID) -> UserPermissions:
        """Get all permissions for a user.

        Args:
            user_id: The unique identifier of the user.

        Returns:
            UserPermissions: The permissions associated with the user.

        Raises:
            RepositoryError: If database access fails.
            UserNotFoundError: If user does not exist.

        """
        ...


@runtime_checkable
class SecurityAuditor(Protocol):
    """SecurityAuditor - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    log_security_event(): Método específico da classe
    get_failed_login_attempts(): Obtém dados

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = SecurityAuditor()
    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001_clean_architecture_ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    async def log_security_event(
        self,
        event_type: str,
        user_id: UserID | None,
        ip_address: IPAddress | None,
        user_agent: UserAgent | None,
        metadata: TokenMetadata | None = None,
    ) -> None:
        """Log a security event for audit purposes.

        Args:
            event_type: Type of security event (e.g., 'login_success', 'login_failure').
            user_id: ID of the user involved in the event (if applicable).
            ip_address: IP address where the event originated (if available).
            user_agent: User agent string of the client (if available).
            metadata: Additional event metadata (optional).

        """
        ...

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
            window: Time window to check (defaults to a reasonable period).

        Returns:
            Number of failed login attempts matching the criteria.

        """
        ...


@runtime_checkable
class AuthenticationServiceProtocol(Protocol):
    """AuthenticationServiceProtocol - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações: Atomic operations with rollback
    Padrões: Application services, orchestration

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    authenticate_user(): Método específico da classe
    authenticate_token(): Método específico da classe
    refresh_tokens(): Método específico da classe
    revoke_token(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    service = AuthenticationServiceProtocol(config)
    result = await service.process(data)
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001_clean_architecture_ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    async def authenticate_user(
        self,
        email: str,
        password: PlaintextPassword,
        ip_address: IPAddress | None = None,
        user_agent: UserAgent | None = None,
    ) -> tuple[Any, JWTToken, JWTToken] | None:
        """Authenticate a user with email and password.

        Args:
            email: User's email address.
            password: User's plaintext password.
            ip_address: IP address for security logging (optional).
            user_agent: User agent for security logging (optional).

        Returns:
            Tuple of (User, access_token, refresh_token) on success, None on failure.

        """
        ...

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
        ...

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
        ...

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
        ...


@runtime_checkable
class AuthorizationService(Protocol):
    """AuthorizationService - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações: Atomic operations with rollback
    Padrões: Application services, orchestration

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    check_permission(): Método específico da classe
    check_role(): Método específico da classe
    get_user_permissions(): Obtém dados
    get_resource_permissions(): Obtém dados

    Examples:
    --------
    Uso típico da classe:

    ```python
    service = AuthorizationService(config)
    result = await service.process(data)
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001_clean_architecture_ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    async def check_permission(
        self,
        user_id: UserID,
        permission: str,
        resource: str | None = None,
    ) -> bool:
        """Check if a user has a specific permission.

        Args:
            user_id: The unique identifier of the user.
            permission: The permission string to check for.
            resource: Optional resource context for the permission.

        Returns:
            True if the user has the permission, False otherwise.

        """
        ...

    async def check_role(self, user_id: UserID, role: str) -> bool:
        """Check if a user has a specific role.

        Args:
            user_id: The unique identifier of the user.
            role: The role name to check for.

        Returns:
            True if the user has the role, False otherwise.

        """
        ...

    async def get_user_permissions(self, user_id: UserID) -> UserPermissions:
        """Get all permissions for a user based on their roles.

        Args:
            user_id: The unique identifier of the user.

        Returns:
            UserPermissions: All permissions the user has through their roles.

        """
        ...

    async def get_resource_permissions(
        self,
        user_id: UserID,
        resource: str,
    ) -> UserPermissions:
        """Get user permissions specific to a resource.

        Args:
            user_id: The unique identifier of the user.
            resource: The resource to get permissions for.

        Returns:
            UserPermissions: User permissions specific to the resource.

        """
        ...


@runtime_checkable
class SecurityHeaderValidator(Protocol):
    """SecurityHeaderValidator - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    validate_headers(): Valida dados de entrada
    extract_client_info(): Método específico da classe
    detect_suspicious_patterns(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = SecurityHeaderValidator()
    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001_clean_architecture_ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    def validate_headers(self, headers: SecurityHeaders) -> bool:
        """Validate security headers for proper format and values.

        Args:
            headers: Security headers to validate.

        Returns:
            True if headers are valid, False otherwise.

        """
        ...

    def extract_client_info(self, headers: SecurityHeaders) -> Mapping[str, str]:
        """Extract client information from security headers.

        Args:
            headers: Security headers to extract information from.

        Returns:
            Dictionary containing extracted client information.

        """
        ...

    def detect_suspicious_patterns(self, headers: SecurityHeaders) -> Sequence[str]:
        """Detect suspicious patterns in security headers.

        Args:
            headers: Security headers to analyze for suspicious patterns.

        Returns:
            List of detected suspicious patterns or anomalies.

        """
        ...


@runtime_checkable
class JWTService(Protocol):
    """JWT service for token creation and validation."""

    def create_token_pair(self, user: DomainUser) -> TokenPair:
        """Create access and refresh token pair for user."""
        ...

    async def verify_token(self, token: JWTToken, token_type: str) -> JWTClaims | None:
        """Verify JWT token and return claims."""
        ...

    def extract_token_claims(self, token: JWTToken) -> JWTClaims | None:
        """Extract claims from token without validation."""
        ...

    def refresh_token(
        self, refresh_token: JWTToken, user: DomainUser,
    ) -> tuple[JWTToken, JWTToken] | None:
        """Create new token pair from refresh token."""
        ...


@runtime_checkable
class TokenManager(Protocol):
    """Token storage and management service."""

    async def register_token(self, token_id: str, metadata: TokenMetadata) -> None:
        """Register a token with metadata."""
        ...

    async def validate_token(self, token_id: str) -> bool:
        """Check if token is still valid (not revoked)."""
        ...

    async def revoke_token(
        self, token_id: str, user_id: str | None, reason: str,
    ) -> bool:
        """Revoke a token."""
        ...

    async def revoke_user_tokens(
        self,
        user_id: str,
        token_type: str | None,
        requesting_user_id: str | None,
        reason: str,
    ) -> int:
        """Revoke all tokens for a user."""
        ...


# Add missing type aliases
class TokenPair:
    """Token pair containing access and refresh tokens."""

    def __init__(self, access_token: JWTToken, refresh_token: JWTToken) -> None:
        self.access_token = access_token
        self.refresh_token = refresh_token
