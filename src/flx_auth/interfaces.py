"""Protocol interfaces for authentication system using Python 3.13 patterns."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    import datetime
    from collections.abc import Mapping, Sequence
    from typing import Any

    from flx_auth.models import User
    from flx_auth.types import (
        IPAddress,
        JWTClaims,
        JWTToken,
        PlaintextPassword,
        SecurityHeaders,
        TokenMetadata,
        TokenType,
        UserAgent,
        UserID,
        UserPermissions,
    )


@runtime_checkable
class PasswordHasher(Protocol):
    r"""PasswordHasher - Framework Component.

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
    instance = PasswordHasher()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Protocol for password hashing operations."""

    def hash_password(self, password: PlaintextPassword) -> str:
        """Hash a plaintext password securely.

        Transforms a plaintext password into a secure hash using enterprise-grade
        hashing algorithms following security best practices.

        Args:
        ----
            password: The plaintext password to hash

        Returns:
        -------
            Secure hash of the password

        Note:
        ----
            Implements enterprise security patterns with proper salt and timing.

        """
        ...

    def verify_password(self, password: PlaintextPassword, hashed: str) -> bool:
        """Verify a password against its hash.

        Args:
        ----
            password: The plaintext password to verify
            hashed: The stored hash to verify against

        Returns:
        -------
            True if password matches hash, False otherwise

        """
        ...


@runtime_checkable
class TokenValidator(Protocol):
    r"""TokenValidator - Framework Component.

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
    instance = TokenValidator()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Protocol for JWT token validation."""

    async def validate_token(
        self, token: JWTToken, token_type: TokenType
    ) -> JWTClaims | None:
        """Validate a JWT token and return claims if valid.

        Args:
        ----
            token: The JWT token to validate
            token_type: Expected type of the token

        Returns:
        -------
            Token claims if valid, None if invalid

        """
        ...

    async def is_token_revoked(self, token: JWTToken) -> bool:
        """Check if a token has been revoked.

        Args:
        ----
            token: The JWT token to check

        Returns:
        -------
            True if token is revoked, False otherwise

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
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Repository Pattern estabelecidos no projeto.

    """

    """Protocol for user data access."""

    async def get_user_by_id(self, user_id: UserID) -> User | None:
        """Retrieve user by unique identifier.

        Finds and returns user information based on the provided user ID
        with secure data access patterns.

        Args:
        ----
            user_id: Unique identifier for the user

        Returns:
        -------
            User object if found, None otherwise

        Note:
        ----
            Provides data integrity validation.

        """
        ...

    async def get_user_by_email(self, email: str) -> User | None:
        """Retrieve user by email address.

        Searches for and returns user information based on the provided
        email address with secure data access patterns.

        Args:
        ----
            email: Email address to search for

        Returns:
        -------
            User object if found, None otherwise

        Note:
        ----
            Provides email validation and security.

        """
        ...

    async def create_user(self, user_data: Mapping[str, Any]) -> User:
        """Create a new user in the system.

        Creates a new user account with the provided data following
        enterprise user management patterns and validation rules.

        Args:
        ----
            user_data: Dictionary containing user information

        Returns:
        -------
            Newly created User object

        Note:
        ----
            Provides validation and audit trails for user operations.

        """
        ...

    async def update_user(self, user_id: UserID, user_data: Mapping[str, Any]) -> User:
        """Update existing user information.

        Updates user account data with the provided information following
        enterprise data modification patterns and validation rules.

        Args:
        ----
            user_id: Unique identifier for the user to update
            user_data: Dictionary containing updated user information

        Returns:
        -------
            Updated User object

        Note:
        ----
            Provides change tracking and validation.

        """
        ...

    async def get_user_permissions(self, user_id: UserID) -> UserPermissions:
        """Get all permissions for a user.

        Retrieves comprehensive permission set for the specified user including
        role-based permissions and direct grants with security validation.

        Args:
        ----
            user_id: Unique identifier for the user

        Returns:
        -------
            Complete set of user permissions for authorization checks

        Note:
        ----
            Provides permission aggregation from roles and direct assignments.

        """
        ...


# ZERO TOLERANCE: Import canonical implementation for bridging


# ZERO TOLERANCE - Deprecated RateLimiter protocol removed
# Modern rate limiting available from:
# - flx_core.security.rate_limiting.RateLimiter (protocol interface)
# - flx_core.security.redis_rate_limiting.RedisRateLimitManager (Redis implementation)


@runtime_checkable
class SecurityAuditor(Protocol):
    r"""SecurityAuditor - Framework Component.

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
    instance = SecurityAuditor()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Protocol for security event auditing."""

    async def log_security_event(
        self,
        event_type: str,
        user_id: UserID | None,
        ip_address: IPAddress | None,
        user_agent: UserAgent | None,
        metadata: TokenMetadata | None = None,
    ) -> None:
        """Log a security-related event for audit trails.

        Records security events for compliance and monitoring following
        enterprise auditing patterns and regulatory requirements.

        Args:
        ----
            event_type: Type of security event
            user_id: User involved in the event (if applicable)
            ip_address: Client IP address
            user_agent: Client user agent string
            metadata: Additional event metadata

        Note:
        ----
            Provides tamper-proof logging and retention.

        """
        ...

    async def get_failed_login_attempts(
        self,
        ip_address: IPAddress | None = None,
        user_id: UserID | None = None,
        window: datetime.timedelta | None = None,
    ) -> int:
        """Get count of failed login attempts.

        Args:
        ----
            ip_address: IP address to check (optional)
            user_id: User ID to check (optional)
            window: Time window for the count

        Returns:
        -------
            Number of failed login attempts

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
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    """Protocol for user authentication operations."""

    async def authenticate_user(
        self,
        email: str,
        password: PlaintextPassword,
        ip_address: IPAddress | None = None,
        user_agent: UserAgent | None = None,
    ) -> tuple[Any, JWTToken, JWTToken] | None:
        """Authenticate user and return user, access token, and refresh token.

        Args:
        ----
            email: User email address
            password: Plaintext password
            ip_address: Client IP address
            user_agent: Client user agent string

        Returns:
        -------
            Tuple of (user, access_token, refresh_token) if successful, None otherwise

        """
        ...

    async def authenticate_token(
        self, token: JWTToken, required_permissions: Sequence[str] | None = None
    ) -> User | None:
        """Authenticate using JWT token.

        Validates a JWT token and returns the associated user if the token
        is valid and the user has required permissions.

        Args:
        ----
            token: JWT token to authenticate
            required_permissions: List of permissions required for access

        Returns:
        -------
            User object if authentication successful, None otherwise

        Note:
        ----
            Provides token validation and permission checks.

        """
        ...

    async def refresh_tokens(
        self,
        refresh_token: JWTToken,
        ip_address: IPAddress | None = None,
        user_agent: UserAgent | None = None,
    ) -> tuple[JWTToken, JWTToken] | None:
        """Refresh access and refresh tokens.

        Args:
        ----
            refresh_token: Valid refresh token
            ip_address: Client IP address
            user_agent: Client user agent string

        Returns:
        -------
            Tuple of (new_access_token, new_refresh_token) if successful, None otherwise

        """
        ...

    async def revoke_token(
        self, token: JWTToken, user_id: UserID | None = None
    ) -> bool:
        """Revoke a JWT token.

        Marks a JWT token as revoked, preventing its future use following
        enterprise security patterns for token lifecycle management.

        Args:
        ----
            token: JWT token to revoke
            user_id: User ID for additional validation

        Returns:
        -------
            True if token was successfully revoked, False otherwise

        Note:
        ----
            Provides secure token blacklisting.

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
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    """Protocol for user authorization operations."""

    async def check_permission(
        self, user_id: UserID, permission: str, resource: str | None = None
    ) -> bool:
        """Check if user has specific permission.

        Args:
        ----
            user_id: User to check permissions for
            permission: Permission to verify
            resource: Specific resource (optional)

        Returns:
        -------
            True if user has permission, False otherwise

        """
        ...

    async def check_role(self, user_id: UserID, role: str) -> bool:
        """Check if user has specific role.

        Args:
        ----
            user_id: User to check role for
            role: Role to verify

        Returns:
        -------
            True if user has role, False otherwise

        """
        ...

    async def get_user_permissions(self, user_id: UserID) -> UserPermissions:
        """Get all permissions for a user.

        Args:
        ----
            user_id: User to get permissions for

        Returns:
        -------
            Complete set of user permissions

        """
        ...

    async def get_resource_permissions(
        self, user_id: UserID, resource: str
    ) -> UserPermissions:
        """Get permissions for a specific resource.

        Args:
        ----
            user_id: User to get permissions for
            resource: Specific resource to check

        Returns:
        -------
            Permissions for the specified resource

        """
        ...


@runtime_checkable
class SecurityHeaderValidator(Protocol):
    r"""SecurityHeaderValidator - Framework Component.

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
    instance = SecurityHeaderValidator()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Protocol for validating security headers."""

    def validate_headers(self, headers: SecurityHeaders) -> bool:
        """Validate security headers for compliance.

        Checks security headers against enterprise security policies
        and compliance requirements for proper client authentication.

        Args:
        ----
            headers: Security headers to validate

        Returns:
        -------
            True if headers are valid, False otherwise

        Note:
        ----
            Provides comprehensive header validation.

        """
        ...

    def extract_client_info(self, headers: SecurityHeaders) -> Mapping[str, str]:
        """Extract client information from headers.

        Args:
        ----
            headers: Security headers to extract from

        Returns:
        -------
            Dictionary containing extracted client information

        """
        ...

    def detect_suspicious_patterns(self, headers: SecurityHeaders) -> Sequence[str]:
        """Detect suspicious patterns in headers.

        Args:
        ----
            headers: Security headers to analyze

        Returns:
        -------
            List of detected suspicious patterns

        """
        ...
