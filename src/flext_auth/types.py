"""Type definitions for JWT authentication system using Python 3.13 patterns."""

from __future__ import annotations

import datetime
from collections.abc import Mapping, Sequence
from enum import Enum, auto
from typing import Any

# Python 3.11 compatible type aliases for security types
JWTToken = str
UserID = str
RoleID = str
PermissionID = str
IPAddress = str
UserAgent = str
SecretKey = str
PublicKey = str
PrivateKey = str
HashedPassword = str
PlaintextPassword = str

# JWT Claims type
JWTClaims = Mapping[str, Any]

# Token metadata
TokenMetadata = Mapping[str, Any]

# Rate limit configuration
RateLimitConfig = Mapping[str, int]

# Security headers
SecurityHeaders = Mapping[str, str]

# User permissions
UserPermissions = Sequence[str]


class TokenType(Enum):
    """Enumeration for different types of tokens used in authentication.

    This includes access tokens, refresh tokens, and verification tokens.
    Each token type has a unique identifier and purpose.

    Attributes
    ----------
        ACCESS: Represents an access token used for authenticated requests.
        REFRESH: Represents a refresh token used to obtain new access tokens.
        RESET: Represents a token used for password reset operations.
        VERIFICATION: Represents a token used for email or account verification.

    """

    ACCESS = auto()
    REFRESH = auto()
    RESET = auto()
    VERIFICATION = auto()


class AuthenticationMethod(Enum):
    """Enumeration for different authentication methods.

    This includes methods like password-based authentication, token-based,
    API key authentication, and OAuth.

    Attributes
    ----------
        PASSWORD: Represents authentication using a username and password.
        TOKEN: Represents authentication using a token (e.g., JWT).
        API_KEY: Represents authentication using an API key.
        OAUTH: Represents authentication using OAuth protocols.

    """

    PASSWORD = auto()
    TOKEN = auto()
    API_KEY = auto()
    OAUTH = auto()


class JWTAlgorithm(Enum):
    """Enumeration for JWT signing algorithms.

    Supports HMAC-based algorithms (HS*) and RSA/ECDSA public key algorithms.
    Used for configuring JWT token signing and verification.
    """

    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"


class UserStatus(Enum):
    r"""UserStatus - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes: Sem atributos públicos documentados.

    Methods: Sem métodos públicos.

    Examples: Uso típico da classe:

    ```python
    instance = UserStatus()\n    result = instance.method()
    ```

    See Also
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note: Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Enumeration of user account status values."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    LOCKED = "locked"


class RoleType(Enum):
    r"""RoleType - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes: Sem atributos públicos documentados.

    Methods: Sem métodos públicos.

    Examples: Uso típico da classe:

    ```python
    instance = RoleType()\n    result = instance.method()
    ```

    See Also
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note: Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Enumeration of user role types for authorization."""

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    SERVICE = "service"
    READONLY = "readonly"
    DEVELOPER = "developer"
    AUDITOR = "auditor"


class PermissionScope(Enum):
    """Enumeration of permission scopes for access control."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    EXECUTE = "execute"
    MANAGE = "manage"


class SecurityEvent(Enum):
    r"""SecurityEvent - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes: Sem atributos públicos documentados.

    Methods: Sem métodos públicos.

    Examples: Uso típico da classe:

    ```python
    instance = SecurityEvent()\n    result = instance.method()
    ```

    See Also
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note: Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Enumeration of security events for audit logging."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PASSWORD_CHANGE = "password_change"  # nosec S105 - enum value, not password
    TOKEN_REFRESH = "token_refresh"  # nosec S105 - enum value, not password
    TOKEN_REVOCATION = "token_revocation"  # nosec S105 - enum value, not password
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class RateLimitWindow(Enum):
    r"""RateLimitWindow - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes: Sem atributos públicos documentados.

    Methods: Sem métodos públicos.

    Examples: Uso típico da classe:

    ```python
    instance = RateLimitWindow()\n    result = instance.method()
    ```

    See Also
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note: Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Enumeration of rate limiting time windows."""

    MINUTE = datetime.timedelta(minutes=1)
    HOUR = datetime.timedelta(hours=1)
    DAY = datetime.timedelta(days=1)
    WEEK = datetime.timedelta(weeks=1)
