"""FLEXT Auth types - Modern Python 3.13 patterns.

REFACTORED: Uses flext-core types and StrEnum patterns.
Zero tolerance for duplication.
"""

from __future__ import annotations

from enum import StrEnum

from flext_core.domain.types import UserId as CoreUserId

# Re-export core types for auth module
UserID = CoreUserId


class TokenType:
    """Token types for authentication system.

    Defines available token types for the authentication system.
    """

    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"
    VERIFICATION = "verification"
    API = "api"
    TEMPORARY = "temporary"


class AuthenticationStatus:
    """Authentication status enumeration.

    Defines possible authentication outcomes.
    """

    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"
    PENDING = "pending"


class SessionStatus:
    """Session status enumeration.

    Defines possible session states.
    """

    ACTIVE = "active"
    EXPIRED = "expired"


class PermissionScope(StrEnum):
    """Permission scope for authorization system."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    EXECUTE = "execute"
    MANAGE = "manage"
    REVOKED = "revoked"
    INACTIVE = "inactive"


class PermissionLevel:
    """Permission levels for RBAC.

    Defines hierarchical permission levels.
    """

    READ = "read"
    WRITE = "write"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    SUPER_ADMIN = "super_REDACTED_LDAP_BIND_PASSWORD"


class AuthProvider:
    """Authentication providers.

    Defines supported authentication provider types.
    """

    LOCAL = "local"
    LDAP = "ldap"
    OAUTH = "oauth"
    SAML = "saml"
    JWT = "jwt"


class JWTAlgorithm:
    """JWT signing algorithms.

    Defines supported JWT signing algorithms.
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


class UserStatus:
    """User account status enumeration.

    Defines possible user account states.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    LOCKED = "locked"


class RoleType:
    """User role types for authorization.

    Defines standard role types in the system.
    """

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    SERVICE = "service"
    READONLY = "readonly"
    DEVELOPER = "developer"
    AUDITOR = "auditor"


class SecurityEvent:
    """Security events for audit logging.

    Defines security events that should be logged for auditing.
    """

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PASSWORD_CHANGE = "password_change"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOCATION = "token_revocation"
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class RateLimitWindow:
    """Rate limiting time windows.

    Defines time windows for rate limiting calculations.
    """

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"


__all__ = [
    "AuthProvider",
    "AuthenticationStatus",
    "JWTAlgorithm",
    "PermissionLevel",
    "RateLimitWindow",
    "RoleType",
    "SecurityEvent",
    "SessionStatus",
    "TokenType",
    "UserID",
    "UserStatus",
]
