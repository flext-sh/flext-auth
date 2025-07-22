"""FLEXT Auth types - Unified typing system using flext-core.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

This module imports from the unified typing system in flext-core and defines
auth-specific types using modern Python 3.13 patterns and Pydantic v2.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

# Import from unified core typing system
from flext_core.domain.shared_types import Password, Token, UserId, Username
from pydantic import Field, StringConstraints

# ==============================================================================
# AUTH-SPECIFIC TYPE ALIASES USING CORE TYPES
# ==============================================================================

# Re-export core types with auth-specific aliases
UserID = UserId  # Backward compatibility
HashedPassword = Annotated[
    str,
    StringConstraints(min_length=60, max_length=60, pattern=r"^\$2[ayb]\$.{56}$"),
    Field(description="Bcrypt hashed password"),
]
PlaintextPassword = Password
JWTToken = Token
UserAgent = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512),
    Field(description="HTTP User-Agent header"),
]
IPAddress = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"),
    Field(description="IPv4 or IPv6 address"),
]

# Complex auth types
type JWTClaims = dict[str, Any]
type SecurityHeaders = dict[str, str]
type UserPermissions = list[str]
type RolePermissions = dict[str, list[str]]

# JWT specific types
type JWTSubject = str
type JWTIssuer = str
type JWTAudience = str | list[str]
type JWTTokenId = str

# Session types
type SessionToken = str
type DeviceFingerprint = str
type SessionData = dict[str, Any]

# ==============================================================================
# AUTH-SPECIFIC ENUMS USING STRENUM
# ==============================================================================


class TokenType(StrEnum):
    """JWT token types for authentication system."""

    ACCESS = "access"
    REFRESH = "refresh"
    RESET = "reset"
    VERIFICATION = "verification"
    API = "api"
    TEMPORARY = "temporary"
    RESET_PASSWORD = "reset_password"
    EMAIL_VERIFICATION = "email_verification"
    PHONE_VERIFICATION = "phone_verification"


class AuthenticationStatus(StrEnum):
    """Authentication status outcomes."""

    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"
    PENDING = "pending"
    LOCKED = "locked"
    RATE_LIMITED = "rate_limited"
    REQUIRES_MFA = "requires_mfa"


class SessionStatus(StrEnum):
    """Session status states."""

    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    SUSPENDED = "suspended"
    INVALID = "invalid"


class PermissionScope(StrEnum):
    """Permission scope for authorization system."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    EXECUTE = "execute"
    MANAGE = "manage"
    CREATE = "create"
    UPDATE = "update"
    LIST = "list"
    VIEW = "view"
    REVOKED = "revoked"
    INACTIVE = "inactive"


class PermissionLevel(StrEnum):
    """Hierarchical permission levels for RBAC."""

    READ = "read"
    WRITE = "write"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    SUPER_ADMIN = "super_REDACTED_LDAP_BIND_PASSWORD"
    SYSTEM = "system"
    ROOT = "root"


class AuthProvider(StrEnum):
    """Supported authentication provider types."""

    LOCAL = "local"
    LDAP = "ldap"
    OAUTH = "oauth"
    OAUTH2 = "oauth2"
    SAML = "saml"
    JWT = "jwt"
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    GITHUB = "github"
    FACEBOOK = "facebook"


class JWTAlgorithm(StrEnum):
    """JWT signing algorithms."""

    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"


class UserStatus(StrEnum):
    """User account status states."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    LOCKED = "locked"
    DELETED = "deleted"
    ARCHIVED = "archived"
    PENDING_APPROVAL = "pending_approval"


class RoleType(StrEnum):
    """Standard user role types."""

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    SERVICE = "service"
    READONLY = "readonly"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    GUEST = "guest"
    MODERATOR = "moderator"
    SUPER_ADMIN = "super_REDACTED_LDAP_BIND_PASSWORD"


class SecurityEvent(StrEnum):
    """Security events for audit logging."""

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PASSWORD_CHANGE = "password_change"
    TOKEN_REFRESH = "token_refresh"
    TOKEN_REVOCATION = "token_revocation"
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"


class RateLimitWindow(StrEnum):
    """Rate limiting time windows."""

    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


# ==============================================================================
# EXPORTS - ALL AUTH TYPES
# ==============================================================================

__all__ = [
    "AuthProvider",
    "AuthenticationStatus",
    "DeviceFingerprint",
    "HashedPassword",
    "IPAddress",
    "JWTAlgorithm",
    "JWTAudience",
    "JWTClaims",
    "JWTIssuer",
    "JWTSubject",
    "JWTToken",
    "JWTTokenId",
    "Password",
    "PermissionLevel",
    "PermissionScope",
    "PlaintextPassword",
    "RateLimitWindow",
    "RolePermissions",
    "RoleType",
    "SecurityEvent",
    "SecurityHeaders",
    "SessionData",
    "SessionStatus",
    "SessionToken",
    "Token",
    "TokenType",
    "UserAgent",
    "UserID",
    "UserId",
    "UserPermissions",
    "UserStatus",
    "Username",
]
