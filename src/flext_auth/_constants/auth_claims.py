"""Authentication claim and shared scalar constants."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from flext_api import c

from flext_auth._constants.auth_enums import FlextAuthConstantsAuthEnums

if TYPE_CHECKING:
    from collections.abc import Mapping, Set as AbstractSet

    from flext_auth import t


class FlextAuthConstantsAuthClaims(FlextAuthConstantsAuthEnums):
    # ===== Regex Patterns for Validation =====
    PATTERN_EMAIL: Final[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    "Standard email address validation pattern."

    VALID_TOKEN_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value
        for member in FlextAuthConstantsAuthEnums.TokenTypes.__members__.values()
    )
    "Immutable set of all valid token types for O(1) validation."
    VALID_PROVIDER_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value
        for member in FlextAuthConstantsAuthEnums.ProviderTypes.__members__.values()
    )
    "Immutable set of all valid provider types."
    VALID_ROLE_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value
        for member in FlextAuthConstantsAuthEnums.RoleTypes.__members__.values()
    )
    "Immutable set of all valid role types."
    VALID_PERMISSION_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value
        for member in FlextAuthConstantsAuthEnums.PermissionTypes.__members__.values()
    )
    "Immutable set of all valid permission types."
    KEY_SUBJECT: Final[str] = "sub"
    "Subject claim key."
    KEY_IDENTITY_ID: Final[str] = "identity_id"
    "Identity identifier claim key."
    KEY_USER_ID: Final[str] = "user_id"
    "User identifier payload key."
    KEY_USERNAME: Final[str] = "username"
    "Username claim key."
    KEY_NAME: Final[str] = "name"
    "Display-name claim key."
    KEY_PREFERRED_USERNAME: Final[str] = "preferred_username"
    "Preferred username claim key."
    KEY_CONTACT: Final[str] = "contact"
    "Contact claim key."
    KEY_EMAIL: Final[str] = "email"
    "Email claim key."
    KEY_ROLES: Final[str] = "roles"
    "Roles claim key."
    KEY_SCOPE: Final[str] = "scope"
    "OAuth scope claim key."
    KEY_CONTACT_DOMAIN: Final[str] = "contact_domain"
    "Local contact-domain override key for identity claim normalization."
    TOKEN_IDENTITY_KEYS: Final[tuple[str, ...]] = (
        KEY_SUBJECT,
        KEY_IDENTITY_ID,
        KEY_USER_ID,
        KEY_USERNAME,
    )
    "Identity claim keys in priority order."
    TOKEN_NAME_KEYS: Final[tuple[str, ...]] = (
        KEY_NAME,
        KEY_PREFERRED_USERNAME,
        KEY_USERNAME,
    )
    "Display-name claim keys in priority order."
    TOKEN_CONTACT_KEYS: Final[tuple[str, ...]] = (KEY_CONTACT, KEY_EMAIL)
    "Contact claim keys in priority order."
    TOKEN_IDENTITY_PASSTHROUGH_FIELDS: Final[tuple[str, ...]] = (
        "credential_hash",
        "failed_attempts",
        "full_name",
        "is_active",
        "last_access",
        "locked_until",
        "permissions",
        "session_id",
        "token",
    )
    "AuthIdentity fields preserved when normalizing external token claims."
    DEFAULT_OAUTH_CONTACT_DOMAIN: Final[str] = "oauth.local"
    "Fallback local contact domain for OAuth identities."
    DEFAULT_KERBEROS_CONTACT_DOMAIN: Final[str] = "kerberos.local"
    "Fallback local contact domain for Kerberos identities."
    DEFAULT_KERBEROS_USERNAME: Final[str] = "kerberos-user"
    "Fallback principal name for Kerberos ticket data without a principal."
    SCOPE_SEPARATOR: Final[str] = " "
    "OAuth scope separator."
    DEFAULT_TIMEOUT: Final[float] = float(c.DEFAULT_TIMEOUT_SECONDS)
    "Default request timeout in seconds."
    DEFAULT_MAX_RETRIES: Final[int] = 3
    "Default maximum retry attempts."
    DEFAULT_JWT_EXPIRY_MINUTES: Final[int] = 1440
    "Default JWT token expiry in minutes."
    DEFAULT_SESSION_EXPIRY_MINUTES: Final[int] = 1440
    "Default session expiry in minutes."
    DEFAULT_MAX_SESSIONS_PER_USER: Final[int] = 5
    "Default maximum sessions per user."
    DEFAULT_HASH_ROUNDS: Final[int] = 12
    "Default bcrypt hash rounds."
    DEFAULT_JWT_ALGORITHM: Final[str] = FlextAuthConstantsAuthEnums.Algorithms.HS256
    "Default JWT algorithm."
    MAX_USERNAME_LENGTH: Final[int] = 255
    "Maximum username length."
    MAX_EMAIL_LENGTH: Final[int] = 254
    "Maximum email length."
    MIN_PASSWORD_LENGTH: Final[int] = 8
    "Minimum password length."
    MAX_PASSWORD_LENGTH: Final[int] = 128
    "Maximum password length."
    MAX_TOKEN_LENGTH: Final[int] = 4096
    "Maximum token length."
    MAX_SECRET_KEY_LENGTH: Final[int] = 4096
    "Maximum secret key length."
    DEFAULT_ISSUER: Final[str] = "flext-auth"
    "Default JWT issuer."
    DEFAULT_AUDIENCE: Final[str] = "flext-auth-users"
    "Default JWT audience."
    HASH_ROUNDS_MIN: Final[int] = 4
    "Minimum hash rounds."
    HASH_ROUNDS_MAX: Final[int] = 31
    "Maximum hash rounds."
    CREDENTIAL_MIN_LENGTH: Final[int] = 8
    "Minimum credential length."
    CREDENTIAL_MAX_LENGTH: Final[int] = 128
    "Maximum credential length."
    MAX_ATTEMPTS_DEFAULT: Final[int] = 5
    "Default max authentication attempts."
    LOCKOUT_DURATION_MINUTES: Final[int] = 30
    "Lockout duration in minutes."
    SECRET_MIN_LENGTH: Final[int] = 32
    "Minimum secret key length."
    VALIDATION_LIMITS: Final[Mapping[str, t.Numeric]] = MappingProxyType({
        "MAX_USERNAME_LENGTH": MAX_USERNAME_LENGTH,
        "MAX_EMAIL_LENGTH": MAX_EMAIL_LENGTH,
        "MIN_PASSWORD_LENGTH": MIN_PASSWORD_LENGTH,
        "MAX_PASSWORD_LENGTH": MAX_PASSWORD_LENGTH,
        "MAX_TOKEN_LENGTH": MAX_TOKEN_LENGTH,
        "MAX_SECRET_KEY_LENGTH": MAX_SECRET_KEY_LENGTH,
        "DEFAULT_TIMEOUT": DEFAULT_TIMEOUT,
    })
    "Validation limits mapping."
    SUCCESS_AUTH_RESPONSE: Final[t.OptionalStrMapping] = MappingProxyType({
        "status": c.Status.SUCCESS.value,
        "message": "Authentication successful",
        "token_type": None,
    })
    "Template for successful authentication responses."


__all__: list[str] = ["FlextAuthConstantsAuthClaims"]
