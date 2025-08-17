from enum import Enum

from _typeshed import Incomplete
from flext_core import FlextConstants

__all__ = [
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "TEST_JWT_SECRET",
    "FlextAuthConstants",
    "FlextAuthSemanticConstants",
    "FlextTokenTypeEnum",
    "FlextUserRoleEnum",
    "FlextUserStatusEnum",
]

class FlextAuthSemanticConstants(FlextConstants):
    class Authentication:
        USERNAME_PATTERN: str
        PASSWORD_VALIDATION_REGEX: Incomplete
        MIN_PASSWORD_LENGTH: Incomplete
        MAX_PASSWORD_LENGTH: Incomplete
        MIN_PASSWORD_SECURITY_SCORE: int

    class Security:
        DEFAULT_MAX_LOGIN_ATTEMPTS: int
        DEFAULT_LOCKOUT_DURATION_MINUTES: int
        MAX_ACCOUNT_LOCK_HOURS: int
        DEFAULT_BCRYPT_ROUNDS: int

    class Sessions:
        DEFAULT_SESSION_TIMEOUT_HOURS: int
        MAX_CONCURRENT_SESSIONS: int

    class Tokens:
        DEFAULT_ACCESS_TOKEN_MINUTES: int
        DEFAULT_REFRESH_TOKEN_DAYS: int
        JWT_ALGORITHM: str
        TEST_JWT_SECRET: Incomplete
        DEFAULT_JWT_SECRET: Incomplete

    class UserStatus:
        ACTIVE: str
        INACTIVE: str
        SUSPENDED: str
        LOCKED: str

    class UserRoles:
        ADMIN: str
        USER: str
        GUEST: str

    class TokenTypes:
        ACCESS: str
        REFRESH: str
        RESET: str
        VERIFICATION: str

class FlextAuthConstants(FlextAuthSemanticConstants):
    Authentication = FlextAuthSemanticConstants.Authentication
    Security = FlextAuthSemanticConstants.Security
    Sessions = FlextAuthSemanticConstants.Sessions
    Tokens = FlextAuthSemanticConstants.Tokens
    UserStatus = FlextAuthSemanticConstants.UserStatus
    UserRoles = FlextAuthSemanticConstants.UserRoles
    TokenTypes = FlextAuthSemanticConstants.TokenTypes
    USERNAME_PATTERN: Incomplete
    PASSWORD_VALIDATION_REGEX: Incomplete
    MIN_PASSWORD_LENGTH: Incomplete
    MAX_PASSWORD_LENGTH: Incomplete
    MIN_PASSWORD_SECURITY_SCORE: Incomplete
    DEFAULT_MAX_LOGIN_ATTEMPTS: Incomplete
    DEFAULT_LOCKOUT_DURATION_MINUTES: Incomplete
    MAX_ACCOUNT_LOCK_HOURS: Incomplete
    DEFAULT_BCRYPT_ROUNDS: Incomplete
    DEFAULT_SESSION_TIMEOUT_HOURS: Incomplete
    MAX_CONCURRENT_SESSIONS: Incomplete
    DEFAULT_ACCESS_TOKEN_MINUTES: Incomplete
    DEFAULT_REFRESH_TOKEN_DAYS: Incomplete
    JWT_ALGORITHM: Incomplete
    TEST_JWT_SECRET: Incomplete
    DEFAULT_JWT_SECRET: Incomplete

class FlextUserStatusEnum(Enum):
    ACTIVE = ...
    INACTIVE = ...
    SUSPENDED = ...
    LOCKED = ...

class FlextUserRoleEnum(Enum):
    ADMIN = ...
    USER = ...
    GUEST = ...

class FlextTokenTypeEnum(Enum):
    ACCESS = ...
    REFRESH = ...
    RESET = ...
    VERIFICATION = ...

TEST_JWT_SECRET: Incomplete
DEFAULT_JWT_SECRET: Incomplete
DEFAULT_DEV_SECRET = DEFAULT_JWT_SECRET
