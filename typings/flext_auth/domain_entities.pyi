from datetime import datetime
from enum import StrEnum

from flext_core import (
    FlextEntity,
    FlextEntityId as FlextEntityId,
    FlextResult,
    FlextTimestamp,
)

MIN_USERNAME_LENGTH: int
MAX_USERNAME_LENGTH: int
MIN_PASSWORD_LENGTH: int
MAX_PASSWORD_LENGTH: int
MIN_EMAIL_LENGTH: int
MAX_EMAIL_LENGTH: int
MAX_NAME_LENGTH: int
MAX_DESCRIPTION_LENGTH: int
MAX_SESSION_ID_LENGTH: int
MIN_TOKEN_LENGTH: int

class FlextUserStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"

class FlextUserRole(StrEnum):
    USER = "user"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    MODERATOR = "moderator"

class FlextUser(FlextEntity):
    id: FlextEntityId
    username: str
    email: str
    password_hash: str
    role: FlextUserRole
    status: FlextUserStatus
    failed_login_attempts: int
    locked_until: datetime | None
    last_login: datetime | None
    created_at: FlextTimestamp
    updated_at: FlextTimestamp
    def is_active(self) -> bool: ...
    def is_locked(self) -> bool: ...
    def unlock_account(self) -> FlextUser: ...
    def increment_failed_login(self) -> FlextUser: ...
    def reset_failed_login(self) -> FlextUser: ...
    def is_valid(self) -> bool: ...
    def is_REDACTED_LDAP_BIND_PASSWORD(self) -> bool: ...
    def validate_domain_rules(self) -> FlextResult[None]: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextSessionStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"

class FlextSession(FlextEntity):
    id: FlextEntityId
    user_id: str
    access_token: str
    refresh_token: str | None
    status: FlextSessionStatus
    ip_address: str | None
    user_agent: str | None
    expires_at: datetime
    created_at: FlextTimestamp
    last_accessed: datetime
    def is_valid(self) -> bool: ...
    def extend_session(self, minutes: int = 30) -> FlextSession: ...
    def revoke(self) -> FlextSession: ...
    def has_valid_data(self) -> bool: ...
    def validate_domain_rules(self) -> FlextResult[None]: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextPermission(FlextEntity):
    id: FlextEntityId
    name: str
    description: str
    resource: str
    action: str
    def is_valid(self) -> bool: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextRole(FlextEntity):
    id: FlextEntityId
    name: str
    description: str
    permissions: list[FlextPermission]
    is_system_role: bool
    created_at: FlextTimestamp
    def has_permission(self, resource: str, action: str) -> bool: ...
    def is_valid(self) -> bool: ...
    def validate_domain_rules(self) -> FlextResult[None]: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextLoginAttempt(FlextEntity):
    id: FlextEntityId
    username: str
    ip_address: str
    user_agent: str | None
    success: bool
    failure_reason: str | None
    attempted_at: datetime
    def validate_domain_rules(self) -> FlextResult[None]: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextBaseToken(FlextEntity):
    id: FlextEntityId
    user_id: str
    token: str
    expires_at: datetime
    used: bool
    created_at: FlextTimestamp
    def is_valid(self) -> bool: ...
    def use_token(self) -> None: ...
    def validate_domain_rules(self) -> FlextResult[None]: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextPasswordResetToken(FlextBaseToken): ...
class FlextEmailVerificationToken(FlextBaseToken): ...
