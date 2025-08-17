from _typeshed import Incomplete
from flext_core import FlextFieldCore, FlextResult

__all__ = [
    "EMAIL_FIELD",
    "FAILED_ATTEMPTS_FIELD",
    "LOCKOUT_ENABLED_FIELD",
    "PASSWORD_FIELD",
    "ROLE_FIELD",
    "SESSION_EXPIRE_FIELD",
    "STATUS_FIELD",
    "USERNAME_FIELD",
    "FlextAuthFieldSchema",
    "get_auth_field_by_name",
    "validate_complete_user_registration",
    "validate_email",
    "validate_email_uniqueness",
    "validate_failed_attempts_threshold",
    "validate_password",
    "validate_password_strength",
    "validate_role",
    "validate_security_context",
    "validate_session_expiry",
    "validate_user_profile_update",
    "validate_user_role_permissions",
    "validate_username",
    "validate_username_uniqueness",
]

USERNAME_FIELD: Incomplete
EMAIL_FIELD: Incomplete
PASSWORD_FIELD: Incomplete
ROLE_FIELD: Incomplete
STATUS_FIELD: Incomplete
SESSION_EXPIRE_FIELD: Incomplete
FAILED_ATTEMPTS_FIELD: Incomplete
LOCKOUT_ENABLED_FIELD: Incomplete

class FlextAuthFieldSchema:
    USERNAME = USERNAME_FIELD
    EMAIL = EMAIL_FIELD
    PASSWORD = PASSWORD_FIELD
    ROLE = ROLE_FIELD
    STATUS = STATUS_FIELD
    SESSION_EXPIRE = SESSION_EXPIRE_FIELD
    FAILED_ATTEMPTS = FAILED_ATTEMPTS_FIELD
    LOCKOUT_ENABLED = LOCKOUT_ENABLED_FIELD
    @classmethod
    def validate_user_data(
        cls, user_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]: ...
    @classmethod
    def get_field_metadata(cls) -> dict[str, dict[str, object]]: ...
    @classmethod
    def get_sensitive_fields(cls) -> list[str]: ...
    @classmethod
    def get_indexed_fields(cls) -> list[str]: ...

def validate_username_uniqueness(
    username: str, existing_usernames: list[str]
) -> FlextResult[str]: ...
def validate_email_uniqueness(
    email: str, existing_emails: list[str]
) -> FlextResult[str]: ...
def validate_password_strength(password: str) -> FlextResult[dict[str, object]]: ...
def validate_session_expiry(
    session_expire_hours: int, max_hours: int = 720
) -> FlextResult[int]: ...
def validate_failed_attempts_threshold(
    failed_attempts: int, max_attempts: int = 10
) -> FlextResult[int]: ...
def validate_user_role_permissions(
    role: str, required_permissions: list[str]
) -> FlextResult[str]: ...
def validate_username(username: str) -> FlextResult[str]: ...
def validate_email(email: str) -> FlextResult[str]: ...
def validate_password(password: str) -> FlextResult[str]: ...
def validate_role(role: str) -> FlextResult[str]: ...
def get_auth_field_by_name(field_name: str) -> FlextResult[FlextFieldCore]: ...
def validate_complete_user_registration(
    user_data: dict[str, object],
) -> FlextResult[dict[str, object]]: ...
def validate_user_profile_update(
    user_data: dict[str, object], current_user_data: dict[str, object]
) -> FlextResult[dict[str, object]]: ...
def validate_security_context(
    security_data: dict[str, object],
) -> FlextResult[dict[str, object]]: ...
