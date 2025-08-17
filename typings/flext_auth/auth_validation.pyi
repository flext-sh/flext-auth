from _typeshed import Incomplete
from flext_core import FlextResult

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
    "FlextAuthValidators",
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

class FlextFieldCore:
    field_name: Incomplete
    required: Incomplete
    sensitive: Incomplete
    indexed: Incomplete
    default_value: Incomplete
    def __init__(
        self,
        field_name: str,
        *,
        required: bool = True,
        sensitive: bool = False,
        indexed: bool = False,
        default_value: object = None,
    ) -> None: ...
    def validate_value(self, value: object) -> FlextResult[object]: ...
    def get_field_metadata(self) -> dict[str, object]: ...

class FlextFields:
    @staticmethod
    def create_string_field(**kwargs: object) -> FlextFieldCore: ...
    @staticmethod
    def create_integer_field(**kwargs: object) -> FlextFieldCore: ...
    @staticmethod
    def create_boolean_field(**kwargs: object) -> FlextFieldCore: ...
    @staticmethod
    def register_field(field: object) -> None: ...
    @staticmethod
    def get_field_by_name(field_name: str) -> FlextResult[FlextFieldCore]: ...

class FlextAuthValidators:
    @staticmethod
    def validate_username(username: str) -> FlextResult[None]: ...
    @staticmethod
    def validate_email(email: str) -> FlextResult[None]: ...
    @staticmethod
    def validate_password(password: str) -> FlextResult[None]: ...
    @staticmethod
    def validate_user_id(user_id: str) -> FlextResult[None]: ...

USERNAME_FIELD: FlextFieldCore
EMAIL_FIELD: FlextFieldCore
PASSWORD_FIELD: FlextFieldCore
ROLE_FIELD: FlextFieldCore
STATUS_FIELD: FlextFieldCore
SESSION_EXPIRE_FIELD: FlextFieldCore
FAILED_ATTEMPTS_FIELD: FlextFieldCore
LOCKOUT_ENABLED_FIELD: FlextFieldCore

class FlextAuthFieldSchema:
    USERNAME: FlextFieldCore
    EMAIL: FlextFieldCore
    PASSWORD: FlextFieldCore
    ROLE: FlextFieldCore
    STATUS: FlextFieldCore
    SESSION_EXPIRE: FlextFieldCore
    FAILED_ATTEMPTS: FlextFieldCore
    LOCKOUT_ENABLED: FlextFieldCore
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
