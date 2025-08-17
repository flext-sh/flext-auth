from flext_core import FlextResult, FlextValueObject
from pydantic import EmailStr as EmailStr

MIN_USERNAME_LENGTH: int
MAX_USERNAME_LENGTH: int
MIN_PASSWORD_LENGTH: int
MAX_PASSWORD_LENGTH: int
MIN_BCRYPT_HASH_LENGTH: int
MIN_AUTH_TOKEN_LENGTH: int
MIN_REFRESH_TOKEN_LENGTH: int
MIN_SESSION_TOKEN_LENGTH: int
MAX_USER_AGENT_LENGTH: int
MIN_PASSWORD_RESET_TOKEN_LENGTH: int
MIN_EMAIL_VERIFICATION_TOKEN_LENGTH: int

class FlextUsername(FlextValueObject):
    value: str
    @classmethod
    def validate_username(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextUserEmail(FlextValueObject):
    value: EmailStr
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextPlainPassword(FlextValueObject):
    value: str
    @classmethod
    def validate_password(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextHashedPassword(FlextValueObject):
    value: str
    @classmethod
    def validate_hash(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextAuthToken(FlextValueObject):
    value: str
    token_type: str
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextBaseTokenValueObject(FlextValueObject):
    value: str
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextRefreshToken(FlextBaseTokenValueObject): ...
class FlextSessionToken(FlextBaseTokenValueObject): ...

class FlextIPAddress(FlextValueObject):
    value: str
    @classmethod
    def validate_ip(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextUserAgent(FlextValueObject):
    value: str
    def is_mobile(self) -> bool: ...
    def get_browser(self) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextPasswordResetToken(FlextBaseTokenValueObject):
    value: str

class FlextEmailVerificationToken(FlextBaseTokenValueObject):
    value: str

class FlextJWTClaims(FlextValueObject):
    sub: str
    username: str | None
    role: str | None
    permissions: list[str]
    iat: int
    exp: int
    token_type: str
    session_id: str | None
    def is_expired(self) -> bool: ...
    def time_until_expiry(self) -> int: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextSecurityContext(FlextValueObject):
    user_id: str
    username: str
    role: str
    session_id: str
    permissions: list[str]
    ip_address: str | None
    user_agent: str | None
    def has_permission(self, permission: str) -> bool: ...
    def is_REDACTED_LDAP_BIND_PASSWORD(self) -> bool: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
