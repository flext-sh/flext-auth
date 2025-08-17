from _typeshed import Incomplete
from flext_core import FlextBaseConfigModel, FlextSettings, TEntityId

__all__ = [
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_MFA_SECRET",
    "DEFAULT_SERVICE_SECRET",
    "AppConfig",
    "DatabaseConfig",
    "FlextAuthApplicationConfig",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "JWTConfig",
    "SecurityConfig",
    "ServerConfig",
    "TAuditEventType",
    "TAuthResult",
    "TEmail",
    "TLoginAttempt",
    "TPassword",
    "TSecurityContext",
    "TSessionId",
    "TUserId",
    "TUserRole",
    "TUsername",
    "create_auth_config",
    "create_complete_auth_config",
    "create_development_config",
    "create_production_config",
    "get_default_secret",
    "validate_production_config",
]

type TUserId = TEntityId
type TSessionId = TEntityId
type TUsername = str
type TEmail = str
type TPassword = str
type TUserRole = str
type TAuthResult = dict[str, object]
type TSecurityContext = dict[str, object]
type TLoginAttempt = dict[str, object]
type TAuditEventType = str

class FlextAuthConstants:
    USERNAME_PATTERN: str
    MIN_PASSWORD_LENGTH: int
    MAX_PASSWORD_LENGTH: int
    PASSWORD_VALIDATION_REGEX: str

class FlextAuthConfig(FlextBaseConfigModel):
    app_name: str
    version: str
    debug: bool
    environment: str
    password_min_length: int
    password_max_length: int
    bcrypt_rounds: int
    max_login_attempts: int
    lockout_duration_minutes: int
    session_timeout_hours: int
    max_concurrent_sessions: int
    rate_limit_per_minute: int
    auth_rate_limit_per_minute: int
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    jwt_secret_key: str | None

class FlextAuthApplicationConfig(FlextBaseConfigModel):
    app_name: str
    auth: FlextAuthConfig

class DatabaseConfig:
    def __init__(self, **kwargs: object) -> None: ...
    def __getattr__(self, name: str) -> object: ...
    @property
    def url(self) -> str: ...
    @property
    def min_pool_size(self) -> int: ...
    @property
    def max_pool_size(self) -> int: ...
    @property
    def command_timeout(self) -> int: ...

class JWTConfig(FlextSettings):
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    model_config: Incomplete
    def __init__(self, **kwargs: object) -> None: ...
    def validate_secret_key(self) -> None: ...
    @classmethod
    def generate_secret_key(cls) -> str: ...

class SecurityConfig(FlextSettings):
    password_rounds: int
    max_failed_attempts: int
    lockout_duration_minutes: int
    session_expire_hours: int
    max_concurrent_sessions: int
    require_email_verification: bool
    enable_2fa: bool
    model_config: Incomplete

class ServerConfig(FlextSettings):
    debug: bool
    host: str
    port: int
    model_config: Incomplete

class AppConfig(FlextSettings):
    name: str
    version: str
    app_name: str
    debug: bool
    environment: str
    database: DatabaseConfig
    jwt: JWTConfig
    security: SecurityConfig
    server: ServerConfig
    model_config: Incomplete
    def model_dump_safe(self) -> dict[str, object]: ...

def create_auth_config(**overrides: object) -> FlextAuthConfig: ...
def create_complete_auth_config(**overrides: object) -> FlextAuthApplicationConfig: ...
def get_default_secret(key_name: str) -> str: ...
def validate_production_config(config: AppConfig) -> bool: ...
def create_development_config() -> FlextAuthApplicationConfig: ...
def create_production_config() -> FlextAuthApplicationConfig: ...

DEFAULT_JWT_SECRET: Incomplete
DEFAULT_SERVICE_SECRET: Incomplete
DEFAULT_MFA_SECRET: Incomplete
DEFAULT_DEV_SECRET: Incomplete
