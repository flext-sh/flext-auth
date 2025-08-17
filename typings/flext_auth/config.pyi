from _typeshed import Incomplete
from flext_core import FlextBaseConfigModel, FlextResult
from pydantic import BaseModel

__all__ = [
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_MFA_SECRET",
    "DEFAULT_SERVICE_SECRET",
    "AppConfig",
    "DatabaseConfig",
    "FlextAuthApplicationConfig",
    "FlextAuthConfig",
    "JWTConfig",
    "SecurityConfig",
    "create_auth_config",
    "create_complete_auth_config",
    "create_development_config",
    "create_production_config",
    "get_default_secret",
    "validate_production_config",
]

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

class DatabaseConfig(BaseModel):
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

class JWTConfig(FlextBaseConfigModel):
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    model_config: Incomplete
    @classmethod
    def validate_algorithm(cls, value: str) -> str: ...
    def validate_secret_key(self) -> None: ...
    @classmethod
    def generate_secret_key(cls) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class SecurityConfig(FlextBaseConfigModel):
    password_rounds: int
    max_failed_attempts: int
    lockout_duration_minutes: int
    session_expire_hours: int
    max_concurrent_sessions: int
    require_email_verification: bool
    enable_2fa: bool
    model_config: Incomplete
    def validate_business_rules(self) -> FlextResult[None]: ...

class ServerConfig(FlextBaseConfigModel):
    debug: bool
    host: str
    port: int
    model_config: Incomplete
    def validate_business_rules(self) -> FlextResult[None]: ...

class AppConfig(FlextBaseConfigModel):
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
    def validate_business_rules(self) -> FlextResult[None]: ...
    def model_dump_safe(self) -> dict[str, object]: ...

def validate_production_config(config: AppConfig) -> bool: ...
def create_auth_config(**overrides: object) -> FlextAuthConfig: ...
def create_complete_auth_config(**overrides: object) -> FlextAuthApplicationConfig: ...
def get_default_secret(key_name: str) -> str: ...
def create_development_config() -> FlextAuthApplicationConfig: ...
def create_production_config() -> FlextAuthApplicationConfig: ...

DEFAULT_JWT_SECRET: Incomplete
DEFAULT_SERVICE_SECRET: Incomplete
DEFAULT_MFA_SECRET: Incomplete
DEFAULT_DEV_SECRET: Incomplete
