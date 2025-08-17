from datetime import datetime
from enum import StrEnum

from _typeshed import Incomplete
from flext_core import FlextResult

from flext_auth.constants import FlextAuthConstants as FlextAuthConstants
from flext_auth.domain_value_objects import FlextJWTClaims as JWTClaims

DEV_SECRET_KEY: Incomplete

class TokenType(StrEnum):
    ACCESS = ...
    REFRESH = ...

logger: object | None

class FlextJWTService:
    secret_key: Incomplete
    algorithm: Incomplete
    access_token_expire_minutes: Incomplete
    refresh_token_expire_days: Incomplete
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
    ) -> None: ...
    def generate_access_token(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str | None = None,
        extra_claims: dict[str, str] | None = None,
    ) -> FlextResult[str]: ...
    def generate_refresh_token(
        self, user_id: str, session_id: str | None = None
    ) -> FlextResult[str]: ...
    def generate_token_pair(
        self,
        user_id: str,
        username: str,
        role: str,
        session_id: str,
        extra_claims: dict[str, str] | None = None,
    ) -> FlextResult[dict[str, str]]: ...
    def verify_token(self, token: str) -> FlextResult[JWTClaims]: ...
    def refresh_access_token(self, refresh_token: str) -> FlextResult[str]: ...
    def extract_user_id(self, token: str) -> FlextResult[str]: ...
    def get_token_claims(self, token: str) -> FlextResult[JWTClaims]: ...
    def get_token_expiry(self, token: str) -> FlextResult[datetime]: ...
    def is_token_expired(self, token: str) -> FlextResult[bool]: ...
