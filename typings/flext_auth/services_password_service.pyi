from _typeshed import Incomplete
from flext_core import FlextResult

from flext_auth.auth_models import (
    MAX_PASSWORD_LENGTH as MAX_PASSWORD_LENGTH,
    FlextHashedPassword as FlextHashedPassword,
    FlextPlainPassword as FlextPlainPassword,
)

MIN_BCRYPT_ROUNDS: int
MAX_BCRYPT_ROUNDS: int
MIN_PASSWORD_LENGTH: int
RECOMMENDED_PASSWORD_LENGTH: int
STRONG_PASSWORD_LENGTH: int
MIN_STRENGTH_SCORE: int
STRONG_STRENGTH_SCORE: int
EXCELLENT_STRENGTH_SCORE: int
VERY_LONG_PASSWORD_LENGTH: int
EXTREME_PASSWORD_LENGTH: int
MINIMUM_CRACK_TIME_SCORE: int
SECONDS_PER_MINUTE: int
SECONDS_PER_HOUR: int
SECONDS_PER_DAY: int
SECONDS_PER_YEAR: int
TOKEN_BYTES: int
logger: Incomplete

class FlextPasswordService:
    rounds: Incomplete
    def __init__(self, rounds: int = 12) -> None: ...
    def hash_password(
        self, plain_password: str | FlextPlainPassword
    ) -> FlextResult[FlextHashedPassword]: ...
    def verify_password(
        self,
        plain_password: str | FlextPlainPassword,
        hashed_password: str | FlextHashedPassword,
    ) -> FlextResult[bool]: ...
    def generate_secure_password(
        self, length: int = 16
    ) -> FlextResult[FlextPlainPassword]: ...
    def check_password_strength(
        self, password: str | FlextPlainPassword
    ) -> FlextResult[dict[str, object]]: ...
    def generate_password_reset_token(self) -> FlextResult[str]: ...
    def is_password_compromised(self, password: str) -> FlextResult[bool]: ...
