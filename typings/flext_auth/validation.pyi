from flext_core import FlextResult

from flext_auth.auth_types import TEmail, TPassword, TUsername

__all__ = ["FlextAuthValidators"]

class FlextAuthValidators:
    @staticmethod
    def validate_username(username: TUsername) -> FlextResult[None]: ...
    @staticmethod
    def validate_email(email: TEmail) -> FlextResult[None]: ...
    @staticmethod
    def validate_password(password: TPassword) -> FlextResult[None]: ...
    @staticmethod
    def validate_user_id(user_id: str) -> FlextResult[None]: ...
