"""Authentication configuration using flext-core patterns.

Simplified configuration eliminating duplication and leveraging flext-core's
configuration patterns directly.
"""

from __future__ import annotations

# Use flext-core configuration patterns directly
from flext_core import FlextBaseSettings
from pydantic import Field

# =============================================================================
# AUTHENTICATION CONFIGURATION - Using flext-core efficiently
# =============================================================================


class FlextAuthConfig(FlextBaseSettings):
    """Authentication configuration using flext-core patterns."""

    # JWT settings
    jwt_secret_key: str = Field(default="dev-secret-key", description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30,
        description="Access token expiration",
    )
    refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration",
    )

    # Password settings
    password_min_length: int = Field(default=8, description="Minimum password length")
    password_max_length: int = Field(default=128, description="Maximum password length")
    bcrypt_rounds: int = Field(default=12, description="Bcrypt rounds")

    # Security settings
    max_login_attempts: int = Field(default=5, description="Maximum login attempts")
    lockout_duration_minutes: int = Field(
        default=30,
        description="Account lockout duration",
    )
    session_timeout_hours: int = Field(default=24, description="Session timeout")
    max_concurrent_sessions: int = Field(
        default=5,
        description="Maximum concurrent sessions",
    )

    class Config:
        """Pydantic configuration for FlextAuthConfig."""

        env_prefix = "FLEXT_AUTH_"


# =============================================================================
# EXPORTS - Clean config API
# =============================================================================

__all__ = [
    "FlextAuthConfig",
]
