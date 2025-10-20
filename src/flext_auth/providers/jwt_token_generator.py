"""FLEXT Auth JWT Token Generator - Dedicated token generation service.

This module provides a dedicated service for JWT token generation following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import jwt
from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuthJwtTokenGenerator:
    """Dedicated JWT token generator service.

    Single responsibility: Generate JWT tokens with proper railway-oriented error handling.
    Uses composition and delegates to flext-core for consistent patterns.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def generate_token(
        self,
        identity_id: str,
        expiry_minutes: int | None = None,
        extra_claims: dict[str, object] | None = None,
    ) -> FlextResult[str]:
        """Generate JWT token with railway-oriented programming.

        Args:
            identity_id: Identity identifier for token subject
            expiry_minutes: Custom expiry time (uses config default if None)
            extra_claims: Additional claims to include in token

        Returns:
            FlextResult containing token string or error

        """
        try:
            # Get configuration from provider
            config = self._provider.config
            secret_key = config.get("secret_key")
            algorithm = config.get("algorithm", "HS256")
            default_expiry = int(config.get("expiry_minutes", 30))

            if not secret_key:
                return FlextResult.fail("JWT secret key not configured")

            # Build token payload
            now = datetime.now(UTC)
            payload = {
                "sub": identity_id,
                "iat": int(now.timestamp()),
                "exp": int(
                    (
                        now + timedelta(minutes=expiry_minutes or default_expiry)
                    ).timestamp()
                ),
                "iss": config.get("issuer", "flext-auth"),
                "aud": config.get("audience"),
            }

            # Add extra claims if provided
            if extra_claims:
                payload.update(extra_claims)

            # Generate token
            token = jwt.encode(payload, secret_key, algorithm=algorithm)
            return FlextResult.ok(token)

        except Exception as e:
            return FlextResult.fail(f"Token generation failed: {e}")


__all__ = ["FlextAuthJwtTokenGenerator"]
