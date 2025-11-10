"""FLEXT Auth Utilities - Generic credential and token processing.

Single FlextAuthUtilities class with static methods for password and JWT operations,
delegating to bcrypt and jwt libraries directly.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import bcrypt
import jwt
from flext_core import FlextResult
from pydantic import SecretStr

from flext_auth.constants import FlextAuthConstants
from flext_auth.typings import FlextAuthTypes


class FlextAuthUtilities:
    """Generic authentication utilities with password and token processing."""

    @staticmethod
    def hash_credential(
        credential: str, rounds: int = FlextAuthConstants.HASH_ROUNDS_DEFAULT
    ) -> FlextResult[str]:
        """Generic credential hashing using bcrypt.

        Args:
        credential: Credential to hash
        rounds: Bcrypt rounds

        Returns:
        FlextResult with hashed credential or error

        """
        try:
            salt = bcrypt.gensalt(rounds=rounds)
            hashed = bcrypt.hashpw(credential.encode("utf-8"), salt)
            return FlextResult[str].ok(hashed.decode("utf-8"))
        except Exception as e:
            return FlextResult[str].fail(f"Hashing failed: {e}")

    @staticmethod
    def verify_credential(credential: str, credential_hash: str) -> FlextResult[bool]:
        """Generic credential verification.

        Args:
        credential: Plain credential to verify
        credential_hash: Stored hash

        Returns:
        FlextResult with boolean or error

        """
        try:
            is_valid = bcrypt.checkpw(
                credential.encode("utf-8"), credential_hash.encode("utf-8")
            )
            return FlextResult[bool].ok(is_valid)
        except Exception as e:
            return FlextResult[bool].fail(f"Verification failed: {e}")

    @staticmethod
    def validate_credential_strength(
        credential: str,
    ) -> FlextResult[FlextAuthTypes.Security.CredentialStrength]:
        """Generic credential strength validation.

        Args:
        credential: Credential to validate

        Returns:
        FlextResult with validation result dict or error

        """
        errors: list[str] = []
        if len(credential) < FlextAuthConstants.CREDENTIAL_MIN_LENGTH:
            errors.append(f"Min length: {FlextAuthConstants.CREDENTIAL_MIN_LENGTH}")
        if len(credential) > FlextAuthConstants.CREDENTIAL_MAX_LENGTH:
            errors.append(f"Max length: {FlextAuthConstants.CREDENTIAL_MAX_LENGTH}")
        if not any(c.isupper() for c in credential):
            errors.append("Need uppercase letter")
        if not any(c.islower() for c in credential):
            errors.append("Need lowercase letter")
        if not any(c.isdigit() for c in credential):
            errors.append("Need digit")

        result: FlextAuthTypes.Security.CredentialStrength = {
            "is_valid": not errors,
            "length": len(credential),
            "errors": tuple(errors),
        }
        return FlextResult[FlextAuthTypes.Security.CredentialStrength].ok(result)

    @staticmethod
    def encode_token(
        payload: FlextAuthTypes.Tokens.ClaimMap,
        secret: str,
        algorithm: str = FlextAuthConstants.ALGORITHM_DEFAULT,
    ) -> FlextResult[str]:
        """Generic JWT token encoding.

        Args:
        payload: Token payload
        secret: Secret key for signing
        algorithm: JWT algorithm

        Returns:
        FlextResult with encoded token or error

        """
        try:
            token = jwt.encode(payload, secret, algorithm=algorithm)
            return FlextResult[str].ok(
                token if isinstance(token, str) else token.decode()
            )
        except Exception as e:
            return FlextResult[str].fail(f"Encoding failed: {e}")

    @staticmethod
    def decode_token(
        token: str,
        secret: SecretStr,
        *,
        verify: bool = True,
        algorithms: tuple[str, ...] | None = None,
    ) -> FlextResult[FlextAuthTypes.Tokens.ClaimMap]:
        """Generic JWT token decoding.

        Args:
        token: JWT token to decode
        secret: Secret key for verification
        verify: Whether to verify signature

        Returns:
        FlextResult with decoded payload or error

        """
        try:
            payload = jwt.decode(
                token,
                secret.get_secret_value(),
                algorithms=list(algorithms or (FlextAuthConstants.ALGORITHM_DEFAULT,)),
                options={"verify_signature": verify},
            )
            if not isinstance(payload, dict):
                return FlextResult[FlextAuthTypes.Tokens.ClaimMap].fail(
                    "Decoded token payload is not a dictionary"
                )

            typed_payload: FlextAuthTypes.Tokens.ClaimMap = {
                str(key): value for key, value in payload.items()
            }
            return FlextResult[FlextAuthTypes.Tokens.ClaimMap].ok(typed_payload)
        except jwt.InvalidTokenError as e:
            return FlextResult[FlextAuthTypes.Tokens.ClaimMap].fail(
                f"Invalid token: {e}"
            )
        except Exception as e:
            return FlextResult[FlextAuthTypes.Tokens.ClaimMap].fail(
                f"Decoding failed: {e}"
            )


__all__ = ["FlextAuthUtilities"]
