"""FLEXT Auth - Advanced Features Examples.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import secrets

from flext_auth import FlextAuth, c, p, r, u


class FlextAuthAdvancedFeaturesExample:
    """Single owner for the advanced features example flow."""

    logger = u.fetch_logger(__name__)

    @staticmethod
    def _demo_credential(prefix: str) -> str:
        """Per-run demo credential; the example never embeds a reusable secret.

        Returns:
            The resulting ``str``.
        """
        return f"{prefix}-{secrets.token_hex(6)}"

    @staticmethod
    def example_jwt_operations() -> p.Result[bool]:
        """Register an admin, authenticate it and validate the issued JWT.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        demo_password = os.getenv(
            "EXAMPLE_PASSWORD",
        ) or FlextAuthAdvancedFeaturesExample._demo_credential("jwt")
        user_result = auth.register_user(
            username="advanced_user",
            email="advanced@example.com",
            password=demo_password,
            roles=["admin", "user"],
        )
        if user_result.failure:
            return r[bool].from_failure(user_result)
        auth_result = auth.authenticate_user(
            username="advanced_user",
            password=demo_password,
        )
        if auth_result.failure:
            return r[bool].from_failure(auth_result)
        return auth.token_service.validate_token(auth_result.value.token)

    @staticmethod
    def example_role_based_access() -> p.Result[bool]:
        """Register users with distinct roles and confirm each grant.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        for username, roles in (
            ("admin", ["admin", "user"]),
            ("manager", ["manager", "user"]),
            ("employee", ["user"]),
        ):
            result = auth.register_user(
                username,
                f"{username}@company.com",
                FlextAuthAdvancedFeaturesExample._demo_credential(username),
                roles=roles,
            )
            if result.failure:
                return r[bool].from_failure(result)
            if tuple(result.value.roles) != tuple(roles):
                return r[bool].fail(f"{username} was registered with other roles")
        return r[bool].ok(value=True)

    @staticmethod
    def example_session_management() -> p.Result[bool]:
        """Each authentication opens its own session.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        password = FlextAuthAdvancedFeaturesExample._demo_credential("session")
        user_result = auth.register_user("sessionuser", "session@example.com", password)
        if user_result.failure:
            return r[bool].from_failure(user_result)
        first = auth.authenticate_user("sessionuser", password)
        if first.failure:
            return r[bool].from_failure(first)
        first_session_id = first.value.session_id
        second = auth.authenticate_user("sessionuser", password)
        if second.failure:
            return r[bool].from_failure(second)
        return r[bool].ok(first_session_id != second.value.session_id)

    @staticmethod
    def example_token_validation() -> p.Result[bool]:
        """A real token validates; malformed tokens are rejected.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        user_result = auth.register_user(
            "tokenuser",
            "token@example.com",
            FlextAuthAdvancedFeaturesExample._demo_credential("token"),
        )
        if user_result.failure:
            return r[bool].from_failure(user_result)
        token_result = auth.create_token(identity_id=user_result.value.unique_id)
        if token_result.failure:
            return r[bool].from_failure(token_result)
        valid = auth.token_service.validate_token(token_result.value)
        if valid.failure:
            return valid
        rejected = all(
            not (outcome := auth.token_service.validate_token(token)).success
            or not outcome.value
            for token in (
                "invalid.token.format",
                "",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid",
            )
        )
        return r[bool].ok(valid.value and rejected)

    @staticmethod
    def example_account_lockout() -> p.Result[bool]:
        """After the configured failed attempts even the right password is refused.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        password = FlextAuthAdvancedFeaturesExample._demo_credential("lockout")
        user_result = auth.register_user("lockoutuser", "lockout@example.com", password)
        if user_result.failure:
            return r[bool].from_failure(user_result)
        wrong = FlextAuthAdvancedFeaturesExample._demo_credential("wrong")
        attempts = tuple(
            auth.authenticate_user("lockoutuser", wrong)
            for _ in range(c.Auth.SECURITY_MAX_LOGIN_ATTEMPTS)
        )
        if any(attempt.success for attempt in attempts):
            return r[bool].fail("A wrong password authenticated")
        return r[bool].ok(auth.authenticate_user("lockoutuser", password).failure)

    @classmethod
    def main(cls) -> None:
        """Run every advanced example; the first failure escapes with its cause."""
        for example in (
            cls.example_jwt_operations,
            cls.example_role_based_access,
            cls.example_session_management,
            cls.example_token_validation,
            cls.example_account_lockout,
        ):
            outcome = example().unwrap()
            cls.logger.info(
                "Advanced example finished",
                example=example.__name__,
                ok=outcome,
            )


if __name__ == "__main__":
    FlextAuthAdvancedFeaturesExample.main()
