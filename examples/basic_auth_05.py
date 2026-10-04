"""Basic Authentication Example using current flext-auth API.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os

from flext_cli import cli

from flext_auth import FlextAuth, FlextAuthSettings, p, r


class FlextAuthBasicAuthExample:
    """Single owner for the basic auth example flow."""

    @staticmethod
    def _emit(message: str) -> None:
        """Emit example output through the canonical CLI facade."""
        cli.print(message)

    @staticmethod
    def main() -> p.Result[bool]:
        """Demonstrate core auth workflow with the supported API surface.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth(settings=FlextAuthSettings())
        password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!")
        registration = auth.register_user(
            username="demouser",
            email="demo@example.com",
            password=password,
            roles=["user"],
        )
        if registration.failure:
            FlextAuthBasicAuthExample._emit(
                f"registration failed: {registration.error}",
            )
            return r[bool].from_failure(registration)
        authentication = auth.authenticate_user("demouser", password)
        if authentication.failure:
            FlextAuthBasicAuthExample._emit(
                f"authentication failed: {authentication.error}",
            )
            return r[bool].from_failure(authentication)
        identity = authentication.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        if token_result.failure:
            FlextAuthBasicAuthExample._emit(
                f"token generation failed: {token_result.error}",
            )
            return r[bool].from_failure(token_result)
        validation_result = auth.token_service.validate_token(token_result.value)
        FlextAuthBasicAuthExample._emit(
            f"token valid: {validation_result.success and validation_result.value}",
        )
        return validation_result


if __name__ == "__main__":
    FlextAuthBasicAuthExample.main().unwrap()
