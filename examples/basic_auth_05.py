"""Basic Authentication Example using current flext-auth API."""

from __future__ import annotations

import os

from flext_auth import FlextAuth, FlextAuthSettings


def main() -> None:
    """Demonstrate core auth workflow with the supported API surface."""
    auth = FlextAuth(config=FlextAuthSettings())
    password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoPassword123!")
    registration = auth.register_user(
        username="demouser", email="demo@example.com", password=password, roles=["user"]
    )
    if registration.is_failure:
        print(f"registration failed: {registration.error}")
        return
    authentication = auth.authenticate_user("demouser", password)
    if authentication.is_failure:
        print(f"authentication failed: {authentication.error}")
        return
    identity = authentication.value
    token_result = auth.create_token(identity_id=identity.unique_id)
    if token_result.is_failure:
        print(f"token generation failed: {token_result.error}")
        return
    validation_result = auth.validate_token(token_result.value)
    print(f"token valid: {validation_result.is_success and validation_result.value}")


if __name__ == "__main__":
    main()
