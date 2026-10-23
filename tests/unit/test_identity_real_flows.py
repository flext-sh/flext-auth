"""Identity persistence through the public authentication services.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth import FlextAuth
from tests import c, tm


class TestsFlextAuthIdentityRealFlows:
    """Credential mutations and access state survive a fresh public read."""

    pytestmark = pytest.mark.usefixtures("reset_auth_singleton")

    @staticmethod
    @pytest.mark.parametrize(c.ContextScope.OPERATION, ["change", "reset", "access"])
    def test_persisted_credential_and_access_state(operation: str) -> None:
        """Credentials and successful access remain visible after fresh reads."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        identity = auth.register_user(
            "identity-flow-user", "identity-flow@example.com", c.TEST_CREDENTIAL
        ).unwrap()
        service = auth.identity_service
        manager = service.identity_manager
        replacement = c.TEST_CREDENTIAL + "_updated"
        if operation == "change":
            tm.ok(
                service.change_credential(
                    identity.unique_id, c.TEST_CREDENTIAL, replacement
                ),
                eq=True,
            )
        elif operation == "reset":
            tm.ok(service.reset_credential(identity.unique_id, replacement), eq=True)
        credential = c.TEST_CREDENTIAL if operation == "access" else replacement
        reloaded = tm.ok(manager.fetch_user(identity.unique_id))
        tm.ok(reloaded.verify_credential(credential), eq=True)
        rejected_credential = (
            c.TEST_CREDENTIAL + "_wrong" if operation == "access" else c.TEST_CREDENTIAL
        )
        tm.fail(
            auth.authenticate({
                "username": identity.name,
                "password": rejected_credential,
            })
        )
        tm.that(tm.ok(manager.fetch_user(identity.unique_id)).failed_attempts, eq=1)
        authenticated = tm.ok(
            auth.authenticate({"username": identity.name, "password": credential})
        )
        after_success = tm.ok(manager.fetch_user(identity.unique_id))
        tm.that(after_success.failed_attempts, eq=0)
        tm.that(after_success.last_access, eq=authenticated.last_access)
        tm.ok(after_success.last_access > identity.last_access)
        tm.that(after_success.locked_until, eq=identity.locked_until)
        tm.that(authenticated.unique_id, eq=identity.unique_id)
        tm.fail(
            auth.authenticate({
                "username": identity.name,
                "password": c.TEST_CREDENTIAL + "_wrong",
            })
        )
        tm.that(tm.ok(manager.fetch_user(identity.unique_id)).failed_attempts, eq=1)

    @staticmethod
    @pytest.mark.parametrize(
        (c.ContextScope.OPERATION, "failure"),
        [
            ("change", "incorrect"),
            ("change", "short"),
            ("reset", "short"),
            ("change", "missing"),
            ("reset", "missing"),
        ],
    )
    def test_rejected_mutations_preserve_credentials_and_failure_metadata(
        operation: str, failure: str
    ) -> None:
        """Rejected changes preserve the real credential and lookup diagnostics."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        identity = auth.register_user(
            "identity-flow-user", "identity-flow@example.com", c.TEST_CREDENTIAL
        ).unwrap()
        service = auth.identity_service
        manager = service.identity_manager
        identity_id = (
            identity.unique_id + "-missing"
            if failure == "missing"
            else identity.unique_id
        )
        replacement = (
            c.TEST_CREDENTIAL[: c.Auth.CREDENTIAL_MIN_LENGTH - 1]
            if failure == "short"
            else c.TEST_CREDENTIAL + "_updated"
        )
        current = (
            c.TEST_CREDENTIAL + "_wrong"
            if failure == "incorrect"
            else c.TEST_CREDENTIAL
        )
        result = (
            service.change_credential(identity_id, current, replacement)
            if operation == "change"
            else service.reset_credential(identity_id, replacement)
        )
        tm.fail(result)
        if failure == "missing":
            lookup = manager.fetch_user(identity_id)
            tm.fail(lookup, code=c.ErrorCode.NOT_FOUND_ERROR)
            tm.that(result.error_code, eq=lookup.error_code)
            tm.that(result.error, eq=lookup.error)
            tm.that(result.error_data, eq=lookup.error_data)
        tm.that(
            tm.ok(manager.fetch_user(identity.unique_id)).credential_hash,
            eq=identity.credential_hash,
        )
        tm.ok(
            auth.authenticate({
                "username": identity.name,
                "password": c.TEST_CREDENTIAL,
            })
        )

    @staticmethod
    def test_invalid_stored_hash_preserves_verification_exception() -> None:
        """The real bcrypt failure survives authentication and change boundaries."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        identity = auth.register_user(
            "identity-flow-user", "identity-flow@example.com", c.TEST_CREDENTIAL
        ).unwrap()
        service = auth.identity_service
        manager = service.identity_manager
        stored = manager.update_user(
            identity.unique_id, credential_hash="invalid-bcrypt-hash"
        ).unwrap()
        verification = stored.verify_credential(c.TEST_CREDENTIAL)
        tm.fail(verification)
        tm.that(verification.exception, is_=ValueError)
        for result in (
            auth.authenticate({
                "username": identity.name,
                "password": c.TEST_CREDENTIAL,
            }),
            service.change_credential(
                identity.unique_id, c.TEST_CREDENTIAL, c.TEST_CREDENTIAL + "_updated"
            ),
        ):
            tm.fail(result)
            tm.that(result.exception, is_=ValueError)
            tm.that(result.error_code, eq=verification.error_code)
            tm.that(result.error_data, eq=verification.error_data)
        tm.that(
            tm.ok(manager.fetch_user(identity.unique_id)).credential_hash,
            eq=stored.credential_hash,
        )

    @staticmethod
    def test_invalid_update_preserves_stored_identity() -> None:
        """Rejected data leaves the stored identity and credential usable."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            "atomic-update-user", "atomic-update@example.com", c.TEST_CREDENTIAL
        ).unwrap()
        manager = auth.identity_service.identity_manager
        before = manager.fetch_user(registered.unique_id).unwrap()
        before_failed_attempts = before.failed_attempts

        rejected = manager.update_user(registered.unique_id, failed_attempts=-1)

        tm.fail(rejected)
        tm.that(rejected.exception, is_=c.ValidationError)
        after = manager.fetch_user(registered.unique_id).unwrap()
        tm.that(after.failed_attempts, eq=before_failed_attempts)
        tm.ok(after.verify_credential(c.TEST_CREDENTIAL), eq=True)
