"""Basic FLEXT Auth workflow examples.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
import secrets

from flext_auth import FlextAuth, p, r, u


class FlextAuthBasicUsageWorkflow:
    """Reusable full workflow usage examples."""

    logger = u.fetch_logger(__name__)

    @staticmethod
    def _demo_credential(prefix: str) -> str:
        """Per-run demo credential; the example never embeds a reusable secret.

        Returns:
            The resulting ``str``.
        """
        return f"{prefix}-{secrets.token_hex(6)}"

    @classmethod
    def example_advanced_registration(cls) -> p.Result[bool]:
        """Register an admin and a regular user and confirm their roles.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        password = os.getenv("FLEXT_DEMO_ADVANCED_PASSWORD") or cls._demo_credential(
            "advanced",
        )
        admin_result = auth.register_user(
            username="admin",
            email="admin@company.com",
            password=password,
            roles=["admin", "user"],
        )
        if admin_result.failure:
            return r[bool].from_failure(admin_result)
        user_result = auth.register_user(
            username="regularuser",
            email="user@company.com",
            password=password,
            roles=["user"],
        )
        if user_result.failure:
            return r[bool].from_failure(user_result)
        cls.logger.info(
            "Users registered",
            admin_has_admin_role="admin" in admin_result.value.roles,
            user_has_admin_role="admin" in user_result.value.roles,
        )
        return r[bool].ok(
            "admin" in admin_result.value.roles
            and "admin" not in user_result.value.roles,
        )

    @classmethod
    def example_complete_workflow(cls) -> p.Result[bool]:
        """Register, authenticate, validate the token and read the identity back.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        auth = FlextAuth()
        password = os.getenv("FLEXT_DEMO_WORKFLOW_PASSWORD") or cls._demo_credential(
            "workflow",
        )
        reg_result = auth.register_user(
            username="workflowuser",
            email="workflow@example.com",
            password=password,
        )
        if reg_result.failure:
            return r[bool].from_failure(reg_result)
        auth_result = auth.authenticate_user("workflowuser", password)
        if auth_result.failure:
            return r[bool].from_failure(auth_result)
        token_validation = auth.session_service.validate_token(auth_result.value.token)
        if token_validation.failure:
            return token_validation
        user_info = auth.identity_service.identity_manager.fetch_user(
            reg_result.value.unique_id,
        )
        if user_info.failure:
            return r[bool].from_failure(user_info)
        cls.logger.info("User information retrieved", name=user_info.value.name)
        return token_validation


__all__: list[str] = ["FlextAuthBasicUsageWorkflow"]
