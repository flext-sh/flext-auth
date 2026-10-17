"""Auth application lifecycle helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Self

from flext_auth import c, m, p, s, t


class FlextAuthApplicationLifecycle(s, ABC):
    """Auth provisioning composed with the shared service lifecycle.

    Concrete services provide identity registration and construction;
    flext-core owns singleton access, runtime settings and logging.

    """

    @abstractmethod
    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: t.StrSequence | None = None,
        role: str | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Register a new user identity with a hashed credential.

        Args:
            username: Unique account name for the new identity.
            email: Contact address bound to the identity.
            password: Plain credential to hash before storage.
            roles: Optional role names to grant.
            role: Optional single legacy role name to grant.

        Returns:
            The created identity entity.

        """
        raise NotImplementedError

    @classmethod
    def quick_start(cls, *, create_admin_user: bool = True) -> Self:
        """Construct the service and optionally provision an admin user.

        Args:
            create_admin_user: Provision the default admin identity when
                true.

        Returns:
            The freshly constructed service instance.

        """
        auth: Self = cls()
        if create_admin_user:
            result = auth.register_user(
                c.Auth.DEFAULT_ADMIN_USERNAME,
                c.Auth.DEFAULT_ADMIN_EMAIL,
                "AdminPass123!",
                roles=["ADMIN"],
            )
            if result.failure and result.error is not None:
                auth.logger.warning(
                    "Quick start admin user provisioning failed: %s",
                    result.error,
                )
        return auth


__all__: t.MutableSequenceOf[str] = ["FlextAuthApplicationLifecycle"]
