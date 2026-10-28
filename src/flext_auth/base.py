"""Shared service base for flext-auth components.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import override

from flext_core import FlextService

from flext_auth import FlextAuthSettings, m, p, r


class FlextAuthServiceBase(FlextService[bool]):
    """Base class for auth services with typed configuration access."""

    @property
    @override
    def settings(self) -> p.Auth.Settings:
        """Typed auth settings namespace.

        Raises:
            TypeError: If the runtime holds another settings type.

        """
        current = super().settings
        if not isinstance(current, p.Auth.Settings):
            msg = "Auth service runtime requires the auth settings contract"
            raise TypeError(msg)
        return current

    @classmethod
    def runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Declare the settings owner consumed by the shared service runtime.

        Returns:
            Bootstrap options selecting the Auth settings class.

        """
        return m.RuntimeBootstrapOptions(settings_type=FlextAuthSettings)

    @override
    def execute(self) -> p.Result[bool]:
        """Reject generic execution in favor of focused auth operations.

        Returns:
            The resulting ``p.Result[bool]``.

        """
        return r[bool].fail("Use a service-specific authentication operation")


s = FlextAuthServiceBase

__all__: MutableSequence[str] = ["FlextAuthServiceBase", "s"]
