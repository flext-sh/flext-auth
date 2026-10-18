"""FLEXT Auth API facade.

Public entrypoint kept as a strict facade over service classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuthSettings, p, t, u
from flext_auth.services import (
    FlextAuthApplicationService,
    FlextAuthIdentityService,
    FlextAuthProviderBuiltinRegistration,
    FlextAuthProviderService,
    FlextAuthSessionService,
)


class FlextAuth(FlextAuthApplicationService, FlextAuthProviderBuiltinRegistration):
    """Authentication facade composing identity, token, session and providers."""

    def __init__(
        self,
        *,
        registry: p.Registry | None = None,
        runtime_settings: p.Settings | None = None,
    ) -> None:
        """Compose an isolated graph, or explicitly share injected capabilities."""
        elected_registry = registry if registry is not None else u.build_registry()
        elected_settings = (
            runtime_settings if runtime_settings is not None else FlextAuthSettings()
        )
        identity_manager = u.Auth.FlextAuthUserManager()
        identity_service = FlextAuthIdentityService(
            identity_manager=identity_manager,
            runtime_settings=elected_settings,
        )
        session_service = FlextAuthSessionService(
            provider_service=FlextAuthProviderService(
                registry=elected_registry,
                runtime_settings=elected_settings,
            ),
            user_manager=identity_manager,
            session_manager=u.Auth.FlextAuthSessionManager(),
            runtime_settings=elected_settings,
        )
        super().__init__(
            registry=elected_registry,
            identity_service=identity_service,
            session_service=session_service,
            runtime_settings=elected_settings,
        )
        self._register_builtin_providers()


auth = FlextAuth()
"""Public application instance, explicitly composed at the API boundary."""


__all__: t.MutableSequenceOf[str] = ["FlextAuth", "auth"]
