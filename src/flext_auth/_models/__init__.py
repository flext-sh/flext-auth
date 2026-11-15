# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Models package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import defer_lazy_bases, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._models.auth import FlextAuthModelsAuth
    from flext_auth._models.auth_credential import FlextAuthModelsAuthCredential
    from flext_auth._models.auth_identity import FlextAuthModelsAuthIdentity
    from flext_auth._models.auth_identity_request import (
        FlextAuthModelsAuthIdentityRequest,
    )
    from flext_auth._models.auth_provider_config import (
        FlextAuthModelsAuthProviderConfig,
    )
    from flext_auth._models.auth_response import FlextAuthModelsAuthResponse
    from flext_auth._models.auth_session import FlextAuthModelsAuthSession
    from flext_auth._models.auth_user_identity_extras import (
        FlextAuthModelsAuthUserIdentityExtras,
    )


__all__: tuple[str, ...] = (
    "FlextAuthModelsAuth",
    "FlextAuthModelsAuthCredential",
    "FlextAuthModelsAuthIdentity",
    "FlextAuthModelsAuthIdentityRequest",
    "FlextAuthModelsAuthProviderConfig",
    "FlextAuthModelsAuthResponse",
    "FlextAuthModelsAuthSession",
    "FlextAuthModelsAuthUserIdentityExtras",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextAuthModelsAuth": ".auth",
        "FlextAuthModelsAuthCredential": ".auth_credential",
        "FlextAuthModelsAuthIdentity": ".auth_identity",
        "FlextAuthModelsAuthIdentityRequest": ".auth_identity_request",
        "FlextAuthModelsAuthProviderConfig": ".auth_provider_config",
        "FlextAuthModelsAuthResponse": ".auth_response",
        "FlextAuthModelsAuthSession": ".auth_session",
        "FlextAuthModelsAuthUserIdentityExtras": ".auth_user_identity_extras",
    },
    public_exports=__all__,
    deferred_members={
        "FlextAuthModelsAuth": (),
        "FlextAuthModelsAuthCredential": ("PasswordUtil",),
        "FlextAuthModelsAuthIdentity": ("AuthIdentity",),
        "FlextAuthModelsAuthIdentityRequest": ("AuthIdentityRequest",),
        "FlextAuthModelsAuthProviderConfig": (
            "RegistryPortOptions",
            "ApplicationPortOptions",
            "IdentityPortOptions",
            "SessionPortOptions",
            "ProviderIdentityConfig",
            "ProviderTokenConfig",
            "ProviderOAuthConfig",
            "ProviderKerberosConfig",
            "ProviderSamlConfig",
            "ProviderLdapConfig",
            "ProviderConfig",
        ),
        "FlextAuthModelsAuthResponse": (
            "CredentialValidation",
            "AuthResponse",
            "OAuth2TokenResponse",
            "KerberosTicketData",
            "ProviderWrapper",
            "Providers",
        ),
        "FlextAuthModelsAuthSession": ("AuthSession",),
        "FlextAuthModelsAuthUserIdentityExtras": ("UserIdentityExtras",),
    },
)

defer_lazy_bases(
    __name__,
    {
        "FlextAuthModelsAuth": (
            (".", "FlextAuthModelsAuthCredential"),
            (".", "FlextAuthModelsAuthSession"),
            (".", "FlextAuthModelsAuthIdentityRequest"),
            (".", "FlextAuthModelsAuthIdentity"),
            (".", "FlextAuthModelsAuthProviderConfig"),
            (".", "FlextAuthModelsAuthResponse"),
            (".", "FlextAuthModelsAuthUserIdentityExtras"),
        ),
    },
)
