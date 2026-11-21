"""Authentication constants namespace values.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_auth._constants import FlextAuthConstantsAuthSecurity


class FlextAuthConstantsAuthValues(FlextAuthConstantsAuthSecurity):
    """Complete authentication constants namespace."""

    REGISTRY_PROVIDERS_CATEGORY: ClassVar[str] = "auth_providers"
    REGISTRY_CONFIG_CATEGORY: ClassVar[str] = f"{REGISTRY_PROVIDERS_CATEGORY}config"
    REGISTRY_METADATA_CATEGORY: ClassVar[str] = (
        f"{REGISTRY_PROVIDERS_CATEGORY}_metadata"
    )
    PROVIDER_VERSION: ClassVar[str] = "1.0.0"
    KEYCLOAK_MISSING_BEARER: ClassVar[str] = "missing bearer credential"
    "Failure for an absent or non-Bearer Authorization value."
    KEYCLOAK_REJECTED_CREDENTIAL: ClassVar[str] = "Invalid realm token"
    "Failure prefix for a realm token that fails verification."
    KEYCLOAK_SIGNING_KEYS_UNAVAILABLE: ClassVar[str] = "Realm signing keys unavailable"
    "Failure prefix when the realm key set cannot be fetched."
    KEYCLOAK_NOT_ACCESS_CREDENTIAL: ClassVar[str] = "Realm token is not an access token"
    "Failure for a verified realm token whose typ is not the access type."
    KEYCLOAK_MISSING_SCOPE: ClassVar[str] = "missing required scope"
    "Failure prefix for a caller lacking the required scope."


__all__: list[str] = ["FlextAuthConstantsAuthValues"]
