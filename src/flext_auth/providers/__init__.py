"""FLEXT Auth Providers - Authentication provider implementations.

This package contains all authentication provider implementations following
the base provider protocol. Each provider encapsulates specific authentication
technology (JWT, OAuth2, SAML, etc.) while maintaining a unified interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.providers.base import BaseAuthProvider, BaseAuthProviderMixin
from flext_auth.providers.jwt import JwtAuthProvider

__all__: list[str] = [
    "BaseAuthProvider",
    "BaseAuthProviderMixin",
    "JwtAuthProvider",
    # Will be populated as more providers are implemented
    # "OAuth2AuthProvider",
    # "OidcAuthProvider",
    # "SamlAuthProvider",
    # "ApiKeyAuthProvider",
    # "BasicAuthProvider",
    # "CertificateAuthProvider",
    # "LdapAuthProvider",
    # "KerberosAuthProvider",
]
