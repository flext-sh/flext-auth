"""FLEXT Auth - Enterprise authentication library following flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.__version__ import __version__
from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.exceptions import FlextAuthExceptions

# Middleware adapters for HTTP clients and web applications (v2.1.0)
from flext_auth.middleware import HttpAuthMiddleware, WebAuthMiddleware
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols

# Provider system (v2.0.0 API)
from flext_auth.providers import (
    ApiKeyAuthProvider,
    BaseAuthProvider,
    BaseAuthProviderMixin,
    BasicAuthProvider,
    CertificateAuthProvider,
    JwtAuthProvider,
    KerberosAuthProvider,
    LdapAuthProvider,
    OAuth2AuthProvider,
    OidcAuthProvider,
    SamlAuthProvider,
)
from flext_auth.registry import FlextAuthRegistry
from flext_auth.typings import FlextAuthTypes

# Note: FlextAuthUtilities and FlextAuthMixins are INTERNAL ONLY - not exported

__all__ = [
    # Phase 3 Providers (v2.0.0)
    "ApiKeyAuthProvider",
    # Base provider protocol
    "BaseAuthProvider",
    "BaseAuthProviderMixin",
    "BasicAuthProvider",
    "CertificateAuthProvider",
    # Core API (v1.0.0)
    "FlextAuth",
    "FlextAuthConfig",
    "FlextAuthConstants",
    "FlextAuthExceptions",
    "FlextAuthModels",
    "FlextAuthProtocols",
    "FlextAuthRegistry",
    "FlextAuthTypes",
    # Middleware adapters (v2.1.0)
    "HttpAuthMiddleware",
    # Phase 1 Provider (v1.0.0)
    "JwtAuthProvider",
    "KerberosAuthProvider",
    "LdapAuthProvider",
    # Phase 2 Providers (v2.0.0)
    "OAuth2AuthProvider",
    "OidcAuthProvider",
    "SamlAuthProvider",
    "WebAuthMiddleware",
    "__version__",
]
