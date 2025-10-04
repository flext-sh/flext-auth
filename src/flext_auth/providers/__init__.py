"""FLEXT Auth Providers - Authentication provider implementations.

This package contains all authentication provider implementations following
the base provider protocol. Each provider encapsulates specific authentication
technology (JWT, OAuth2, SAML, etc.) while maintaining a unified interface.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes

from flext_auth.providers.apikey import ApiKeyAuthProvider
from flext_auth.providers.base import BaseAuthProvider, BaseAuthProviderMixin
from flext_auth.providers.basic import BasicAuthProvider
from flext_auth.providers.certificate import CertificateAuthProvider
from flext_auth.providers.jwt import JwtAuthProvider
from flext_auth.providers.kerberos import KerberosAuthProvider
from flext_auth.providers.ldap import LdapAuthProvider
from flext_auth.providers.oauth2 import OAuth2AuthProvider
from flext_auth.providers.oidc import OidcAuthProvider
from flext_auth.providers.saml import SamlAuthProvider

__all__: FlextTypes.StringList = [
    "ApiKeyAuthProvider",
    "BaseAuthProvider",
    "BaseAuthProviderMixin",
    "BasicAuthProvider",
    "CertificateAuthProvider",
    "JwtAuthProvider",
    "KerberosAuthProvider",
    "LdapAuthProvider",
    "OAuth2AuthProvider",
    "OidcAuthProvider",
    "SamlAuthProvider",
]
