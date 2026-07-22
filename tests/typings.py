from __future__ import annotations

from typing import Literal

from flext_auth import FlextAuthTypes
from flext_tests import FlextTestsTypes


class TestsFlextAuthTypes(FlextTestsTypes, FlextAuthTypes):
    """Test types for flext-auth."""

    class Tests(FlextTestsTypes.Tests):
        """Test-specific types."""

        type TokenTypeLiteral = Literal["access", "refresh", "api", "bearer"]
        type ProviderTypeLiteral = Literal[
            "basic",
            "jwt",
            "oauth2",
            "saml",
            "ldap",
            "certificate",
            "kerberos",
            "apikey",
        ]
        type RoleTypeLiteral = Literal[
            "REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"
        ]
        type PermissionTypeLiteral = Literal[
            "read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"
        ]


t = TestsFlextAuthTypes

__all__: list[str] = ["TestsFlextAuthTypes", "t"]
