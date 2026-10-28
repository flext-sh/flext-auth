"""Test typings for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from typing import TYPE_CHECKING, Literal

from flext_tests import FlextTestsTypes

from flext_auth import FlextAuthTypes

if TYPE_CHECKING:
    import pytest


class TestsFlextAuthTypes(FlextTestsTypes, FlextAuthTypes):
    """Test typings for flext-auth — extends flext_auth.t."""

    class Tests(FlextTestsTypes.Tests):
        """Test-scoped literal aliases."""

        type LogCapture = pytest.LogCaptureFixture

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


# Published short name (ldap family shape): the tests package exposes the
# test-typings facade as ``t`` so consumer modules import it as published
# instead of aliasing the class at every call site.
t = TestsFlextAuthTypes

__all__: list[str] = ["TestsFlextAuthTypes", "t"]
