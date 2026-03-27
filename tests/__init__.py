# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Tests package."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes
    from flext_tests import d, e, h, r, s, x

    from tests import fixtures, helpers, unit
    from tests.conftest import mock_get_global, reset_singletons
    from tests.constants import FlextAuthTestConstants, FlextAuthTestConstants as c
    from tests.fixtures.certificates import (
        CertificateFixture,
        generate_client_cert,
        generate_self_signed_cert,
    )
    from tests.helpers.protocols import TestsProtocols
    from tests.helpers.typings import TestsTypings
    from tests.helpers.utilities import TestsUtilities
    from tests.models import FlextAuthTestModels, FlextAuthTestModels as m
    from tests.protocols import FlextAuthTestProtocols, FlextAuthTestProtocols as p
    from tests.typings import FlextAuthTestTypes, FlextAuthTestTypes as t
    from tests.unit.test_api import (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthErrorHandling,
        TestFlextAuthErrorHandlingPaths,
        TestFlextAuthErrorHandlingSecond,
        TestFlextAuthErrorPaths,
        TestFlextAuthHandlerRegistration,
        TestFlextAuthInitializationCoverage,
        TestFlextAuthLogging,
        TestFlextAuthModelSettingsuration,
        TestFlextAuthPasswordMethods,
        TestFlextAuthProcessorRegistration,
        TestFlextAuthProviderRegistry,
        TestFlextAuthQuickStart,
        TestFlextAuthQuickStartFunction,
        TestFlextAuthQuickStartMethod,
        TestFlextAuthSecurity,
        TestFlextAuthServiceInitialization,
        TestFlextAuthSessionManagement,
        TestFlextAuthSessionMethods,
        TestFlextAuthSettingsurationMethods,
        TestFlextAuthSettingsurationOverrides,
        TestFlextAuthStorageOperations,
        TestFlextAuthTokenMethods,
        TestFlextAuthTokenOperations,
        TestFlextAuthUserMethods,
        TestProviderTokenFlows,
    )
    from tests.unit.test_config import TestFlextAuthSettingsBasic, TestJwtTokenGenerator
    from tests.unit.test_constants import TestFlextAuthConstants
    from tests.unit.test_token_real_flows import TestTokenRealFlows
    from tests.unit.test_typings import TestFlextAuthTypes
    from tests.utilities import FlextAuthTestUtilities, FlextAuthTestUtilities as u

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "CertificateFixture": ["tests.fixtures.certificates", "CertificateFixture"],
    "FlextAuthTestConstants": ["tests.constants", "FlextAuthTestConstants"],
    "FlextAuthTestModels": ["tests.models", "FlextAuthTestModels"],
    "FlextAuthTestProtocols": ["tests.protocols", "FlextAuthTestProtocols"],
    "FlextAuthTestTypes": ["tests.typings", "FlextAuthTestTypes"],
    "FlextAuthTestUtilities": ["tests.utilities", "FlextAuthTestUtilities"],
    "HttpRequest": ["tests.unit.test_api", "HttpRequest"],
    "TestAuthModule": ["tests.unit.test_api", "TestAuthModule"],
    "TestFlextAuth": ["tests.unit.test_api", "TestFlextAuth"],
    "TestFlextAuthAdditionalCoverage": [
        "tests.unit.test_api",
        "TestFlextAuthAdditionalCoverage",
    ],
    "TestFlextAuthAdvancedPatterns": [
        "tests.unit.test_api",
        "TestFlextAuthAdvancedPatterns",
    ],
    "TestFlextAuthConstants": ["tests.unit.test_constants", "TestFlextAuthConstants"],
    "TestFlextAuthErrorHandling": ["tests.unit.test_api", "TestFlextAuthErrorHandling"],
    "TestFlextAuthErrorHandlingPaths": [
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingPaths",
    ],
    "TestFlextAuthErrorHandlingSecond": [
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingSecond",
    ],
    "TestFlextAuthErrorPaths": ["tests.unit.test_api", "TestFlextAuthErrorPaths"],
    "TestFlextAuthHandlerRegistration": [
        "tests.unit.test_api",
        "TestFlextAuthHandlerRegistration",
    ],
    "TestFlextAuthInitializationCoverage": [
        "tests.unit.test_api",
        "TestFlextAuthInitializationCoverage",
    ],
    "TestFlextAuthLogging": ["tests.unit.test_api", "TestFlextAuthLogging"],
    "TestFlextAuthModelSettingsuration": [
        "tests.unit.test_api",
        "TestFlextAuthModelSettingsuration",
    ],
    "TestFlextAuthPasswordMethods": [
        "tests.unit.test_api",
        "TestFlextAuthPasswordMethods",
    ],
    "TestFlextAuthProcessorRegistration": [
        "tests.unit.test_api",
        "TestFlextAuthProcessorRegistration",
    ],
    "TestFlextAuthProviderRegistry": [
        "tests.unit.test_api",
        "TestFlextAuthProviderRegistry",
    ],
    "TestFlextAuthQuickStart": ["tests.unit.test_api", "TestFlextAuthQuickStart"],
    "TestFlextAuthQuickStartFunction": [
        "tests.unit.test_api",
        "TestFlextAuthQuickStartFunction",
    ],
    "TestFlextAuthQuickStartMethod": [
        "tests.unit.test_api",
        "TestFlextAuthQuickStartMethod",
    ],
    "TestFlextAuthSecurity": ["tests.unit.test_api", "TestFlextAuthSecurity"],
    "TestFlextAuthServiceInitialization": [
        "tests.unit.test_api",
        "TestFlextAuthServiceInitialization",
    ],
    "TestFlextAuthSessionManagement": [
        "tests.unit.test_api",
        "TestFlextAuthSessionManagement",
    ],
    "TestFlextAuthSessionMethods": [
        "tests.unit.test_api",
        "TestFlextAuthSessionMethods",
    ],
    "TestFlextAuthSettingsBasic": [
        "tests.unit.test_config",
        "TestFlextAuthSettingsBasic",
    ],
    "TestFlextAuthSettingsurationMethods": [
        "tests.unit.test_api",
        "TestFlextAuthSettingsurationMethods",
    ],
    "TestFlextAuthSettingsurationOverrides": [
        "tests.unit.test_api",
        "TestFlextAuthSettingsurationOverrides",
    ],
    "TestFlextAuthStorageOperations": [
        "tests.unit.test_api",
        "TestFlextAuthStorageOperations",
    ],
    "TestFlextAuthTokenMethods": ["tests.unit.test_api", "TestFlextAuthTokenMethods"],
    "TestFlextAuthTokenOperations": [
        "tests.unit.test_api",
        "TestFlextAuthTokenOperations",
    ],
    "TestFlextAuthTypes": ["tests.unit.test_typings", "TestFlextAuthTypes"],
    "TestFlextAuthUserMethods": ["tests.unit.test_api", "TestFlextAuthUserMethods"],
    "TestJwtTokenGenerator": ["tests.unit.test_config", "TestJwtTokenGenerator"],
    "TestProviderTokenFlows": ["tests.unit.test_api", "TestProviderTokenFlows"],
    "TestTokenRealFlows": ["tests.unit.test_token_real_flows", "TestTokenRealFlows"],
    "TestsProtocols": ["tests.helpers.protocols", "TestsProtocols"],
    "TestsTypings": ["tests.helpers.typings", "TestsTypings"],
    "TestsUtilities": ["tests.helpers.utilities", "TestsUtilities"],
    "c": ["tests.constants", "FlextAuthTestConstants"],
    "d": ["flext_tests", "d"],
    "e": ["flext_tests", "e"],
    "fixtures": ["tests.fixtures", ""],
    "generate_client_cert": ["tests.fixtures.certificates", "generate_client_cert"],
    "generate_self_signed_cert": [
        "tests.fixtures.certificates",
        "generate_self_signed_cert",
    ],
    "h": ["flext_tests", "h"],
    "helpers": ["tests.helpers", ""],
    "m": ["tests.models", "FlextAuthTestModels"],
    "mock_get_global": ["tests.conftest", "mock_get_global"],
    "p": ["tests.protocols", "FlextAuthTestProtocols"],
    "r": ["flext_tests", "r"],
    "reset_singletons": ["tests.conftest", "reset_singletons"],
    "s": ["flext_tests", "s"],
    "t": ["tests.typings", "FlextAuthTestTypes"],
    "u": ["tests.utilities", "FlextAuthTestUtilities"],
    "unit": ["tests.unit", ""],
    "x": ["flext_tests", "x"],
}

__all__ = [
    "CertificateFixture",
    "FlextAuthTestConstants",
    "FlextAuthTestModels",
    "FlextAuthTestProtocols",
    "FlextAuthTestTypes",
    "FlextAuthTestUtilities",
    "HttpRequest",
    "TestAuthModule",
    "TestFlextAuth",
    "TestFlextAuthAdditionalCoverage",
    "TestFlextAuthAdvancedPatterns",
    "TestFlextAuthConstants",
    "TestFlextAuthErrorHandling",
    "TestFlextAuthErrorHandlingPaths",
    "TestFlextAuthErrorHandlingSecond",
    "TestFlextAuthErrorPaths",
    "TestFlextAuthHandlerRegistration",
    "TestFlextAuthInitializationCoverage",
    "TestFlextAuthLogging",
    "TestFlextAuthModelSettingsuration",
    "TestFlextAuthPasswordMethods",
    "TestFlextAuthProcessorRegistration",
    "TestFlextAuthProviderRegistry",
    "TestFlextAuthQuickStart",
    "TestFlextAuthQuickStartFunction",
    "TestFlextAuthQuickStartMethod",
    "TestFlextAuthSecurity",
    "TestFlextAuthServiceInitialization",
    "TestFlextAuthSessionManagement",
    "TestFlextAuthSessionMethods",
    "TestFlextAuthSettingsBasic",
    "TestFlextAuthSettingsurationMethods",
    "TestFlextAuthSettingsurationOverrides",
    "TestFlextAuthStorageOperations",
    "TestFlextAuthTokenMethods",
    "TestFlextAuthTokenOperations",
    "TestFlextAuthTypes",
    "TestFlextAuthUserMethods",
    "TestJwtTokenGenerator",
    "TestProviderTokenFlows",
    "TestTokenRealFlows",
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "c",
    "d",
    "e",
    "fixtures",
    "generate_client_cert",
    "generate_self_signed_cert",
    "h",
    "helpers",
    "m",
    "mock_get_global",
    "p",
    "r",
    "reset_singletons",
    "s",
    "t",
    "u",
    "unit",
    "x",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
