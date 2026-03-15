# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core.typings import FlextTypes
    from tests import fixtures, helpers, unit
    from tests.conftest import mock_get_global
    from tests.constants import TestsFlextAuthConstants, c
    from tests.fixtures.certificates import (
        CertificateFixture,
        generate_client_cert,
        generate_self_signed_cert,
    )
    from tests.helpers.protocols import TestsProtocols
    from tests.helpers.typings import TestsTypings
    from tests.helpers.utilities import TestsUtilities
    from tests.models import TestsFlextAuthModels, m, tm
    from tests.protocols import TestsFlextAuthProtocols, p
    from tests.typings import TestsFlextAuthTypes, t
    from tests.unit.test_api import (
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
    from tests.unit.test_token_real_flows import HttpRequest, TestTokenRealFlows
    from tests.unit.test_typings import TestFlextAuthTypes
    from tests.utilities import TestsFlextAuthUtilities, u

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "CertificateFixture": ("tests.fixtures.certificates", "CertificateFixture"),
    "HttpRequest": ("tests.unit.test_token_real_flows", "HttpRequest"),
    "TestAuthModule": ("tests.unit.test_api", "TestAuthModule"),
    "TestFlextAuth": ("tests.unit.test_api", "TestFlextAuth"),
    "TestFlextAuthAdditionalCoverage": (
        "tests.unit.test_api",
        "TestFlextAuthAdditionalCoverage",
    ),
    "TestFlextAuthAdvancedPatterns": (
        "tests.unit.test_api",
        "TestFlextAuthAdvancedPatterns",
    ),
    "TestFlextAuthConstants": ("tests.unit.test_constants", "TestFlextAuthConstants"),
    "TestFlextAuthErrorHandling": ("tests.unit.test_api", "TestFlextAuthErrorHandling"),
    "TestFlextAuthErrorHandlingPaths": (
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingPaths",
    ),
    "TestFlextAuthErrorHandlingSecond": (
        "tests.unit.test_api",
        "TestFlextAuthErrorHandlingSecond",
    ),
    "TestFlextAuthErrorPaths": ("tests.unit.test_api", "TestFlextAuthErrorPaths"),
    "TestFlextAuthHandlerRegistration": (
        "tests.unit.test_api",
        "TestFlextAuthHandlerRegistration",
    ),
    "TestFlextAuthInitializationCoverage": (
        "tests.unit.test_api",
        "TestFlextAuthInitializationCoverage",
    ),
    "TestFlextAuthLogging": ("tests.unit.test_api", "TestFlextAuthLogging"),
    "TestFlextAuthModelSettingsuration": (
        "tests.unit.test_api",
        "TestFlextAuthModelSettingsuration",
    ),
    "TestFlextAuthPasswordMethods": (
        "tests.unit.test_api",
        "TestFlextAuthPasswordMethods",
    ),
    "TestFlextAuthProcessorRegistration": (
        "tests.unit.test_api",
        "TestFlextAuthProcessorRegistration",
    ),
    "TestFlextAuthProviderRegistry": (
        "tests.unit.test_api",
        "TestFlextAuthProviderRegistry",
    ),
    "TestFlextAuthQuickStart": ("tests.unit.test_api", "TestFlextAuthQuickStart"),
    "TestFlextAuthQuickStartFunction": (
        "tests.unit.test_api",
        "TestFlextAuthQuickStartFunction",
    ),
    "TestFlextAuthQuickStartMethod": (
        "tests.unit.test_api",
        "TestFlextAuthQuickStartMethod",
    ),
    "TestFlextAuthSecurity": ("tests.unit.test_api", "TestFlextAuthSecurity"),
    "TestFlextAuthServiceInitialization": (
        "tests.unit.test_api",
        "TestFlextAuthServiceInitialization",
    ),
    "TestFlextAuthSessionManagement": (
        "tests.unit.test_api",
        "TestFlextAuthSessionManagement",
    ),
    "TestFlextAuthSessionMethods": (
        "tests.unit.test_api",
        "TestFlextAuthSessionMethods",
    ),
    "TestFlextAuthSettingsBasic": (
        "tests.unit.test_config",
        "TestFlextAuthSettingsBasic",
    ),
    "TestFlextAuthSettingsurationMethods": (
        "tests.unit.test_api",
        "TestFlextAuthSettingsurationMethods",
    ),
    "TestFlextAuthSettingsurationOverrides": (
        "tests.unit.test_api",
        "TestFlextAuthSettingsurationOverrides",
    ),
    "TestFlextAuthStorageOperations": (
        "tests.unit.test_api",
        "TestFlextAuthStorageOperations",
    ),
    "TestFlextAuthTokenMethods": ("tests.unit.test_api", "TestFlextAuthTokenMethods"),
    "TestFlextAuthTokenOperations": (
        "tests.unit.test_api",
        "TestFlextAuthTokenOperations",
    ),
    "TestFlextAuthTypes": ("tests.unit.test_typings", "TestFlextAuthTypes"),
    "TestFlextAuthUserMethods": ("tests.unit.test_api", "TestFlextAuthUserMethods"),
    "TestJwtTokenGenerator": ("tests.unit.test_config", "TestJwtTokenGenerator"),
    "TestProviderTokenFlows": ("tests.unit.test_api", "TestProviderTokenFlows"),
    "TestTokenRealFlows": ("tests.unit.test_token_real_flows", "TestTokenRealFlows"),
    "TestsFlextAuthConstants": ("tests.constants", "TestsFlextAuthConstants"),
    "TestsFlextAuthModels": ("tests.models", "TestsFlextAuthModels"),
    "TestsFlextAuthProtocols": ("tests.protocols", "TestsFlextAuthProtocols"),
    "TestsFlextAuthTypes": ("tests.typings", "TestsFlextAuthTypes"),
    "TestsFlextAuthUtilities": ("tests.utilities", "TestsFlextAuthUtilities"),
    "TestsProtocols": ("tests.helpers.protocols", "TestsProtocols"),
    "TestsTypings": ("tests.helpers.typings", "TestsTypings"),
    "TestsUtilities": ("tests.helpers.utilities", "TestsUtilities"),
    "c": ("tests.constants", "c"),
    "fixtures": ("tests.fixtures", ""),
    "generate_client_cert": ("tests.fixtures.certificates", "generate_client_cert"),
    "generate_self_signed_cert": (
        "tests.fixtures.certificates",
        "generate_self_signed_cert",
    ),
    "helpers": ("tests.helpers", ""),
    "m": ("tests.models", "m"),
    "mock_get_global": ("tests.conftest", "mock_get_global"),
    "p": ("tests.protocols", "p"),
    "t": ("tests.typings", "t"),
    "tm": ("tests.models", "tm"),
    "u": ("tests.utilities", "u"),
    "unit": ("tests.unit", ""),
}

__all__ = [
    "CertificateFixture",
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
    "TestsFlextAuthConstants",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthTypes",
    "TestsFlextAuthUtilities",
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "c",
    "fixtures",
    "generate_client_cert",
    "generate_self_signed_cert",
    "helpers",
    "m",
    "mock_get_global",
    "p",
    "t",
    "tm",
    "u",
    "unit",
]


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
