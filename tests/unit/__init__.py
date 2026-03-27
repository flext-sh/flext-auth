# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Unit package."""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

    from tests.unit.test_api import (
        HttpRequest,
        TestAuthModule,
        TestFlextAuth,
        TestFlextAuthAdditionalCoverage,
        TestFlextAuthAdvancedPatterns,
        TestFlextAuthConfigurationMethods,
        TestFlextAuthConfigurationOverrides,
        TestFlextAuthErrorHandling,
        TestFlextAuthErrorHandlingPaths,
        TestFlextAuthErrorHandlingSecond,
        TestFlextAuthErrorPaths,
        TestFlextAuthHandlerRegistration,
        TestFlextAuthInitializationCoverage,
        TestFlextAuthLogging,
        TestFlextAuthModelConfiguration,
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

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "HttpRequest": ["tests.unit.test_api", "HttpRequest"],
    "TestAuthModule": ["tests.unit.test_api", "TestAuthModule"],
    "TestFlextAuth": ["tests.unit.test_api", "TestFlextAuth"],
    "TestFlextAuthAdditionalCoverage": ["tests.unit.test_api", "TestFlextAuthAdditionalCoverage"],
    "TestFlextAuthAdvancedPatterns": ["tests.unit.test_api", "TestFlextAuthAdvancedPatterns"],
    "TestFlextAuthConfigurationMethods": ["tests.unit.test_api", "TestFlextAuthConfigurationMethods"],
    "TestFlextAuthConfigurationOverrides": ["tests.unit.test_api", "TestFlextAuthConfigurationOverrides"],
    "TestFlextAuthConstants": ["tests.unit.test_constants", "TestFlextAuthConstants"],
    "TestFlextAuthErrorHandling": ["tests.unit.test_api", "TestFlextAuthErrorHandling"],
    "TestFlextAuthErrorHandlingPaths": ["tests.unit.test_api", "TestFlextAuthErrorHandlingPaths"],
    "TestFlextAuthErrorHandlingSecond": ["tests.unit.test_api", "TestFlextAuthErrorHandlingSecond"],
    "TestFlextAuthErrorPaths": ["tests.unit.test_api", "TestFlextAuthErrorPaths"],
    "TestFlextAuthHandlerRegistration": ["tests.unit.test_api", "TestFlextAuthHandlerRegistration"],
    "TestFlextAuthInitializationCoverage": ["tests.unit.test_api", "TestFlextAuthInitializationCoverage"],
    "TestFlextAuthLogging": ["tests.unit.test_api", "TestFlextAuthLogging"],
    "TestFlextAuthModelConfiguration": ["tests.unit.test_api", "TestFlextAuthModelConfiguration"],
    "TestFlextAuthPasswordMethods": ["tests.unit.test_api", "TestFlextAuthPasswordMethods"],
    "TestFlextAuthProcessorRegistration": ["tests.unit.test_api", "TestFlextAuthProcessorRegistration"],
    "TestFlextAuthProviderRegistry": ["tests.unit.test_api", "TestFlextAuthProviderRegistry"],
    "TestFlextAuthQuickStart": ["tests.unit.test_api", "TestFlextAuthQuickStart"],
    "TestFlextAuthQuickStartFunction": ["tests.unit.test_api", "TestFlextAuthQuickStartFunction"],
    "TestFlextAuthQuickStartMethod": ["tests.unit.test_api", "TestFlextAuthQuickStartMethod"],
    "TestFlextAuthSecurity": ["tests.unit.test_api", "TestFlextAuthSecurity"],
    "TestFlextAuthServiceInitialization": ["tests.unit.test_api", "TestFlextAuthServiceInitialization"],
    "TestFlextAuthSessionManagement": ["tests.unit.test_api", "TestFlextAuthSessionManagement"],
    "TestFlextAuthSessionMethods": ["tests.unit.test_api", "TestFlextAuthSessionMethods"],
    "TestFlextAuthSettingsBasic": ["tests.unit.test_config", "TestFlextAuthSettingsBasic"],
    "TestFlextAuthStorageOperations": ["tests.unit.test_api", "TestFlextAuthStorageOperations"],
    "TestFlextAuthTokenMethods": ["tests.unit.test_api", "TestFlextAuthTokenMethods"],
    "TestFlextAuthTokenOperations": ["tests.unit.test_api", "TestFlextAuthTokenOperations"],
    "TestFlextAuthTypes": ["tests.unit.test_typings", "TestFlextAuthTypes"],
    "TestFlextAuthUserMethods": ["tests.unit.test_api", "TestFlextAuthUserMethods"],
    "TestJwtTokenGenerator": ["tests.unit.test_config", "TestJwtTokenGenerator"],
    "TestProviderTokenFlows": ["tests.unit.test_api", "TestProviderTokenFlows"],
    "TestTokenRealFlows": ["tests.unit.test_token_real_flows", "TestTokenRealFlows"],
}

__all__ = [
    "HttpRequest",
    "TestAuthModule",
    "TestFlextAuth",
    "TestFlextAuthAdditionalCoverage",
    "TestFlextAuthAdvancedPatterns",
    "TestFlextAuthConfigurationMethods",
    "TestFlextAuthConfigurationOverrides",
    "TestFlextAuthConstants",
    "TestFlextAuthErrorHandling",
    "TestFlextAuthErrorHandlingPaths",
    "TestFlextAuthErrorHandlingSecond",
    "TestFlextAuthErrorPaths",
    "TestFlextAuthHandlerRegistration",
    "TestFlextAuthInitializationCoverage",
    "TestFlextAuthLogging",
    "TestFlextAuthModelConfiguration",
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
    "TestFlextAuthStorageOperations",
    "TestFlextAuthTokenMethods",
    "TestFlextAuthTokenOperations",
    "TestFlextAuthTypes",
    "TestFlextAuthUserMethods",
    "TestJwtTokenGenerator",
    "TestProviderTokenFlows",
    "TestTokenRealFlows",
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
