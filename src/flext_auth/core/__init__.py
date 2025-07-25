"""FlextAuth Core - Core library classes with FlextAuth prefixes.

All classes are designed for massive code reduction and extreme usability.
"""

from __future__ import annotations

from flext_auth.core.authentication import FlextAuthAuthenticator
from flext_auth.core.authorization import FlextAuthAuthorizer
from flext_auth.core.manager import FlextAuthManager
from flext_auth.core.password import FlextAuthPasswordManager
from flext_auth.core.session import FlextAuthSessionManager
from flext_auth.core.token import FlextAuthTokenManager
from flext_auth.core.validation import FlextAuthValidator

__all__ = [
    "FlextAuthAuthenticator",
    "FlextAuthAuthorizer",
    "FlextAuthManager",
    "FlextAuthPasswordManager",
    "FlextAuthSessionManager",
    "FlextAuthTokenManager",
    "FlextAuthValidator",
]
