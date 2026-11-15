"""Authentication security and validation constants.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._constants import FlextAuthConstantsAuthClaims
from flext_auth._constants.security_values import FlextAuthConstantsAuthSecurityValues


class FlextAuthConstantsAuthSecurity(
    FlextAuthConstantsAuthClaims, FlextAuthConstantsAuthSecurityValues
):
    """Security constants for JWT, OAuth2, credentials, and rate limits."""


__all__: list[str] = ["FlextAuthConstantsAuthSecurity"]
