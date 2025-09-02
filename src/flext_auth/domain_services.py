"""Backward-compat domain_services facade for flext-auth.

Exposes the primary authentication service under the legacy module name to
keep older imports working in tests and examples without deprecation shims.
"""

from __future__ import annotations

from flext_auth.core import FlextAuth

__all__ = ["FlextAuth"]
