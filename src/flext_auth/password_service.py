"""Backward-compat password_service facade for flext-auth.

Provides legacy import path for password service.
"""

from __future__ import annotations

from flext_auth.services import FlextPasswordService

__all__ = ["FlextPasswordService"]
