"""FLEXT Auth - Simple Production-Ready Authentication Library.

This library provides secure authentication functionality with:
- bcrypt password hashing with proper salts
- Simple session management
- User creation and authentication
- Production-ready security defaults

All functions return ServiceResult for consistent error handling.
"""

from __future__ import annotations

from flext_auth.core import ServiceResult

# Simple auth functions with production-ready security
from flext_auth.simple_auth import (
    authenticate_user,
    create_session,
    create_user,
    hash_password,
    validate_session,
    verify_password,
)

__version__ = "1.0.0"

__all__ = [
    "ServiceResult",
    "__version__",
    "authenticate_user",
    "create_session",
    "create_user",
    "hash_password",
    "validate_session",
    "verify_password",
]
