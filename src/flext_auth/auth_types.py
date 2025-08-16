"""FLEXT Auth Types - Type definitions extending flext-core patterns."""

from __future__ import annotations

from flext_core import TEntityId

# =============================================================================
# AUTHENTICATION TYPES - Using flext-core efficiently
# =============================================================================

# Core entity types extending flext-core
type TUserId = TEntityId
type TSessionId = TEntityId

# Authentication domain types
type TUsername = str
type TEmail = str
type TPassword = str
type TUserRole = str

# Authentication data types - SOLID refactoring: specific types instead of Any
type TAuthResult = dict[str, object]  # Authentication result with user data
type TSecurityContext = dict[str, object]  # Security context with permissions
type TLoginAttempt = dict[str, object]  # Login attempt data with metadata

# Audit types
type TAuditEventType = str

# =============================================================================
# EXPORTS - Clean types API
# =============================================================================

__all__: list[str] = [
    # Audit types
    "TAuditEventType",
    # Authentication data types
    "TAuthResult",
    "TEmail",
    "TLoginAttempt",
    "TPassword",
    "TSecurityContext",
    "TSessionId",
    # Core entity types
    "TUserId",
    "TUserRole",
    # Authentication domain types
    "TUsername",
]
