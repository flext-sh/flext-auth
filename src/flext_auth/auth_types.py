"""Authentication types using flext-core patterns.

Simplified types eliminating duplication and leveraging flext-core's
type patterns directly.
"""

from __future__ import annotations

# Use flext-core types directly
from flext_core import TAnyDict, TEntityId

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

# Authentication data types
type TAuthResult = TAnyDict
type TSecurityContext = TAnyDict
type TLoginAttempt = TAnyDict

# Audit types
type TAuditEventType = str

# =============================================================================
# EXPORTS - Clean types API
# =============================================================================

__all__ = [
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
