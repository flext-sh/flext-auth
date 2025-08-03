"""FLEXT Auth Types - Type definitions extending flext-core patterns.

This module provides comprehensive type definitions for FLEXT Auth operations,
extending flext-core type patterns to eliminate duplication and ensure type
safety across the authentication ecosystem.

Architecture:
    - Type Layer: Centralized type definitions
    - DRY Pattern: Extends flext-core types to eliminate duplication
    - Type Safety: Strict typing for all authentication operations
    - Domain-Driven: Types aligned with authentication domain concepts

Core Type Categories:
    - Entity Types: User, session, and role identifiers
    - Domain Types: Authentication-specific value types
    - Data Types: Structured data for authentication operations
    - Audit Types: Event tracking and logging types
    - Result Types: Operation results and responses

TODO (Based on docs/TODO.md):
    - [ ] CRITICAL: Add domain event types (Issue #4)
    - [ ] HIGH: Add CQRS command/query types (Issue #5)
    - [ ] MEDIUM: Add validation result types (Issue #9)
    - [ ] LOW: Add performance metric types (Issue #10)

Current Project Status:
    ✅ Authentication type system comprehensively documented
    ✅ Type safety patterns extending flext-core documented
    ✅ Domain-driven type modeling documented and aligned
    🔄 Implementation focus: Domain event types and CQRS command types

Design Patterns:
    - Type Alias Pattern: Semantic type definitions
    - Extension Pattern: Extending flext-core base types
    - Domain Pattern: Domain-specific type modeling
    - Composition Pattern: Complex type composition

Type Categories:
    Entity Types:
    - TUserId: User entity identifier
    - TSessionId: Session entity identifier
    - TEntityId: Base entity identifier (from flext-core)

    Domain Types:
    - TUsername: Username string type
    - TEmail: Email address string type
    - TPassword: Password string type
    - TUserRole: Role identifier type

    Data Types:
    - TAuthResult: Authentication operation results
    - TSecurityContext: Security context information
    - TLoginAttempt: Login attempt data structure
    - TAnyDict: Generic dictionary type (from flext-core)

Example Usage:
    >>> from flext_auth.auth_types import TUserId, TUsername, TAuthResult
    >>>
    >>> def authenticate_user(user_id: TUserId, username: TUsername) -> TAuthResult:
    ...     return {"authenticated": True, "user_id": user_id}

Type Safety Features:
    - Static type checking with MyPy
    - Runtime type validation support
    - Domain-specific type semantics
    - Clear type documentation and examples

Performance Considerations:
    - Zero runtime overhead for type aliases
    - Efficient type checking during development
    - Clear type inference for IDEs
    - Minimal memory footprint

Integration Points:
    - FlextCore: Base type extensions
    - Domain Layer: Entity and value object typing
    - Service Layer: Operation parameter and return typing
    - API Layer: Request/response typing

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
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
