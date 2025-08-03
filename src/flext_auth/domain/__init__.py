"""FLEXT Auth Domain Layer - Domain entities and value objects following DDD patterns.

This module represents the domain layer of FLEXT Auth following Domain-Driven Design
principles. It contains the core business logic and domain models that encapsulate
authentication rules, business invariants, and domain knowledge.

Architecture:
    - Domain Layer: Core business logic and domain models
    - Rich Entities: Business logic embedded in domain entities
    - Immutable Value Objects: Type-safe value representations
    - Domain Events: Business events for enterprise patterns (TODO)

Domain Structure:
    - entities.py: Rich domain entities with business logic
        * FlextUser: User account with authentication business rules
        * FlextSession: Session lifecycle and validation logic
        * FlextRole: Role-based access control with permissions
        * FlextLoginAttempt: Security monitoring and audit trails

    - value_objects.py: Immutable value objects with validation
        * FlextUsername: Username with format validation
        * FlextUserEmail: Email with RFC compliance validation
        * FlextPlainPassword: Password with strength requirements
        * FlextJWTClaims: JWT token claims with security validation

Business Rules:
    - User accounts enforce lockout policies after failed attempts
    - Sessions validate expiration and revocation status
    - Passwords meet complexity requirements and strength policies
    - Login attempts are tracked for security monitoring
    - All domain operations use railway-oriented programming

TODO (Based on docs/TODO.md):
    - [ ] HIGH: Implement FlextAggregateRoot for event sourcing (Issue #4)
    - [ ] HIGH: Add domain events for all business operations (Issue #4)
    - [ ] HIGH: Implement CQRS command handlers (Issue #5)
    - [ ] MEDIUM: Add audit trails for security events (Issue #11)
    - [ ] MEDIUM: Add domain service abstractions (Issue #6)

Design Patterns:
    - Domain-Driven Design: Rich domain model with business logic
    - Layered Architecture: Clear separation of domain concerns
    - Entity Pattern: Identity-based domain objects
    - Value Object Pattern: Immutable domain values
    - Aggregate Pattern: Consistency boundaries for business operations
    - Repository Pattern: Domain object persistence abstraction
    - Factory Pattern: Complex domain object creation

Security Features:
    - Business rules prevent common authentication vulnerabilities
    - Domain entities validate all state changes
    - Value objects prevent invalid data construction
    - Immutable patterns prevent accidental state mutation
    - Type safety ensures correct business rule enforcement

Example Usage:
    >>> from flext_auth.domain.entities import FlextUser, FlextUserRole
    >>> from flext_auth.domain.value_objects import FlextUsername, FlextUserEmail
    >>>
    >>> # Create domain objects with validation
    >>> username = FlextUsername(value="john_doe")
    >>> email = FlextUserEmail(address="john@example.com")
    >>> user = FlextUser(
    ...     id="user123",
    ...     username=username.value,
    ...     email=email.address,
    ...     role=FlextUserRole.USER
    ... )

Integration Points:
    - Application Layer: Domain entities used by application services
    - Infrastructure Layer: Repository patterns for persistence
    - FlextCore: Base entity and value object patterns
    - Domain Events: Event-driven architecture support (TODO)

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

__all__: list[str] = []
