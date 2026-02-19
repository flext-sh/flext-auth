# ADR-001: Multi-Provider Authentication Architecture

<!-- TOC START -->

- [Status](#status)
- [Context](#context)
  - [Problem Statement](#problem-statement)
  - [Background](#background)
  - [Current State](#current-state)
  - [Constraints](#constraints)
  - [Stakeholders](#stakeholders)
- [Decision](#decision)
  - [Decision Statement](#decision-statement)
  - [Implementation Approach](#implementation-approach)
  - [Scope](#scope)
- [Consequences](#consequences)
  - [Positive Consequences](#positive-consequences)
  - [Negative Consequences](#negative-consequences)
  - [Trade-offs](#trade-offs)
- [Alternatives Considered](#alternatives-considered)
  - [Option 1: Monolithic Protocol Support](#option-1-monolithic-protocol-support)
  - [Option 2: Plugin System with Duck Typing](#option-2-plugin-system-with-duck-typing)
  - [Option 3: Strategy Pattern per Protocol](#option-3-strategy-pattern-per-protocol)
- [Implementation Plan](#implementation-plan)
  - [Phase 1: Foundation & Registry (✅ Complete)](#phase-1-foundation-registry-complete)
  - [Phase 2: Core Providers (✅ Complete)](#phase-2-core-providers-complete)
  - [Phase 3: Advanced Providers (✅ Mostly Complete)](#phase-3-advanced-providers-mostly-complete)
  - [Phase 4: Transport & Protocol (⚠️ Partial)](#phase-4-transport-protocol-partial)
- [Success Metrics](#success-metrics)
  - [Quantitative Metrics](#quantitative-metrics)
  - [Qualitative Metrics](#qualitative-metrics)
- [Related ADRs](#related-adrs)
- [References](#references)
  - [External References](#external-references)
  - [Internal References](#internal-references)
- [Notes](#notes)
  - [Implementation Challenges](#implementation-challenges)
  - [Future Considerations](#future-considerations)
  - [Lessons Learned](#lessons-learned)

<!-- TOC END -->

## Status

**Status**: Accepted

**Date**: 2025-10-10

**Deciders**: FLEXT Architecture Team

## Context

### Problem Statement

How should flext-auth support multiple authentication protocols (JWT, OAuth2, SAML, LDAP, etc.) while maintaining clean architecture, extensibility, and production quality?

### Background

The original flext-auth was designed as a simple JWT/bcrypt authentication library. As the FLEXT ecosystem grew, there was increasing demand for:

- Enterprise SSO integration (SAML, OAuth2/OIDC)
- Directory service authentication (LDAP)
- API key authentication for service-to-service communication
- Certificate-based authentication
- Multi-protocol support within the same application

The existing monolithic JWT implementation couldn't easily accommodate these requirements without significant code duplication and architectural compromise.

### Current State

- Single JWT provider implementation
- Hard-coded authentication logic
- Limited extensibility
- Production-ready for JWT use cases
- Strong foundation with FlextResult patterns

### Constraints

- Must maintain backward compatibility with existing JWT API
- Must integrate with FLEXT ecosystem (flext-core, flext-api)
- Must support enterprise security requirements
- Must be maintainable and testable
- Must follow FLEXT architectural patterns

### Stakeholders

- Application developers using flext-auth
- Enterprise customers requiring SSO
- DevOps teams deploying authentication services
- Security teams managing compliance
- FLEXT ecosystem maintainers

## Decision

### Decision Statement

Implement a provider-centric architecture where authentication protocols are encapsulated in interchangeable provider implementations, orchestrated through a central registry system.

### Implementation Approach

1. **Provider Protocol**: Define `FlextAuthBaseProvider` abstract interface
1. **Registry System**: Implement `FlextAuthRegistry` for provider management
1. **Provider Implementations**: Extract JWT to `FlextAuthJwtProvider`, create stubs for other protocols
1. **Facade Pattern**: Maintain `FlextAuth` as clean API facade
1. **Backward Compatibility**: Preserve existing API while adding new capabilities

### Scope

**Included**:

- Provider registration and discovery
- Multiple authentication protocols
- Dynamic provider selection
- FLEXT ecosystem integration

**Excluded**:

- Transport layer (HTTP/gRPC) - Phase 4
- Advanced token management - Phase 5
- UI components - handled by consuming applications

## Consequences

### Positive Consequences

- **Extensibility**: Easy addition of new authentication protocols
- **Maintainability**: Clear separation of concerns
- **Testability**: Each provider can be tested independently
- **Flexibility**: Runtime provider selection and configuration
- **Ecosystem Integration**: Follows FLEXT patterns and integrates well

### Negative Consequences

- **Complexity**: Increased architectural complexity
- **Learning Curve**: Developers need to understand provider abstraction
- **Coordination**: Provider implementations may have different maturity levels
- **Testing**: More complex integration testing required

### Trade-offs

- **Complexity vs. Flexibility**: More complex architecture enables much greater flexibility
- **Immediate vs. Future Needs**: Investment in architecture now enables future requirements
- **Consistency vs. Protocol-Specific**: Standardized interface may not capture all protocol nuances

## Alternatives Considered

### Option 1: Monolithic Protocol Support

**Description**: Extend single authentication class to support multiple protocols internally

**Pros**:

- Simpler architecture
- Single code path
- Easier testing
- Faster initial implementation

**Cons**:

- Code duplication across protocols
- Harder to maintain and extend
- Tight coupling between protocols
- Difficult to add new protocols

**Why Rejected**: Doesn't scale for enterprise requirements, violates single responsibility principle

### Option 2: Plugin System with Duck Typing

**Description**: Use duck typing instead of formal interfaces, load providers dynamically

**Pros**:

- More flexible than strict interfaces
- Easier for third-party providers
- Less boilerplate code

**Cons**:

- Runtime errors instead of compile-time safety
- Harder to test and debug
- Less predictable behavior
- Documentation challenges

**Why Rejected**: Python's dynamic nature makes formal interfaces valuable for large codebases

### Option 3: Strategy Pattern per Protocol

**Description**: Use strategy pattern but keep all implementations in single file/class hierarchy

**Pros**:

- Clear pattern usage
- Single codebase
- Easier refactoring

**Cons**:

- Large files with mixed concerns
- Harder to work on individual protocols
- All protocols must be loaded even when not used

**Why Rejected**: Doesn't provide the modularity needed for enterprise deployment scenarios

## Implementation Plan

### Phase 1: Foundation & Registry (✅ Complete)

- Create provider registry system
- Define base provider protocol
- Extract JWT provider
- Update API facade

### Phase 2: Core Providers (✅ Complete)

- Implement OAuth2 provider
- Implement OIDC provider
- Implement API Key provider
- Implement Basic Auth provider

### Phase 3: Advanced Providers (✅ Mostly Complete)

- Implement SAML provider
- Implement LDAP provider
- Implement Certificate provider
- Kerberos provider (stub)

### Phase 4: Transport & Protocol (⚠️ Partial)

- HTTP transport adapter
- gRPC transport adapter (partial)
- Protocol handlers (pending)

## Success Metrics

### Quantitative Metrics

- 9+ authentication providers implemented
- 70%+ test coverage across providers
- \<100ms average authentication response time
- 99.9% uptime in production deployments

### Qualitative Metrics

- Positive developer feedback on extensibility
- Reduced time to add new authentication protocols
- Clear separation of protocol-specific logic
- Maintainable and well-tested codebase

## Related ADRs

## References

### External References

- [Strategy Pattern](https://refactoring.guru/design-patterns/strategy)
- [Provider Model Pattern](https://martinfowler.com/eaaCatalog/plugin.html)
- [C4 Model](https://c4model.com/) - Documentation approach

### Internal References

- [FLEXT Core Patterns](https://github.com/organization/flext/tree/main/flext-core/docs/architecture/)
- Architecture Overview
- Provider Implementations

## Notes

### Implementation Challenges

- Maintaining backward compatibility while introducing new architecture
- Coordinating multiple provider implementations at different maturity levels
- Balancing abstraction with protocol-specific requirements

### Future Considerations

- Provider versioning and compatibility
- Third-party provider ecosystem
- Provider performance benchmarking
- Security auditing across all providers

### Lessons Learned

- Start with clear interfaces and contracts
- Implement one provider completely as reference
- Use registry pattern for runtime flexibility
- Maintain comprehensive test coverage from day one
