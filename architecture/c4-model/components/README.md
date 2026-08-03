# C4 Components: Component Architecture Diagram

<!-- TOC START -->
- [Overview](#overview)
- [Component Architecture](#component-architecture)
  - [Core Components](#core-components)
- [Component Relationships](#component-relationships)
  - [Data Flow Architecture](#data-flow-architecture)
  - [Key Interaction Patterns](#key-interaction-patterns)
- [Design Patterns Used](#design-patterns-used)
  - [Provider Pattern (Strategy)](#provider-pattern-strategy)
  - [Registry Pattern](#registry-pattern)
  - [Facade Pattern](#facade-pattern)
  - [Railway-Oriented Programming](#railway-oriented-programming)
- [Component Boundaries](#component-boundaries)
  - [Clear Responsibilities](#clear-responsibilities)
  - [Dependency Direction](#dependency-direction)
  - [Interface Segregation](#interface-segregation)
- [Quality Attributes by Component](#quality-attributes-by-component)
  - [Security](#security)
  - [Performance](#performance)
  - [Maintainability](#maintainability)
- [Testing Strategy by Component](#testing-strategy-by-component)
  - [Unit Testing](#unit-testing)
  - [Integration Testing](#integration-testing)
  - [End-to-End Testing](#end-to-end-testing)
- [Related Documentation](#related-documentation)
- [Diagram](#diagram)
<!-- TOC END -->

## Overview

The Component diagram shows the internal structure of flext-auth, focusing on the key components, their responsibilities, and relationships. This view zooms into the container to show the architectural building blocks.

## Component Architecture

flext-auth follows a provider-centric architecture with clear separation of concerns. The system is organized around a facade pattern with specialized components for different aspects of authentication.

### Core Components

#### FlextAuth (API Facade)

- **Type**: Main application facade
- **Responsibilities**:
  - Unified authentication API
  - Backward compatibility layer
  - Provider orchestration
  - Configuration management
- **Key Methods**:
  - `register_user()` - User registration
  - `authenticate_user()` - User authentication
  - `validate_token()` - Token validation
  - `generate_token_for_user()` - Token generation

#### FlextAuthRegistry (Provider Registry)

- **Type**: Component registry and factory
- **Responsibilities**:
  - Dynamic provider registration
  - Provider discovery and instantiation
  - Capability detection and metadata
  - Configuration validation
- **Key Features**:
  - Plugin-style provider loading
  - Runtime provider switching
  - Metadata-driven configuration

#### Provider Ecosystem

- **Type**: Strategy pattern implementation
- **Responsibilities**:
  - Protocol-specific authentication logic
  - Credential validation
  - Token generation and validation
  - Provider-specific security controls

##### FlextAuthJwtProvider

- **Protocol**: JWT (JSON Web Tokens)
- **Features**: HS256 signing, bcrypt password hashing, configurable expiry
- **Status**: Production-ready

##### FlextAuthOAuth2Provider

- **Protocol**: OAuth 2.0 (Authorization Code, Client Credentials, etc.)
- **Features**: PKCE support, multiple grant types, token refresh
- **Status**: Implemented

##### FlextAuthOidcProvider

- **Protocol**: OpenID Connect
- **Features**: ID token validation, userinfo endpoint, discovery
- **Status**: Implemented

##### Additional Providers

- **FlextAuthSamlProvider**: SAML 2.0 SP-initiated flows
- **FlextAuthLdapProvider**: LDAP directory authentication
- **FlextAuthCertificateProvider**: X.509 certificate authentication
- **FlextAuthBasicProvider**: HTTP Basic Authentication
- **FlextAuthApiKeyProvider**: API key authentication
- **FlextAuthKerberosProvider**: Kerberos network authentication

#### Service Layer

##### FlextAuthUserService

- **Type**: Domain service
- **Responsibilities**:
  - User lifecycle management
  - Password hashing and validation
  - User data persistence
  - Account status management

##### FlextAuthTokenService

- **Type**: Domain service
- **Responsibilities**:
  - Token generation and validation
  - Token lifecycle management
  - Token blacklisting/whitelisting
  - Token refresh operations

##### FlextAuthSessionService

- **Type**: Domain service
- **Responsibilities**:
  - Session creation and management
  - Session persistence and retrieval
  - Session cleanup and expiration
  - Concurrent session limits

##### FlextAuthProviderService

- **Type**: Orchestration service
- **Responsibilities**:
  - Provider selection and delegation
  - Multi-provider authentication flows
  - Provider capability negotiation
  - Fallback and error handling

#### Transport Layer (Phase 4)

##### FlextWebTransportAdapter

- **Type**: Transport adapter
- **Responsibilities**:
  - HTTP request/response handling
  - REST API integration
  - Middleware integration
  - Request/response transformation

##### GrpcTransportAdapter (Partial)

- **Type**: Transport adapter
- **Responsibilities**:
  - gRPC service implementation
  - Protocol buffer handling
  - Streaming support
  - High-performance communication

#### Configuration & Infrastructure

##### FlextAuthSettings

- **Type**: Configuration management
- **Responsibilities**:
  - Configuration loading and validation
  - Environment variable handling
  - Configuration builder pattern
  - Runtime reconfiguration

##### FlextAuthConstants

- **Type**: System constants
- **Responsibilities**:
  - Authentication protocol constants
  - Security configuration values
  - Default settings and limits
  - Provider-specific parameters

##### FlextAuthModels

- **Type**: Domain models
- **Responsibilities**:
  - Pydantic data models
  - Type validation and serialization
  - Domain t.JsonValue definitions
  - API request/response schemas

## Component Relationships

### Data Flow Architecture

```
HTTP Request
    ↓
FlextWebTransportAdapter
    ↓
FlextAuth (Facade)
    ↓
Provider Selection → FlextAuthRegistry
    ↓
Authentication → [Provider Implementation]
    ↓
Token Generation → FlextAuthTokenService
    ↓
Session Management → FlextAuthSessionService
    ↓
Response ← FlextWebTransportAdapter
```

### Key Interaction Patterns

#### Provider Registration

1. **Startup**: FlextAuthRegistry loads available providers
1. **Configuration**: Provider-specific settings are validated
1. **Registration**: Providers register capabilities and metadata
1. **Discovery**: Runtime provider selection based on requirements

#### Authentication Flow

1. **Request**: Authentication request received
1. **Validation**: Input validation and sanitization
1. **Provider Selection**: Registry selects appropriate provider
1. **Authentication**: Delegate to provider implementation
1. **Token Generation**: Create authentication tokens
1. **Session Creation**: Establish user session
1. **Response**: Return authentication result

#### Token Validation Flow

1. **Request**: Token validation request
1. **Parsing**: Extract token claims
1. **Verification**: Validate token signature and claims
1. **User Lookup**: Retrieve user information
1. **Session Check**: Validate session status
1. **Authorization**: Check permissions and roles
1. **Response**: Return validation result

## Design Patterns Used

### Provider Pattern (Strategy)

- **Context**: FlextAuth needs different authentication protocols
- **Strategy**: Interchangeable provider implementations
- **Concrete Strategies**: JWT, OAuth2, SAML, LDAP providers
- **Benefits**: Extensibility, testability, protocol independence

### Registry Pattern

- **Context**: Dynamic provider discovery and management
- **Registry**: FlextAuthRegistry manages provider lifecycle
- **Benefits**: Plugin architecture, runtime configuration, loose coupling

### Facade Pattern

- **Context**: Complex subsystem with multiple components
- **Facade**: FlextAuth provides simple authentication API
- **Subsystem**: Providers, services, configuration, transport
- **Benefits**: Simplified API, reduced coupling, backward compatibility

### Railway-Oriented Programming

- **Context**: Error handling across complex authentication flows
- **Railway**: p.Result[T] for composable error handling
- **Benefits**: Explicit error handling, composability, type safety

## Component Boundaries

### Clear Responsibilities

- **API Layer**: External interface and orchestration
- **Provider Layer**: Protocol-specific authentication logic
- **Service Layer**: Business logic and data management
- **Transport Layer**: Communication protocol handling
- **Infrastructure**: Configuration, constants, models

### Dependency Direction

```
Transport Layer ← API Layer ← Service Layer ← Provider Layer
Infrastructure ↑ ↑ ↑ ↑
```

### Interface Segregation

- **Provider Interface**: Authentication protocol contract
- **Service Interfaces**: Domain service contracts
- **Transport Interfaces**: Communication protocol contracts
- **Configuration Interface**: Settings and options contract

## Quality Attributes by Component

### Security

- **Provider Isolation**: Each provider handles its own security
- **Token Security**: Cryptographically secure token generation
- **Credential Protection**: Secure password hashing and storage
- **Audit Trail**: Comprehensive authentication logging

### Performance

- **Provider Selection**: Efficient runtime provider lookup
- **Token Caching**: Fast token validation with caching
- **Session Management**: Optimized session storage and retrieval
- **Async Support**: Non-blocking operations where applicable

### Maintainability

- **Modular Design**: Clear component boundaries and responsibilities
- **Type Safety**: Full type annotations throughout
- **Testability**: Each component can be tested in isolation
- **Extensibility**: Easy addition of new providers and services

## Testing Strategy by Component

### Unit Testing

- **Individual Components**: Isolated unit tests for each component
- **Provider Testing**: Mock external dependencies for provider testing
- **Service Testing**: In-memory repositories for service testing
- **Utility Testing**: Pure function testing for utilities

### Integration Testing

- **Component Integration**: Test component interactions
- **Provider Integration**: Test with real external services (LDAP, OAuth2)
- **Transport Integration**: Test HTTP/gRPC communication
- **Database Integration**: Test with real database connections

### End-to-End Testing

- **Authentication Flows**: Complete authentication scenarios
- **Multi-Provider Testing**: Test provider switching and fallback
- **Load Testing**: Performance testing under load
- **Security Testing**: Penetration testing and security validation

## Related Documentation

- Code Architecture - Implementation details and code organization
- Security Architecture - Security design and controls
- Quality Attributes - Component quality requirements

## Diagram

```plantuml
@startuml Component Architecture
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Component.puml

title Component diagram for flext-auth

Container_Boundary(auth_service, "flext-auth Service") {

    Component(api_facade, "FlextAuth API", "Python/FastAPI", "Main authentication facade and API orchestration")

    Component(provider_registry, "FlextAuthRegistry", "Python", "Provider registration and discovery system")

    Component(jwt_provider, "FlextAuthJwtProvider", "Python/PyJWT", "JWT authentication implementation")
    Component(oauth2_provider, "FlextAuthOAuth2Provider", "Python/authlib", "OAuth2 authentication implementation")
    Component(saml_provider, "FlextAuthSamlProvider", "Python/python3-saml", "SAML authentication implementation")

    Component(user_service, "FlextAuthUserService", "Python", "User management and lifecycle")
    Component(token_service, "FlextAuthTokenService", "Python", "Token generation and validation")
    Component(session_service, "FlextAuthSessionService", "Python", "Session management and persistence")

    Component(http_transport, "FlextWebTransportAdapter", "Python/FastAPI", "HTTP transport and middleware")
    Component(grpc_transport, "GrpcTransportAdapter", "Python/grpcio", "gRPC transport implementation")

    Component(settings, "FlextAuthSettings", "Python/Pydantic", "Configuration management")
    Component(constants, "FlextAuthConstants", "Python", "System constants and defaults")
    Component(models, "FlextAuthModels", "Python/Pydantic", "Domain models and schemas")
}

Component_Ext(ext_identity, "External Identity Providers", "LDAP/OAuth2/SAML")
ComponentDb(database, "Database", "PostgreSQL/Redis")
Component_Ext(monitoring, "Monitoring", "Prometheus/ELK")

Rel(api_facade, provider_registry, "Uses for provider discovery")
Rel(api_facade, user_service, "Delegates user operations")
Rel(api_facade, token_service, "Delegates token operations")
Rel(api_facade, session_service, "Delegates session operations")

Rel(provider_registry, jwt_provider, "Manages provider lifecycle")
Rel(provider_registry, oauth2_provider, "Manages provider lifecycle")
Rel(provider_registry, saml_provider, "Manages provider lifecycle")

Rel(jwt_provider, ext_identity, "Authenticates against external providers")
Rel(oauth2_provider, ext_identity, "Authenticates against external providers")
Rel(saml_provider, ext_identity, "Authenticates against external providers")

Rel(user_service, database, "Persists user data")
Rel(token_service, database, "Stores token data")
Rel(session_service, database, "Manages sessions")

Rel(api_facade, http_transport, "Uses for HTTP communication")
Rel(api_facade, grpc_transport, "Uses for gRPC communication")

Rel(api_facade, settings, "Reads configuration")
Rel(api_facade, constants, "Uses system constants")
Rel(api_facade, models, "Uses domain models")

Rel(api_facade, monitoring, "Sends metrics/logs")

@enduml
```

_Note: This diagram is generated from PlantUML source. See diagrams/plantuml/component-architecture.puml for the source file._
