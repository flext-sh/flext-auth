# C4 Containers: Container Architecture Diagram


<!-- TOC START -->
- [Overview](#overview)
- [Container Architecture](#container-architecture)
  - [Technology Choices](#technology-choices)
- [Deployment Architecture](#deployment-architecture)
  - [Single Container Deployment](#single-container-deployment)
  - [Microservices Deployment](#microservices-deployment)
  - [Kubernetes Deployment](#kubernetes-deployment)
- [Container Relationships](#container-relationships)
  - [Data Flow](#data-flow)
  - [Communication Patterns](#communication-patterns)
- [Technology Stack Details](#technology-stack-details)
  - [Runtime Environment](#runtime-environment)
  - [Data Storage](#data-storage)
  - [External Integrations](#external-integrations)
- [Quality Attributes by Container](#quality-attributes-by-container)
  - [flext-auth Container](#flext-auth-container)
  - [Database Container](#database-container)
  - [External Services](#external-services)
- [Deployment Considerations](#deployment-considerations)
  - [Scaling Strategies](#scaling-strategies)
  - [High Availability](#high-availability)
  - [Security Considerations](#security-considerations)
- [Related Documentation](#related-documentation)
- [Diagram](#diagram)
<!-- TOC END -->

## Overview

The Container diagram shows the high-level technology choices and how the system is deployed as containers/services. This view abstracts away code and focuses on technology stacks and deployment architecture.

## Container Architecture

flext-auth is deployed as a Python-based container with external dependencies for authentication providers, data storage, and monitoring.

### Technology Choices

#### Application Container (flext-auth)

- **Technology**: Python 3.13+ FastAPI/ASGI application
- **Responsibilities**:
  - Authentication orchestration
  - Provider management
  - Token lifecycle management
  - API endpoints for auth operations
- **Interfaces**:
  - HTTP REST API (primary)
  - gRPC service interface
  - Internal Python API

#### Database Container

- **Technology**: PostgreSQL / Redis / MongoDB (configurable)
- **Responsibilities**:
  - User credential storage
  - Session data persistence
  - Token blacklists/whitelists
  - Audit log storage
- **Interfaces**:
  - SQL/NoSQL database protocols
  - Connection pooling
  - Transaction management

#### External Identity Providers

- **Technology**: Various (LDAP, OAuth2, SAML servers)
- **Responsibilities**:
  - User identity verification
  - Credential validation
  - Multi-factor authentication
  - Single sign-on support
- **Interfaces**:
  - LDAP protocol
  - OAuth2/OIDC protocols
  - SAML 2.0 protocol
  - Kerberos protocol

#### FLEXT Ecosystem Services

- **Technology**: Python services (flext-api, flext-core)
- **Responsibilities**:
  - HTTP transport integration
  - Foundation utilities and patterns
  - Observability and monitoring
  - Service mesh communication
- **Interfaces**:
  - HTTP/gRPC APIs
  - Shared Python libraries
  - Message queues
  - Service discovery

#### Monitoring & Observability

- **Technology**: Prometheus, ELK stack, Jaeger
- **Responsibilities**:
  - Metrics collection
  - Log aggregation
  - Distributed tracing
  - Alert management
- **Interfaces**:
  - Metrics endpoints
  - Log shipping protocols
  - Trace propagation
  - Alert webhooks

## Deployment Architecture

### Single Container Deployment

```
┌─────────────────┐
│   flext-auth    │
│   (Python)      │
│                 │
│ • Auth Logic    │
│ • Providers     │
│ • API Endpoints │
│ • In-memory DB  │
└─────────────────┘
```

### Microservices Deployment

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   flext-auth    │    │   Database      │    │   Identity      │
│   (Auth Service)│◄──►│   (PostgreSQL)  │    │   Providers     │
│                 │    │                 │    │                 │
│ • API Gateway   │    │ • User Data     │    │ • LDAP Server   │
│ • Provider Reg  │    │ • Sessions      │    │ • OAuth2 Server │
│ • Token Mgmt    │    │ • Audit Logs    │    │ • SAML IdP      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  ▼
                    ┌─────────────────┐
                    │   Monitoring    │
                    │   (Prometheus)  │
                    │                 │
                    │ • Metrics       │
                    │ • Logs          │
                    │ • Traces        │
                    │ • Alerts        │
                    └─────────────────┘
```

### Kubernetes Deployment

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  flext-auth     │    │  PostgreSQL     │                │
│  │  Deployment     │    │  StatefulSet    │                │
│  │                 │    │                 │                │
│  │ • 3 Replicas    │◄──►│ • Persistent    │                │
│  │ • Service       │    │   Volume        │                │
│  │ • Ingress       │    │ • Backup        │                │
│  └─────────────────┘    └─────────────────┘                │
│           │                                                  │
│           ▼                                                  │
│  ┌─────────────────┐    ┌─────────────────┐                │
│  │  Redis Cache    │    │  Prometheus     │                │
│  │  (Sessions)     │    │  Monitoring     │                │
│  └─────────────────┘    └─────────────────┘                │
└─────────────────────────────────────────────────────────────┘
```

## Container Relationships

### Data Flow

1. **Authentication Request** → flext-auth container
2. **Provider Selection** → Identity provider lookup
3. **Credential Verification** → External identity provider
4. **Token Generation** → Internal JWT creation
5. **Session Storage** → Database/Redis persistence
6. **Audit Logging** → Database storage
7. **Metrics Export** → Monitoring system

### Communication Patterns

- **Synchronous**: HTTP/gRPC for real-time authentication
- **Asynchronous**: Message queues for audit logging
- **Batch**: Periodic cleanup operations
- **Streaming**: Real-time security event monitoring

## Technology Stack Details

### Runtime Environment

- **Python Version**: 3.13+
- **Framework**: FastAPI/ASGI for HTTP, grpcio for gRPC
- **Security**: cryptography, bcrypt, PyJWT
- **Validation**: Pydantic v2 for data models

### Data Storage

- **Primary Database**: PostgreSQL (production), SQLite (development)
- **Cache**: Redis for sessions and tokens
- **Search**: Elasticsearch for audit log analysis
- **Backup**: Automated database backups

### External Integrations

- **Identity Providers**: Configurable protocol support
- **Monitoring**: Prometheus metrics, structured logging
- **Security**: Integration with enterprise security tools
- **CI/CD**: Automated testing and deployment pipelines

## Quality Attributes by Container

### flext-auth Container

- **Security**: Encryption, secure token handling
- **Performance**: Sub-100ms authentication responses
- **Reliability**: Circuit breakers, graceful degradation
- **Maintainability**: Modular provider architecture

### Database Container

- **Durability**: ACID transactions, data consistency
- **Performance**: Connection pooling, query optimization
- **Availability**: Replication, failover support
- **Security**: Encrypted data at rest and in transit

### External Services

- **Compatibility**: Multiple protocol support
- **Reliability**: Retry logic, fallback mechanisms
- **Security**: Secure communication protocols
- **Monitoring**: Health checks and status monitoring

## Deployment Considerations

### Scaling Strategies

- **Horizontal Scaling**: Multiple flext-auth replicas
- **Database Scaling**: Read replicas, sharding
- **Cache Scaling**: Redis cluster configuration
- **Load Balancing**: Kubernetes services, ingress controllers

### High Availability

- **Pod Anti-affinity**: Spread across nodes
- **Health Checks**: Liveness and readiness probes
- **Rolling Updates**: Zero-downtime deployments
- **Backup Strategy**: Regular database backups

### Security Considerations

- **Network Policies**: Kubernetes network segmentation
- **Secret Management**: External secret stores
- **TLS Everywhere**: Encrypted communication
- **Access Controls**: RBAC and network policies

## Related Documentation

- Component Architecture - Internal component structure
- Security Architecture - Security design
- Data Architecture - Data storage patterns

## Diagram

```plantuml
@startuml Container Architecture
!include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Container.puml

title Container diagram for flext-auth

Person(user, "User", "Application user requiring authentication")

System_Boundary(flext_auth_system, "flext-auth System") {

    Container(auth_service, "flext-auth Service", "Python/FastAPI", "Authentication orchestration, provider management, token lifecycle")

    ContainerDb(database, "Database", "PostgreSQL/Redis", "User data, sessions, audit logs, token storage")

    Container(ext_providers, "Identity Providers", "LDAP/OAuth2/SAML", "External authentication services")

    Container(monitoring, "Monitoring", "Prometheus/ELK", "Metrics, logs, alerts, tracing")
}

Container(flext_api, "flext-api", "Python/FastAPI", "HTTP transport, REST API integration")
Container(flext_core, "flext-core", "Python", "Foundation patterns and utilities")

Rel(user, auth_service, "Authenticates via", "HTTPS")

Rel(auth_service, database, "Reads/writes user data", "JDBC/SQL")
Rel(auth_service, ext_providers, "Delegates authentication", "LDAP/OAuth2/SAML")
Rel(auth_service, monitoring, "Sends metrics/logs", "HTTP/Push")

Rel(auth_service, flext_api, "Uses for HTTP transport", "REST/gRPC")
Rel(auth_service, flext_core, "Uses foundation patterns", "Python imports")

@enduml
```

_Note: This diagram is generated from PlantUML source. See diagrams/plantuml/container-architecture.puml for the source file._
