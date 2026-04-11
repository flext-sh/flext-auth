# FLEXT-AUTH ARCHITECTURE v2.0.0

<!-- TOC START -->
- [Generic Authentication API Framework](#generic-authentication-api-framework)
- [📋 TABLE OF CONTENTS](#table-of-contents)
- [🎯 EXECUTIVE SUMMARY](#executive-summary)
  - [Mission](#mission)
  - [Current State (v1.0.0)](#current-state-v100)
  - [Target State (v2.0.0)](#target-state-v200)
- [🏗️ ARCHITECTURAL VISION](#architectural-vision)
  - [Design Principles](#design-principles)
  - [Architectural Layers](#architectural-layers)
- [🔧 CORE COMPONENTS](#core-components)
  - [1. FlextAuth Facade (`api.py`)](#1-flextauth-facade-apipy)
  - [2. FlextAuthRegistry (`registry.py`)](#2-flextauthregistry-registrypy)
  - [3. Base Provider Protocol (`providers/base.py`)](#3-base-provider-protocol-providersbasepy)
- [🔌 PROVIDER ECOSYSTEM](#provider-ecosystem)
  - [Provider Categories](#provider-categories)
  - [Provider Implementation Pattern](#provider-implementation-pattern)
- [🚀 TRANSPORT LAYER](#transport-layer)
  - [Transport Abstraction (`transports/base.py`)](#transport-abstraction-transportsbasepy)
  - [HTTP Transport (`transports/http.py`)](#http-transport-transportshttppy)
  - [gRPC Transport (`transports/grpc.py`)](#grpc-transport-transportsgrpcpy)
  - [WebSocket Transport (`transports/websocket.py`)](#websocket-transport-transportswebsocketpy)
- [📡 PROTOCOL HANDLERS](#protocol-handlers)
  - [Protocol Handler Base (`protocol_handlers/base.py`)](#protocol-handler-base-protocolhandlersbasepy)
  - [REST Protocol Handler (`protocol_handlers/rest.py`)](#rest-protocol-handler-protocolhandlersrestpy)
  - [SOAP Protocol Handler (`protocol_handlers/soap.py`)](#soap-protocol-handler-protocolhandlerssoappy)
- [🎫 TOKEN MANAGEMENT](#token-management)
  - [Token Manager (`tokens/manager.py`)](#token-manager-tokensmanagerpy)
  - [Token Retry Logic (`tokens/retry.py`)](#token-retry-logic-tokensretrypy)
  - [Token Cache (`tokens/cache.py`)](#token-cache-tokenscachepy)
- [🔐 SECURITY ARCHITECTURE](#security-architecture)
  - [Security Principles](#security-principles)
  - [Credential Management (`credentials/manager.py`)](#credential-management-credentialsmanagerpy)
  - [Security Validations](#security-validations)
- [🔗 FLEXT INTEGRATION](#flext-integration)
  - [Mandatory FLEXT Domain Library Usage](#mandatory-flext-domain-library-usage)
  - [s Integration](#flextservice-integration)
- [📘 API DESIGN](#api-design)
  - [Public API Patterns](#public-api-patterns)
- [🏗️ IMPLEMENTATION PHASES](#implementation-phases)
  - [Phase 1: Foundation & Registry (Week 1) ✅ COMPLETE](#phase-1-foundation-registry-week-1-complete)
  - [Phase 2: Core Providers (Week 2) ✅ COMPLETE](#phase-2-core-providers-week-2-complete)
  - [Phase 3: Advanced Providers (Week 3) ✅ MOSTLY COMPLETE](#phase-3-advanced-providers-week-3-mostly-complete)
  - [Phase 4: Transport & Protocol (Week 4) ⚠️ PARTIALLY COMPLETE](#phase-4-transport-protocol-week-4-partially-complete)
  - [Phase 5: Token & Credential Management (Week 5)](#phase-5-token-credential-management-week-5)
  - [Phase 6: Documentation (Week 6)](#phase-6-documentation-week-6)
  - [Phase 7: QA & Release (Week 7)](#phase-7-qa-release-week-7)
- [✅ QUALITY STANDARDS](#quality-standards)
  - [Quality Gates (MANDATORY after each phase)](#quality-gates-mandatory-after-each-phase)
  - [Coverage Requirements](#coverage-requirements)
  - [Performance Standards](#performance-standards)
- [📝 APPENDIX](#appendix)
  - [Technology Stack Summary](#technology-stack-summary)
  - [Backward Compatibility Timeline](#backward-compatibility-timeline)
- [Related Documentation](#related-documentation)
<!-- TOC END -->

## Generic Authentication API Framework

**Version**: 2.0.0-dev
**Status**: In Development
**Last Updated**: 2025-10-01
**Parent**: FLEXT Workspace

______________________________________________________________________

## 📋 TABLE OF CONTENTS

1. Executive Summary
1. Architectural Vision
1. Core Components
1. Provider Ecosystem
1. Transport Layer
1. Protocol Handlers
1. Token Management
1. Session Management
1. Security Architecture
1. FLEXT Integration
1. API Design
1. Implementation Phases
1. Quality Standards

______________________________________________________________________

## 🎯 EXECUTIVE SUMMARY

### Mission

Transform flext-auth from a specific JWT/bcrypt authentication implementation into a **generic, extensible authentication API framework** that supports multiple authentication technologies, protocols, and transports while maintaining FLEXT ecosystem patterns and production quality.

### Current State (v1.0.0)

- **Purpose**: JWT/bcrypt authentication with session management
- **Status**: Production-ready, 71/72 tests passing (99%)
- **Integration**: Complete s + h architecture
- **Quality**: Zero lint/type errors, production security (bcrypt 12 rounds, JWT HS256)

### Target State (v2.0.0)

- **Purpose**: Generic authentication API framework
- **Providers**: 9+ authentication providers (JWT, OAuth2, OIDC, SAML, API Key, Basic, Certificate, LDAP, Kerberos)
- **Transports**: HTTP (flext-api), gRPC (flext-grpc), WebSocket
- **Protocols**: REST, SOAP, GraphQL
- **Architecture**: Registry-based with provider discovery
- **CLI**: Removed (pure library)
- **Quality**: 100% backward compatible, all quality gates passing

______________________________________________________________________

## 🏗️ ARCHITECTURAL VISION

### Design Principles

1. **Provider-Centric**: Authentication logic encapsulated in providers
1. **Registry-Based**: Dynamic provider registration and discovery
1. **Transport-Agnostic**: Works over HTTP, gRPC, WebSocket, etc.
1. **Protocol-Agnostic**: Supports REST, SOAP, GraphQL, etc.
1. **FLEXT-Native**: Mandatory use of FLEXT domain libraries
1. **Type-Safe**: Complete type annotations, MyPy strict mode
1. **Railway-Oriented**: r for all operations
1. **Zero-CLI**: Pure library with no CLI dependencies

### Architectural Layers

```
┌─────────────────────────────────────────────────────────────┐
│                   APPLICATION LAYER                          │
│              (User Code / FLEXT Applications)                │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    API FACADE LAYER                          │
│                  FlextAuth (api.py)                          │
│   • Unified authentication interface                         │
│   • Backward compatibility adapter                           │
│   • Provider delegation                                      │
│   • Configuration management                                 │
└───────────────────────┬─────────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
┌───────▼────┐  ┌──────▼──────┐  ┌────▼────────┐
│  Registry  │  │   Config    │  │   Models    │
│  System    │  │  Management │  │   (Domain)  │
└───────┬────┘  └─────────────┘  └─────────────┘
        │
        │ manages
        ▼
┌─────────────────────────────────────────────────────────────┐
│              PROVIDER ECOSYSTEM LAYER                        │
├─────────────────────────────────────────────────────────────┤
│  Base Provider Protocol                                      │
│  ├── authenticate(credentials) -> r[Token]         │
│  ├── validate(token) -> r[bool]                    │
│  ├── refresh(token) -> r[Token]                    │
│  ├── revoke(token) -> r[bool]                      │
│  └── supports() -> set[str]                                  │
├─────────────────────────────────────────────────────────────┤
│  Concrete Providers:                                         │
│  • FlextAuthJwtProvider (JWT tokens)                              │
│  • FlextAuthOAuth2Provider (OAuth 2.0)                            │
│  • FlextAuthOidcProvider (OpenID Connect)                         │
│  • FlextAuthSamlProvider (SAML 2.0)                               │
│  • FlextAuthApiKeyProvider (API keys)                             │
│  • FlextAuthBasicProvider (HTTP Basic)                            │
│  • FlextAuthCertificateProvider (X.509 certs)                     │
│  • FlextAuthLdapProvider (LDAP bind - uses flext-ldap)            │
│  • FlextAuthKerberosProvider (Kerberos/GSSAPI)                    │
└───────────────────────┬─────────────────────────────────────┘
                        │
            ┌───────────┼───────────┐
            │           │           │
┌───────────▼───┐  ┌───▼────────┐  ┌──────▼─────────┐
│  Transport    │  │  Protocol  │  │  Infrastructure│
│  Adapters     │  │  Handlers  │  │  Services      │
├───────────────┤  ├────────────┤  ├────────────────┤
│• HTTP (flext  │  │• REST      │  │• Token Manager │
│  -api)        │  │• SOAP      │  │• Credential Mgr│
│• gRPC (flext  │  │• GraphQL   │  │• Session Store │
│  -grpc)       │  │            │  │• Cache Layer   │
│• WebSocket    │  │            │  │                │
└───────────────┘  └────────────┘  └────────────────┘
```

______________________________________________________________________

## 🔧 CORE COMPONENTS

### 1. FlextAuth Facade (`api.py`)

**Responsibilities**:

- Single entry point for all authentication operations
- Provider delegation through registry
- Backward compatibility with v1.0.0 API
- Configuration management
- Factory methods for common scenarios

**Public API**:

```python
class FlextAuth(s[AuthenticationResponseDict]):
    # Factory methods
    @classmethod
    def quick_start(cls, create_REDACTED_LDAP_BIND_PASSWORD: bool = False) -> FlextAuth

    @classmethod
    def with_jwt(cls, secret_key: str, **kwargs) -> FlextAuth

    @classmethod
    def with_oauth2(cls, client_id: str, client_secret: str, **kwargs) -> FlextAuth

    @classmethod
    def with_provider(cls, provider: FlextAuthBaseProvider, **kwargs) -> FlextAuth

    # Core operations
    def authenticate(
        self,
        credentials: dict,
        provider: str | None = None
    ) -> r[AuthToken]

    def validate_token(
        self,
        token: str,
        provider: str | None = None
    ) -> r[bool]

    # Registry operations
    def list_providers(self) -> t.StringList
    def get_provider(self, name: str) -> r[FlextAuthBaseProvider]
    def get_provider_capabilities(self, name: str) -> r[set[str]]

    # Token/Session management
    def get_token_manager(self) -> TokenManager
    def get_session_manager(self) -> SessionManager
    def get_credential_manager(self) -> CredentialManager
```

### 2. FlextAuthRegistry (`registry.py`)

**Responsibilities**:

- Provider registration and lifecycle
- Provider discovery and lookup
- Capability detection
- Configuration validation per provider

**Interface**:

```python
class FlextAuthRegistry:
    """Registry for managing authentication providers."""

    def register(
        self,
        name: str,
        provider: FlextAuthBaseProvider,
        config: t.ContainerMapping | None = None
    ) -> r[bool]

    def unregister(self, name: str) -> r[bool]

    def get(self, name: str) -> r[FlextAuthBaseProvider]

    def list_providers(self) -> t.StringList

    def discover_providers(self) -> Mapping[str, type[FlextAuthBaseProvider]]

    def get_capabilities(self, name: str) -> r[set[str]]

    def validate_config(
        self,
        name: str,
        config: dict
    ) -> r[bool]
```

### 3. Base Provider Protocol (`providers/base.py`)

**Protocol Definition**:

```python
class FlextAuthBaseProvider(Protocol):
    """Base protocol for all authentication providers."""

    def authenticate(self, credentials: dict) -> r[AuthToken]:
        """Authenticate user with provided credentials."""
        ...

    def validate(self, token: str | AuthToken) -> r[bool]:
        """Validate authentication token."""
        ...

    def refresh(self, token: str | AuthToken) -> r[AuthToken]:
        """Refresh authentication token."""
        ...

    def revoke(self, token: str | AuthToken) -> r[bool]:
        """Revoke authentication token."""
        ...

    def supports(self) -> set[str]:
        """Return set of supported capabilities."""
        ...

    def get_metadata(self) -> t.ContainerMapping:
        """Return provider metadata."""
        ...
```

______________________________________________________________________

## 🔌 PROVIDER ECOSYSTEM

### Provider Categories

#### 1. Token-Based Providers

**JWT Provider** (`providers/jwt.py`)

- **Technology**: PyJWT
- **Capabilities**: `{"token", "refresh", "expiration", "claims"}`
- **Configuration**: secret_key, algorithm, expiration
- **Status**: ✅ Extracted from v1.0.0 (Phase 1)

**API Key Provider** (`providers/apikey.py`)

- **Technology**: Custom + cryptography
- **Capabilities**: `{"token", "rotation", "scopes"}`
- **Configuration**: key_length, hash_algorithm, rotation_policy
- **Status**: 🔄 Implementation (Phase 2)

#### 2. OAuth/OIDC Providers

**OAuth2 Provider** (`providers/oauth2.py`)

- **Technology**: authlib
- **Capabilities**: `{"oauth2", "authorization_code", "client_credentials", "password_grant", "refresh"}`
- **Configuration**: client_id, client_secret, authorization_url, token_url
- **Status**: 🔄 Implementation (Phase 2)

**OIDC Provider** (`providers/oidc.py`)

- **Technology**: authlib (extends OAuth2)
- **Capabilities**: `{"oidc", "id_token", "userinfo", "discovery"}`
- **Configuration**: extends OAuth2 + discovery_url
- **Status**: 🔄 Implementation (Phase 2)

#### 3. Enterprise SSO Providers

**SAML Provider** (`providers/saml.py`)

- **Technology**: python3-saml
- **Capabilities**: `{"saml", "sso", "slo", "metadata", "sp_initiated", "idp_initiated"}`
- **Configuration**: idp_metadata, sp_entity_id, assertion_consumer_service
- **Status**: 🔄 Implementation (Phase 3)

**LDAP Provider** (`providers/ldap.py`)

- **Technology**: **flext-ldap** (MANDATORY)
- **Capabilities**: `{"ldap", "bind", "attribute_mapping", "group_sync"}`
- **Configuration**: ldap_uri, base_dn, bind_dn, bind_password
- **Status**: 🔄 Implementation (Phase 3)
- **⚠️ CRITICAL**: MUST use flext-ldap, NOT direct ldap3

#### 4. Credential-Based Providers

**Basic Auth Provider** (`providers/basic.py`)

- **Technology**: bcrypt (existing utilities)
- **Capabilities**: `{"basic_auth", "password_hash"}`
- **Configuration**: hash_rounds, pepper
- **Status**: 🔄 Implementation (Phase 2)

**Certificate Provider** (`providers/certificate.py`)

- **Technology**: cryptography + pyOpenSSL
- **Capabilities**: `{"certificate", "x509", "mtls", "ocsp", "crl"}`
- **Configuration**: ca_cert, crl_url, ocsp_url
- **Status**: 🔄 Implementation (Phase 3)

#### 5. Kerberos Provider (Stub)

**Kerberos Provider** (`providers/kerberos.py`)

- **Technology**: gssapi
- **Capabilities**: `{"kerberos", "gssapi", "spnego"}`
- **Configuration**: realm, kdc, keytab
- **Status**: 📝 Stub (Phase 3 - extensible but not fully implemented)

### Provider Implementation Pattern

```python
from __future__ import annotations

from collections.abc import Mapping, Sequence
from flext_core import FlextBus

from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u

from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u
from flext_auth import FlextAuthBaseProvider
from flext_auth import FlextAuthModels


class FlextAuthExampleProvider(FlextAuthBaseProvider):
    """Example authentication provider implementation."""

    def __init__(self, config: dict) -> None:
        self._config = config
        self.logger = u.fetch_logger(__name__)

    def authenticate(self, credentials: dict) -> r[FlextAuthModels.AuthToken]:
        """Authenticate using provider-specific logic."""
        # Validation
        if not credentials.get("username"):
            return r[FlextAuthModels.AuthToken].fail("Username required")

        # Provider-specific authentication
        try:
            # Actual authentication logic
            token = self._generate_token(credentials)
            return r[FlextAuthModels.AuthToken].ok(token)
        except Exception as e:
            return r[FlextAuthModels.AuthToken].fail(f"Authentication failed: {e}")

    def validate(self, token: str | FlextAuthModels.AuthToken) -> r[bool]:
        """Validate token using provider-specific logic."""
        # Implementation
        ...

    def refresh(
        self, token: str | FlextAuthModels.AuthToken
    ) -> r[FlextAuthModels.AuthToken]:
        """Refresh token if provider supports it."""
        if "refresh" not in self.supports():
            return r[FlextAuthModels.AuthToken].fail(
                "Refresh not supported by this provider"
            )
        # Implementation
        ...

    def revoke(self, token: str | FlextAuthModels.AuthToken) -> r[bool]:
        """Revoke token if provider supports it."""
        # Implementation
        ...

    def supports(self) -> set[str]:
        """Return provider capabilities."""
        return {"token", "validate", "refresh"}

    def get_metadata(self) -> t.ContainerMapping:
        """Return provider metadata."""
        return {
            "name": "example",
            "version": "1.0.0",
            "capabilities": list(self.supports()),
            "config_schema": {...},
        }
```

______________________________________________________________________

## 🚀 TRANSPORT LAYER

### Transport Abstraction (`transports/base.py`)

```python
class BaseTransportAdapter(Protocol):
    """Base protocol for transport adapters."""

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: t.ContainerMapping | None = None,
    ) -> r[t.Dict]:
        """Send authentication request over transport."""
        ...

    def send_validate_request(
        self,
        endpoint: str,
        token: str,
        metadata: t.ContainerMapping | None = None,
    ) -> r[t.Dict]:
        """Send token validation request over transport."""
        ...

    def get_transport_metadata(self) -> t.ContainerMapping:
        """Return transport metadata."""
        ...
```

### HTTP Transport (`transports/http.py`)

**⚠️ MANDATORY**: Uses **flext-api** (NOT direct httpx/requests)

```python
from flext_api import FlextApi
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u


class FlextWebTransportAdapter(BaseTransportAdapter):
    """HTTP transport adapter using flext-api."""

    def __init__(self, config: t.ContainerMapping | None = None) -> None:
        self._api = FlextApi(config=config)  # MANDATORY: Use flext-api
        self.logger = u.fetch_logger(__name__)

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: t.ContainerMapping | None = None,
    ) -> r[t.Dict]:
        """Send authentication request via HTTP using flext-api."""
        result = self._api.post(url=endpoint, json=credentials, headers=metadata)

        if result.is_failure:
            return r[t.Dict].fail(f"HTTP transport failed: {result.error}")

        return r[t.Dict].ok(result.unwrap())
```

### gRPC Transport (`transports/grpc.py`)

**⚠️ MANDATORY**: Uses **flext-grpc** (NOT direct grpc/grpcio)

```python
from flext_grpc import FlextGrpc
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u


class GrpcTransportAdapter(BaseTransportAdapter):
    """gRPC transport adapter using flext-grpc."""

    def __init__(self, config: t.ContainerMapping | None = None) -> None:
        self._grpc = FlextGrpc(config=config)  # MANDATORY: Use flext-grpc
        self.logger = u.fetch_logger(__name__)

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: t.ContainerMapping | None = None,
    ) -> r[t.Dict]:
        """Send authentication request via gRPC using flext-grpc."""
        result = self._grpc.call(
            service="AuthService",
            method="Authenticate",
            request=credentials,
            metadata=metadata,
        )

        if result.is_failure:
            return r[t.Dict].fail(f"gRPC transport failed: {result.error}")

        return r[t.Dict].ok(result.unwrap())
```

### WebSocket Transport (`transports/websocket.py`)

```python
class WebSocketTransportAdapter(BaseTransportAdapter):
    """WebSocket transport adapter for real-time authentication."""

    def __init__(self, config: t.ContainerMapping | None = None) -> None:
        self._config = config
        self.logger = u.fetch_logger(__name__)

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: t.ContainerMapping | None = None,
    ) -> r[t.Dict]:
        """Send authentication request via WebSocket."""
        # Implementation using websockets library
        ...
```

______________________________________________________________________

## 📡 PROTOCOL HANDLERS

### Protocol Handler Base (`protocol_handlers/base.py`)

```python
class BaseProtocolHandler(Protocol):
    """Base protocol for protocol-specific handlers."""

    def format_auth_request(
        self, credentials: dict, metadata: t.ContainerMapping | None = None
    ) -> r[bytes | str]:
        """Format authentication request for protocol."""
        ...

    def parse_auth_response(self, response: bytes | str) -> r[t.Dict]:
        """Parse authentication response from protocol."""
        ...
```

### REST Protocol Handler (`protocol_handlers/rest.py`)

```python
class RestProtocolHandler(BaseProtocolHandler):
    """REST/JSON protocol handler (default)."""

    def format_auth_request(
        self, credentials: dict, metadata: t.ContainerMapping | None = None
    ) -> r[str]:
        """Format as JSON REST request."""
        import json

        try:
            formatted = json.dumps(credentials)
            return r[str].ok(formatted)
        except Exception as e:
            return r[str].fail(f"JSON formatting failed: {e}")

    def parse_auth_response(self, response: str) -> r[t.Dict]:
        """Parse JSON REST response."""
        import json

        try:
            parsed = json.loads(response)
            return r[t.Dict].ok(parsed)
        except Exception as e:
            return r[t.Dict].fail(f"JSON parsing failed: {e}")
```

### SOAP Protocol Handler (`protocol_handlers/soap.py`)

```python
class SoapProtocolHandler(BaseProtocolHandler):
    """SOAP/XML protocol handler (stub)."""

    def format_auth_request(
        self, credentials: dict, metadata: t.ContainerMapping | None = None
    ) -> r[str]:
        """Format as SOAP XML request."""
        # Implementation for SOAP envelope creation
        ...

    def parse_auth_response(self, response: str) -> r[t.Dict]:
        """Parse SOAP XML response."""
        # Implementation for SOAP envelope parsing
        ...
```

______________________________________________________________________

## 🎫 TOKEN MANAGEMENT

### Token Manager (`tokens/manager.py`)

**Responsibilities**:

- Unified token interface across providers
- Token lifecycle management
- Token caching
- Automatic token refresh
- Token retry logic

**Interface**:

```python
class TokenManager:
    """Unified token management across providers."""

    def __init__(
        self,
        provider: FlextAuthBaseProvider,
        cache: TokenCache | None = None,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self._provider = provider
        self._cache = cache or TokenCache()
        self._retry = retry_policy or RetryPolicy()
        self.logger = u.fetch_logger(__name__)

    def get_token(self, credentials: dict, use_cache: bool = True) -> r[AuthToken]:
        """Get token with caching."""
        if use_cache:
            cached = self._cache.get(credentials)
            if cached:
                return r[AuthToken].ok(cached)

        result = self._provider.authenticate(credentials)

        if result.is_success and use_cache:
            self._cache.set(credentials, result.unwrap())

        return result

    def get_with_retry(
        self,
        credentials: dict,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        retry_on: Sequence[type[Exception]] | None = None,
    ) -> r[AuthToken]:
        """Get token with automatic retry on failure."""
        return self._retry.execute(
            func=self._provider.authenticate,
            credentials=credentials,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            retry_on=retry_on or [],
        )

    def refresh_token(self, token: AuthToken) -> r[AuthToken]:
        """Refresh token if provider supports it."""
        if "refresh" not in self._provider.supports():
            return r[AuthToken].fail("Provider does not support token refresh")

        return self._provider.refresh(token)

    def validate_token(self, token: AuthToken) -> r[bool]:
        """Validate token."""
        return self._provider.validate(token)
```

### Token Retry Logic (`tokens/retry.py`)

```python
class RetryPolicy:
    """Token retry policy with exponential backoff."""

    def execute(
        self,
        func: Callable,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        retry_on: Sequence[type[Exception]] | None = None,
        **kwargs,
    ) -> r[T]:
        """Execute function with retry logic."""
        retry_on = retry_on or [ConnectionError, TimeoutError]

        for attempt in range(max_retries + 1):
            try:
                result = func(**kwargs)
                return result
            except Exception as e:
                if attempt == max_retries:
                    return r[T].fail(f"Max retries ({max_retries}) exceeded: {e}")

                if not any(isinstance(e, exc) for exc in retry_on):
                    return r[T].fail(f"Non-retryable error: {e}")

                wait_time = backoff_factor**attempt
                sleep(wait_time)
```

### Token Cache (`tokens/cache.py`)

```python
class TokenCache:
    """Token caching with multiple backend support."""

    def __init__(
        self,
        backend: str = "memory",  # "memory", "redis", "memcached"
        config: t.ContainerMapping | None = None,
    ) -> None:
        self._backend = self._create_backend(backend, config)
        self.logger = u.fetch_logger(__name__)

    def get(self, key: dict) -> AuthToken | None:
        """Get token from cache."""
        cache_key = self._hash_credentials(key)
        return self._backend.get(cache_key)

    def set(self, key: dict, token: AuthToken, ttl: int | None = None) -> None:
        """Set token in cache."""
        cache_key = self._hash_credentials(key)
        self._backend.set(cache_key, token, ttl=ttl)

    def delete(self, key: dict) -> None:
        """Delete token from cache."""
        cache_key = self._hash_credentials(key)
        self._backend.delete(cache_key)
```

______________________________________________________________________

## 🔐 SECURITY ARCHITECTURE

### Security Principles

1. **Defense in Depth**: Multiple layers of security validation
1. **Least Privilege**: Minimum required permissions
1. **Fail Secure**: Errors result in denial, not bypass
1. **Audit Logging**: All authentication events logged
1. **Secure Storage**: Encrypted credentials at rest
1. **Token Expiration**: Automatic token lifecycle management

### Credential Management (`credentials/manager.py`)

```python
class CredentialManager:
    """Secure credential management with encryption."""

    def __init__(self, storage: CredentialStore, encryption_key: bytes) -> None:
        self._storage = storage
        self._cipher = self._init_cipher(encryption_key)
        self.logger = u.fetch_logger(__name__)

    def store_credential(
        self,
        identifier: str,
        credential: dict,
        metadata: t.ContainerMapping | None = None,
    ) -> r[bool]:
        """Store credential with encryption."""
        encrypted = self._cipher.encrypt(credential)
        return self._storage.save(identifier, encrypted, metadata)

    def retrieve_credential(self, identifier: str) -> r[t.Dict]:
        """Retrieve and decrypt credential."""
        result = self._storage.load(identifier)
        if result.is_failure:
            return r[t.Dict].fail(result.error)

        encrypted = result.unwrap()
        decrypted = self._cipher.decrypt(encrypted)
        return r[t.Dict].ok(decrypted)

    def rotate_credential(self, identifier: str, new_credential: dict) -> r[bool]:
        """Rotate credential with old credential backup."""
        # Archive old credential
        old_result = self.retrieve_credential(identifier)
        if old_result.is_success:
            self._storage.archive(identifier, old_result.unwrap())

        # Store new credential
        return self.store_credential(identifier, new_credential)
```

### Security Validations

```python
class SecurityValidator:
    """Security validation for authentication operations."""

    @staticmethod
    def validate_token_expiration(token: AuthToken) -> r[bool]:
        """Validate token has not expired."""
        if token.expires_at < datetime.now(UTC):
            return r[bool].fail("Token expired")
        return r[bool].ok(True)

    @staticmethod
    def validate_token_signature(token: str, secret: str) -> r[bool]:
        """Validate token signature."""
        # Implementation
        ...

    @staticmethod
    def validate_certificate(cert: bytes) -> r[bool]:
        """Validate X.509 certificate."""
        # Implementation
        ...
```

______________________________________________________________________

## 🔗 FLEXT INTEGRATION

### Mandatory FLEXT Domain Library Usage

**CRITICAL**: flext-auth MUST use FLEXT domain libraries for all domain operations.

#### Integration Matrix

| Domain               | FLEXT Library       | Status    | Usage in flext-auth                      |
| -------------------- | ------------------- | --------- | ---------------------------------------- |
| HTTP Operations      | **flext-api**       | MANDATORY | HTTP transport adapter                   |
| gRPC Operations      | **flext-grpc**      | MANDATORY | gRPC transport adapter                   |
| LDAP Authentication  | **flext-ldap**      | MANDATORY | LDAP provider                            |
| Database (if needed) | **flext-db-oracle** | MANDATORY | User/session persistence                 |
| Foundation Patterns  | **flext-core**      | MANDATORY | r, s, FlextRegistry |

#### FORBIDDEN Direct Imports

```python
# ❌ ABSOLUTELY FORBIDDEN in flext-auth
import httpx  # Use flext-api instead
import requests  # Use flext-api instead
import grpc  # Use flext-grpc instead
import grpcio  # Use flext-grpc instead
import ldap3  # Use flext-ldap instead
```

#### Correct Integration Pattern

```python
# ✅ CORRECT - Using FLEXT domain libraries
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u
from flext_api import FlextApi  # For HTTP transport
from flext_grpc import FlextGrpc  # For gRPC transport
from flext_ldap import ldap  # For LDAP provider


class FlextWebTransportAdapter:
    def __init__(self) -> None:
        self._api = FlextApi()  # MANDATORY: Use flext-api

    def send_request(self, url: str, data: dict) -> r[t.Dict]:
        return self._api.post(url=url, json=data)


class FlextAuthLdapProvider:
    def __init__(self, config: dict) -> None:
        self._ldap = ldap(config)  # MANDATORY: Use flext-ldap

    def authenticate(self, credentials: dict) -> r[AuthToken]:
        return self._ldap.bind(
            username=credentials["username"], password=credentials["password"]
        )
```

### s Integration

All providers and managers extend s for consistency:

```python
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import d
from flext_core import FlextDispatcher
from flext_core import e
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import u
from flext_core import s
from flext_core import t
from flext_core import u


class FlextAuthJwtProvider(s[AuthToken]):
    """JWT provider extending s."""

    def __init__(self, config: dict) -> None:
        super().__init__()
        self._config = config
        self.logger = u.fetch_logger(__name__)
```

______________________________________________________________________

## 📘 API DESIGN

### Public API Patterns

#### Pattern 1: Simple JWT (Backward Compatible)

```python
from flext_auth import FlextAuth

# v1.0.0 API (deprecated but works)
auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

# v2.0.0 API (recommended)
auth = FlextAuth.with_jwt(secret_key="your-secret")

result = auth.authenticate_user("username", "password")
```

#### Pattern 2: Multi-Provider

```python
from flext_auth import FlextAuth, FlextAuthRegistry
from flext_auth import (
    FlextAuthJwtProvider,
    FlextAuthOAuth2Provider,
    FlextAuthSamlProvider,
)

# Create registry
registry = FlextAuthRegistry()

# Register providers
registry.register("jwt", FlextAuthJwtProvider(jwt_config))
registry.register("oauth2", FlextAuthOAuth2Provider(oauth_config))
registry.register("saml", FlextAuthSamlProvider(saml_config))

# Create auth service
auth = FlextAuth(registry=registry)

# Authenticate with specific provider
jwt_result = auth.authenticate(
    credentials={"username": "user", "password": "pass"}, provider="jwt"
)

oauth_result = auth.authenticate(
    credentials={"authorization_code": "code"}, provider="oauth2"
)

# List available providers
providers = auth.list_providers()  # ["jwt", "oauth2", "saml"]
```

#### Pattern 3: Custom Transport

```python
from flext_auth import FlextAuth
from flext_auth import FlextAuthOAuth2Provider
from flext_auth import GrpcTransportAdapter

# Create provider with gRPC transport
provider = FlextAuthOAuth2Provider(
    config=oauth_config, transport=GrpcTransportAdapter()
)

# Create auth service
auth = FlextAuth.with_provider(provider)

result = auth.authenticate(credentials)
```

#### Pattern 4: Token Retry

```python
from flext_auth import FlextAuth

auth = FlextAuth.with_oauth2(client_id="client", client_secret="secret")

# Get token manager
token_mgr = auth.get_token_manager()

# Get token with retry
token = token_mgr.get_with_retry(
    credentials={"username": "user", "password": "pass"},
    max_retries=3,
    backoff_factor=2.0,
)
```

______________________________________________________________________

## 🏗️ IMPLEMENTATION PHASES

### Phase 1: Foundation & Registry (Week 1) ✅ COMPLETE

**Deliverables**:

- ✅ Create `docs/ARCHITECTURE.md` (this document)
- ✅ Implement FlextAuthRegistry in `registry.py` (445 lines, ~85% coverage)
- ✅ Define base provider protocol in `providers/base.py` (226 lines)
- ✅ Extract JWT logic to `providers/jwt.py` (474 lines, production-ready)
- ✅ Remove ALL CLI code (source, tests, docs)
- ✅ Update `api.py` with registry integration (310 lines)
- ✅ Update `__init__.py` exports (66 exported classes/functions)
- ⚠️ Validate: 228/558 tests passing (significant test failures need resolution)
- ⚠️ Quality gates: Mixed results (linting ✅, type safety ✅, tests ⚠️)

**Success Criteria**: Registry operational ✅, JWT provider extracted ✅, zero CLI code ✅, comprehensive provider architecture ✅
**Actual Status**: Foundation complete but test suite needs stabilization

### Phase 2: Core Providers (Week 2) ✅ COMPLETE

**Deliverables**:

- ✅ Implement FlextAuthOAuth2Provider (728 lines, authlib integration)
- ✅ Implement FlextAuthOidcProvider (418 lines, extends OAuth2)
- ✅ Implement FlextAuthApiKeyProvider (448 lines, production-ready)
- ✅ Implement FlextAuthBasicProvider (513 lines, bcrypt integration)
- ✅ Provider factory pattern (via registry system)
- ⚠️ Provider tests (~75% average coverage, individual provider issues)
- ⚠️ Quality gates: Mixed (linting ✅, type safety ✅, integration tests ⚠️)

**Success Criteria**: 4 new providers operational ✅, comprehensive architecture ✅, documentation framework ✅
**Actual Status**: All core providers implemented but testing and integration need stabilization

### Phase 3: Advanced Providers (Week 3) ✅ MOSTLY COMPLETE

**Deliverables**:

- ✅ Implement FlextAuthSamlProvider (408 lines, python3-saml integration)
- ✅ Implement FlextAuthLdapProvider (331 lines, flext-ldap integration)
- ✅ Implement FlextAuthCertificateProvider (639 lines, cryptography integration)
- ⚠️ Kerberos provider stub (412 lines, basic structure)
- ⚠️ Security validation per provider (partial implementation)
- ⚠️ Quality gates: Mixed (linting ✅, type safety ✅, provider tests ⚠️)

**Success Criteria**: 3 advanced providers operational ✅, LDAP using flext-ldap ✅, comprehensive provider ecosystem ✅
**Actual Status**: 4/4 advanced providers implemented but with testing and integration issues

### Phase 4: Transport & Protocol (Week 4) ⚠️ PARTIALLY COMPLETE

**Deliverables**:

- ✅ Transport base protocol (FlextWebTransportAdapter implemented)
- ✅ FlextWebTransportAdapter (integrated with flext-api MANDATORY)
- ⚠️ GrpcTransportAdapter (partial implementation, flext-grpc MANDATORY)
- ❌ WebSocket adapter (not implemented)
- ❌ REST/SOAP/GraphQL protocol handlers (not implemented)
- ⚠️ Provider-transport integration (basic HTTP integration only)
- ⚠️ Quality gates: Mixed (transport tests failing)

**Success Criteria**: Transport abstraction complete ⚠️, HTTP/gRPC using FLEXT libraries ⚠️ (HTTP ✅, gRPC partial)
**Actual Status**: Basic HTTP transport implemented, gRPC and protocols pending

### Phase 5: Token & Credential Management (Week 5)

**Deliverables**:

- [ ] Token manager with retry logic
- [ ] Token caching (Redis/Memcached)
- [ ] Credential manager with encryption
- [ ] Session manager refactoring
- [ ] Quality gates: make validate passing

**Success Criteria**: Advanced token/credential management operational

### Phase 6: Documentation (Week 6)

**Deliverables**:

- [ ] `docs/MIGRATION.md` (v1 to v2 guide)
- [ ] Provider documentation (`docs/providers/*.md`)
- [ ] Transport documentation (`docs/transports/*.md`)
- [ ] Update `docs/api-reference.md`
- [ ] Update `README.md` (remove CLI, add multi-provider)
- [ ] Code examples

**Success Criteria**: Complete documentation suite, migration guide published

### Phase 7: QA & Release (Week 7)

**Deliverables**:

- [ ] 100% test coverage for all providers
- [ ] Security audit for all providers
- [ ] Performance benchmarks
- [ ] API stability verification
- [ ] Release candidate preparation

**Success Criteria**: All quality gates passing, security audit passed, ready for release

______________________________________________________________________

## ✅ QUALITY STANDARDS

### Quality Gates (MANDATORY after each phase)

```bash
make validate          # Complete pipeline
make lint
make type-check       # MyPy/PyRight: ZERO errors in src/
make security         # Bandit: ZERO critical issues
make test             # Tests: 100% pass rate
```

### Coverage Requirements

- **Providers**: 95%+ test coverage per provider
- **Core Components**: 100% coverage (registry, base protocols)
- **Integration Tests**: All provider combinations tested
- **Security Tests**: Vulnerability and penetration testing

### Performance Standards

- **Overhead**: \<5% performance overhead vs v1.0.0
- **Token Operations**: \<10ms for token generation/validation
- **Provider Switching**: \<1ms overhead for registry lookup
- **Memory**: No memory leaks, efficient caching

______________________________________________________________________

## 📝 APPENDIX

### Technology Stack Summary

| Category        | Libraries                                     | Status         |
| --------------- | --------------------------------------------- | -------------- |
| OAuth2/OIDC     | authlib>=1.3.0                                | Phase 2        |
| SAML            | python3-saml>=1.16.0, xmlsec>=1.3.0           | Phase 3        |
| Kerberos        | gssapi>=1.8.0                                 | Phase 3 (stub) |
| Caching         | memcache>=0.8.0                               | Phase 5        |
| WebSocket       | websockets>=14.0                              | Phase 4        |
| GraphQL         | graphql-core>=3.2.0                           | Phase 4 (stub) |
| FLEXT Libraries | flext-core, flext-api, flext-grpc, flext-ldap | All phases     |

### Backward Compatibility Timeline

- **v2.0.0**: New architecture, v1 API deprecated with warnings
- **v2.1.0** (+3 months): Prominent deprecation warnings
- **v2.5.0** (+6 months): Final warnings
- **v3.0.0** (+12 months): Remove v1 API completely

______________________________________________________________________

**Document Status**: ✅ Multi-Provider Architecture - Implementation Complete (Phases 1-3), Transport Layer In Progress (Phase 4)
**Next Review**: After test suite stabilization and Phase 4 completion
**Maintained By**: FLEXT Auth Team

______________________________________________________________________

_This architecture document is the authoritative reference for the flext-auth v2.0.0 transformation. All implementation must follow these patterns and principles._

## Related Documentation

**Within Project**:

- Getting Started - Installation and basic usage
- API Reference - Complete API documentation
- Configuration - Settings management
- Integration - FLEXT ecosystem patterns

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/architecture/overview.md) - Clean architecture and CQRS patterns
- [flext-core Service Patterns](https://github.com/organization/flext/tree/main/flext-core/docs/guides/service-patterns.md) - Service patterns and dependency injection
- [flext-cli Authentication](https://github.com/organization/flext/tree/main/flext-cli/docs/api-reference.md) - CLI authentication patterns

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
