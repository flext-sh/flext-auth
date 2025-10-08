# FLEXT-AUTH ARCHITECTURE v2.0.0

## Generic Authentication API Framework

**Version**: 2.0.0-dev
**Status**: In Development
**Last Updated**: 2025-10-01
**Parent**: [FLEXT Workspace](../../CLAUDE.md)

---

## 📋 TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Architectural Vision](#architectural-vision)
3. [Core Components](#core-components)
4. [Provider Ecosystem](#provider-ecosystem)
5. [Transport Layer](#transport-layer)
6. [Protocol Handlers](#protocol-handlers)
7. [Token Management](#token-management)
8. [Session Management](#session-management)
9. [Security Architecture](#security-architecture)
10. [FLEXT Integration](#flext-integration)
11. [API Design](#api-design)
12. [Implementation Phases](#implementation-phases)
13. [Quality Standards](#quality-standards)

---

## 🎯 EXECUTIVE SUMMARY

### Mission

Transform flext-auth from a specific JWT/bcrypt authentication implementation into a **generic, extensible authentication API framework** that supports multiple authentication technologies, protocols, and transports while maintaining FLEXT ecosystem patterns and production quality.

### Current State (v1.0.0)

- **Purpose**: JWT/bcrypt authentication with session management
- **Status**: Production-ready, 71/72 tests passing (99%)
- **Integration**: Complete FlextService + FlextHandlers architecture
- **Quality**: Zero lint/type errors, production security (bcrypt 12 rounds, JWT HS256)

### Target State (v2.0.0)

- **Purpose**: Generic authentication API framework
- **Providers**: 9+ authentication providers (JWT, OAuth2, OIDC, SAML, API Key, Basic, Certificate, LDAP, Kerberos)
- **Transports**: HTTP (flext-api), gRPC (flext-grpc), WebSocket
- **Protocols**: REST, SOAP, GraphQL
- **Architecture**: Registry-based with provider discovery
- **CLI**: Removed (pure library)
- **Quality**: 100% backward compatible, all quality gates passing

---

## 🏗️ ARCHITECTURAL VISION

### Design Principles

1. **Provider-Centric**: Authentication logic encapsulated in providers
2. **Registry-Based**: Dynamic provider registration and discovery
3. **Transport-Agnostic**: Works over HTTP, gRPC, WebSocket, etc.
4. **Protocol-Agnostic**: Supports REST, SOAP, GraphQL, etc.
5. **FLEXT-Native**: Mandatory use of FLEXT domain libraries
6. **Type-Safe**: Complete type annotations, MyPy strict mode
7. **Railway-Oriented**: FlextResult for all operations
8. **Zero-CLI**: Pure library with no CLI dependencies

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
│  ├── authenticate(credentials) -> FlextResult[Token]         │
│  ├── validate(token) -> FlextResult[bool]                    │
│  ├── refresh(token) -> FlextResult[Token]                    │
│  ├── revoke(token) -> FlextResult[None]                      │
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

---

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
class FlextAuth(FlextService[AuthenticationResponseDict]):
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
    ) -> FlextResult[AuthToken]

    def validate_token(
        self,
        token: str,
        provider: str | None = None
    ) -> FlextResult[bool]

    # Registry operations
    def list_providers(self) -> FlextTypes.StringList
    def get_provider(self, name: str) -> FlextResult[FlextAuthBaseProvider]
    def get_provider_capabilities(self, name: str) -> FlextResult[set[str]]

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
        config: dict | None = None
    ) -> FlextResult[None]

    def unregister(self, name: str) -> FlextResult[None]

    def get(self, name: str) -> FlextResult[FlextAuthBaseProvider]

    def list_providers(self) -> FlextTypes.StringList

    def discover_providers(self) -> dict[str, type[FlextAuthBaseProvider]]

    def get_capabilities(self, name: str) -> FlextResult[set[str]]

    def validate_config(
        self,
        name: str,
        config: dict
    ) -> FlextResult[None]
```

### 3. Base Provider Protocol (`providers/base.py`)

**Protocol Definition**:

```python
class FlextAuthBaseProvider(Protocol):
    """Base protocol for all authentication providers."""

    def authenticate(
        self,
        credentials: dict
    ) -> FlextResult[AuthToken]:
        """Authenticate user with provided credentials."""
        ...

    def validate(
        self,
        token: str | AuthToken
    ) -> FlextResult[bool]:
        """Validate authentication token."""
        ...

    def refresh(
        self,
        token: str | AuthToken
    ) -> FlextResult[AuthToken]:
        """Refresh authentication token."""
        ...

    def revoke(
        self,
        token: str | AuthToken
    ) -> FlextResult[None]:
        """Revoke authentication token."""
        ...

    def supports(self) -> set[str]:
        """Return set of supported capabilities."""
        ...

    def get_metadata(self) -> dict:
        """Return provider metadata."""
        ...
```

---

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

from flext_core import FlextResult, FlextLogger
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.models import FlextAuthModels

class FlextAuthExampleProvider(FlextAuthBaseProvider):
    """Example authentication provider implementation."""

    def __init__(self, config: dict) -> None:
        self._config = config
        self.logger = FlextLogger(__name__)

    def authenticate(
        self,
        credentials: dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate using provider-specific logic."""
        # Validation
        if not credentials.get("username"):
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Username required"
            )

        # Provider-specific authentication
        try:
            # Actual authentication logic
            token = self._generate_token(credentials)
            return FlextResult[FlextAuthModels.AuthToken].ok(token)
        except Exception as e:
            return FlextResult[FlextAuthModels.AuthToken].fail(
                f"Authentication failed: {e}"
            )

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken
    ) -> FlextResult[bool]:
        """Validate token using provider-specific logic."""
        # Implementation
        ...

    def refresh(
        self,
        token: str | FlextAuthModels.AuthToken
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Refresh token if provider supports it."""
        if "refresh" not in self.supports():
            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Refresh not supported by this provider"
            )
        # Implementation
        ...

    def revoke(
        self,
        token: str | FlextAuthModels.AuthToken
    ) -> FlextResult[None]:
        """Revoke token if provider supports it."""
        # Implementation
        ...

    def supports(self) -> set[str]:
        """Return provider capabilities."""
        return {"token", "validate", "refresh"}

    def get_metadata(self) -> dict:
        """Return provider metadata."""
        return {
            "name": "example",
            "version": "1.0.0",
            "capabilities": list(self.supports()),
            "config_schema": {...}
        }
```

---

## 🚀 TRANSPORT LAYER

### Transport Abstraction (`transports/base.py`)

```python
class BaseTransportAdapter(Protocol):
    """Base protocol for transport adapters."""

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: dict | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Send authentication request over transport."""
        ...

    def send_validate_request(
        self,
        endpoint: str,
        token: str,
        metadata: dict | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Send token validation request over transport."""
        ...

    def get_transport_metadata(self) -> dict:
        """Return transport metadata."""
        ...
```

### HTTP Transport (`transports/http.py`)

**⚠️ MANDATORY**: Uses **flext-api** (NOT direct httpx/requests)

```python
from flext_api import FlextApi
from flext_core import FlextResult

class HttpTransportAdapter(BaseTransportAdapter):
    """HTTP transport adapter using flext-api."""

    def __init__(self, config: dict | None = None) -> None:
        self._api = FlextApi(config=config)  # MANDATORY: Use flext-api
        self.logger = FlextLogger(__name__)

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: dict | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Send authentication request via HTTP using flext-api."""
        result = self._api.post(
            url=endpoint,
            json=credentials,
            headers=metadata
        )

        if result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(
                f"HTTP transport failed: {result.error}"
            )

        return FlextResult[FlextTypes.Dict].ok(result.unwrap())
```

### gRPC Transport (`transports/grpc.py`)

**⚠️ MANDATORY**: Uses **flext-grpc** (NOT direct grpc/grpcio)

```python
from flext_grpc import FlextGrpc
from flext_core import FlextResult

class GrpcTransportAdapter(BaseTransportAdapter):
    """gRPC transport adapter using flext-grpc."""

    def __init__(self, config: dict | None = None) -> None:
        self._grpc = FlextGrpc(config=config)  # MANDATORY: Use flext-grpc
        self.logger = FlextLogger(__name__)

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: dict | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Send authentication request via gRPC using flext-grpc."""
        result = self._grpc.call(
            service="AuthService",
            method="Authenticate",
            request=credentials,
            metadata=metadata
        )

        if result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(
                f"gRPC transport failed: {result.error}"
            )

        return FlextResult[FlextTypes.Dict].ok(result.unwrap())
```

### WebSocket Transport (`transports/websocket.py`)

```python
class WebSocketTransportAdapter(BaseTransportAdapter):
    """WebSocket transport adapter for real-time authentication."""

    def __init__(self, config: dict | None = None) -> None:
        self._config = config
        self.logger = FlextLogger(__name__)

    def send_auth_request(
        self,
        endpoint: str,
        credentials: dict,
        metadata: dict | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Send authentication request via WebSocket."""
        # Implementation using websockets library
        ...
```

---

## 📡 PROTOCOL HANDLERS

### Protocol Handler Base (`protocol_handlers/base.py`)

```python
class BaseProtocolHandler(Protocol):
    """Base protocol for protocol-specific handlers."""

    def format_auth_request(
        self,
        credentials: dict,
        metadata: dict | None = None
    ) -> FlextResult[bytes | str]:
        """Format authentication request for protocol."""
        ...

    def parse_auth_response(
        self,
        response: bytes | str
    ) -> FlextResult[FlextTypes.Dict]:
        """Parse authentication response from protocol."""
        ...
```

### REST Protocol Handler (`protocol_handlers/rest.py`)

```python
class RestProtocolHandler(BaseProtocolHandler):
    """REST/JSON protocol handler (default)."""

    def format_auth_request(
        self,
        credentials: dict,
        metadata: dict | None = None
    ) -> FlextResult[str]:
        """Format as JSON REST request."""
        import json
        try:
            formatted = json.dumps(credentials)
            return FlextResult[str].ok(formatted)
        except Exception as e:
            return FlextResult[str].fail(f"JSON formatting failed: {e}")

    def parse_auth_response(
        self,
        response: str
    ) -> FlextResult[FlextTypes.Dict]:
        """Parse JSON REST response."""
        import json
        try:
            parsed = json.loads(response)
            return FlextResult[FlextTypes.Dict].ok(parsed)
        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"JSON parsing failed: {e}")
```

### SOAP Protocol Handler (`protocol_handlers/soap.py`)

```python
class SoapProtocolHandler(BaseProtocolHandler):
    """SOAP/XML protocol handler (stub)."""

    def format_auth_request(
        self,
        credentials: dict,
        metadata: dict | None = None
    ) -> FlextResult[str]:
        """Format as SOAP XML request."""
        # Implementation for SOAP envelope creation
        ...

    def parse_auth_response(
        self,
        response: str
    ) -> FlextResult[FlextTypes.Dict]:
        """Parse SOAP XML response."""
        # Implementation for SOAP envelope parsing
        ...
```

---

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
        retry_policy: RetryPolicy | None = None
    ) -> None:
        self._provider = provider
        self._cache = cache or TokenCache()
        self._retry = retry_policy or RetryPolicy()
        self.logger = FlextLogger(__name__)

    def get_token(
        self,
        credentials: dict,
        use_cache: bool = True
    ) -> FlextResult[AuthToken]:
        """Get token with caching."""
        if use_cache:
            cached = self._cache.get(credentials)
            if cached:
                return FlextResult[AuthToken].ok(cached)

        result = self._provider.authenticate(credentials)

        if result.is_success and use_cache:
            self._cache.set(credentials, result.unwrap())

        return result

    def get_with_retry(
        self,
        credentials: dict,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        retry_on: list[type[Exception]] | None = None
    ) -> FlextResult[AuthToken]:
        """Get token with automatic retry on failure."""
        return self._retry.execute(
            func=self._provider.authenticate,
            credentials=credentials,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            retry_on=retry_on or []
        )

    def refresh_token(
        self,
        token: AuthToken
    ) -> FlextResult[AuthToken]:
        """Refresh token if provider supports it."""
        if "refresh" not in self._provider.supports():
            return FlextResult[AuthToken].fail(
                "Provider does not support token refresh"
            )

        return self._provider.refresh(token)

    def validate_token(
        self,
        token: AuthToken
    ) -> FlextResult[bool]:
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
        retry_on: list[type[Exception]] | None = None,
        **kwargs
    ) -> FlextResult[T]:
        """Execute function with retry logic."""
        retry_on = retry_on or [ConnectionError, TimeoutError]

        for attempt in range(max_retries + 1):
            try:
                result = func(**kwargs)
                return result
            except Exception as e:
                if attempt == max_retries:
                    return FlextResult[T].fail(
                        f"Max retries ({max_retries}) exceeded: {e}"
                    )

                if not any(isinstance(e, exc) for exc in retry_on):
                    return FlextResult[T].fail(f"Non-retryable error: {e}")

                wait_time = backoff_factor ** attempt
                sleep(wait_time)
```

### Token Cache (`tokens/cache.py`)

```python
class TokenCache:
    """Token caching with multiple backend support."""

    def __init__(
        self,
        backend: str = "memory",  # "memory", "redis", "memcached"
        config: dict | None = None
    ) -> None:
        self._backend = self._create_backend(backend, config)
        self.logger = FlextLogger(__name__)

    def get(self, key: dict) -> AuthToken | None:
        """Get token from cache."""
        cache_key = self._hash_credentials(key)
        return self._backend.get(cache_key)

    def set(
        self,
        key: dict,
        token: AuthToken,
        ttl: int | None = None
    ) -> None:
        """Set token in cache."""
        cache_key = self._hash_credentials(key)
        self._backend.set(cache_key, token, ttl=ttl)

    def delete(self, key: dict) -> None:
        """Delete token from cache."""
        cache_key = self._hash_credentials(key)
        self._backend.delete(cache_key)
```

---

## 🔐 SECURITY ARCHITECTURE

### Security Principles

1. **Defense in Depth**: Multiple layers of security validation
2. **Least Privilege**: Minimum required permissions
3. **Fail Secure**: Errors result in denial, not bypass
4. **Audit Logging**: All authentication events logged
5. **Secure Storage**: Encrypted credentials at rest
6. **Token Expiration**: Automatic token lifecycle management

### Credential Management (`credentials/manager.py`)

```python
class CredentialManager:
    """Secure credential management with encryption."""

    def __init__(
        self,
        storage: CredentialStore,
        encryption_key: bytes
    ) -> None:
        self._storage = storage
        self._cipher = self._init_cipher(encryption_key)
        self.logger = FlextLogger(__name__)

    def store_credential(
        self,
        identifier: str,
        credential: dict,
        metadata: dict | None = None
    ) -> FlextResult[None]:
        """Store credential with encryption."""
        encrypted = self._cipher.encrypt(credential)
        return self._storage.save(identifier, encrypted, metadata)

    def retrieve_credential(
        self,
        identifier: str
    ) -> FlextResult[FlextTypes.Dict]:
        """Retrieve and decrypt credential."""
        result = self._storage.load(identifier)
        if result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(result.error)

        encrypted = result.unwrap()
        decrypted = self._cipher.decrypt(encrypted)
        return FlextResult[FlextTypes.Dict].ok(decrypted)

    def rotate_credential(
        self,
        identifier: str,
        new_credential: dict
    ) -> FlextResult[None]:
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
    def validate_token_expiration(token: AuthToken) -> FlextResult[bool]:
        """Validate token has not expired."""
        if token.expires_at < datetime.now(UTC):
            return FlextResult[bool].fail("Token expired")
        return FlextResult[bool].ok(True)

    @staticmethod
    def validate_token_signature(token: str, secret: str) -> FlextResult[bool]:
        """Validate token signature."""
        # Implementation
        ...

    @staticmethod
    def validate_certificate(cert: bytes) -> FlextResult[bool]:
        """Validate X.509 certificate."""
        # Implementation
        ...
```

---

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
| Foundation Patterns  | **flext-core**      | MANDATORY | FlextResult, FlextService, FlextRegistry |

#### FORBIDDEN Direct Imports

```python
# ❌ ABSOLUTELY FORBIDDEN in flext-auth
import httpx          # Use flext-api instead
import requests       # Use flext-api instead
import grpc           # Use flext-grpc instead
import grpcio         # Use flext-grpc instead
import ldap3          # Use flext-ldap instead
```

#### Correct Integration Pattern

```python
# ✅ CORRECT - Using FLEXT domain libraries
from flext_core import FlextResult, FlextService, FlextRegistry, FlextLogger
from flext_api import FlextApi        # For HTTP transport
from flext_grpc import FlextGrpc      # For gRPC transport
from flext_ldap import FlextLdap      # For LDAP provider

class HttpTransportAdapter:
    def __init__(self) -> None:
        self._api = FlextApi()  # MANDATORY: Use flext-api

    def send_request(self, url: str, data: dict) -> FlextResult[FlextTypes.Dict]:
        return self._api.post(url=url, json=data)

class FlextAuthLdapProvider:
    def __init__(self, config: dict) -> None:
        self._ldap = FlextLdap(config)  # MANDATORY: Use flext-ldap

    def authenticate(self, credentials: dict) -> FlextResult[AuthToken]:
        return self._ldap.bind(
            username=credentials["username"],
            password=credentials["password"]
        )
```

### FlextService Integration

All providers and managers extend FlextService for consistency:

```python
from flext_core import FlextService, FlextResult

class FlextAuthJwtProvider(FlextService[AuthToken]):
    """JWT provider extending FlextService."""

    def __init__(self, config: dict) -> None:
        super().__init__()
        self._config = config
        self.logger = FlextLogger(__name__)
```

---

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
from flext_auth.providers import FlextAuthJwtProvider, FlextAuthOAuth2Provider, FlextAuthSamlProvider

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
    credentials={"username": "user", "password": "pass"},
    provider="jwt"
)

oauth_result = auth.authenticate(
    credentials={"authorization_code": "code"},
    provider="oauth2"
)

# List available providers
providers = auth.list_providers()  # ["jwt", "oauth2", "saml"]
```

#### Pattern 3: Custom Transport

```python
from flext_auth import FlextAuth
from flext_auth.providers import FlextAuthOAuth2Provider
from flext_auth.transports import GrpcTransportAdapter

# Create provider with gRPC transport
provider = FlextAuthOAuth2Provider(
    config=oauth_config,
    transport=GrpcTransportAdapter()
)

# Create auth service
auth = FlextAuth.with_provider(provider)

result = auth.authenticate(credentials)
```

#### Pattern 4: Token Retry

```python
from flext_auth import FlextAuth

auth = FlextAuth.with_oauth2(
    client_id="client",
    client_secret="secret"
)

# Get token manager
token_mgr = auth.get_token_manager()

# Get token with retry
token = token_mgr.get_with_retry(
    credentials={"username": "user", "password": "pass"},
    max_retries=3,
    backoff_factor=2.0
)
```

---

## 🏗️ IMPLEMENTATION PHASES

### Phase 1: Foundation & Registry (Week 1) ✅ IN PROGRESS

**Deliverables**:

- ✅ Create `docs/ARCHITECTURE.md` (this document)
- [ ] Implement FlextAuthRegistry in `registry.py`
- [ ] Define base provider protocol in `providers/base.py`
- [ ] Extract JWT logic to `providers/jwt.py`
- [ ] Remove ALL CLI code (source, tests, docs)
- [ ] Update `api.py` with registry integration
- [ ] Update `__init__.py` exports
- [ ] Validate: 71/72 tests still passing
- [ ] Quality gates: make validate passing

**Success Criteria**: Registry operational, JWT provider extracted, zero CLI code, all existing tests passing

### Phase 2: Core Providers (Week 2)

**Deliverables**:

- [ ] Implement FlextAuthOAuth2Provider (authlib)
- [ ] Implement FlextAuthOidcProvider (extends OAuth2)
- [ ] Implement FlextAuthApiKeyProvider
- [ ] Implement FlextAuthBasicProvider (bcrypt)
- [ ] Provider factory pattern
- [ ] Provider tests (95%+ coverage)
- [ ] Quality gates: make validate passing

**Success Criteria**: 4 new providers operational, comprehensive tests, documentation

### Phase 3: Advanced Providers (Week 3)

**Deliverables**:

- [ ] Implement FlextAuthSamlProvider (python3-saml)
- [ ] Implement FlextAuthLdapProvider (flext-ldap MANDATORY)
- [ ] Implement FlextAuthCertificateProvider (cryptography)
- [ ] Kerberos provider stub
- [ ] Security validation per provider
- [ ] Quality gates: make validate passing

**Success Criteria**: 3 advanced providers operational, LDAP using flext-ldap, security audit passed

### Phase 4: Transport & Protocol (Week 4)

**Deliverables**:

- [ ] Transport base protocol
- [ ] HttpTransportAdapter (flext-api MANDATORY)
- [ ] GrpcTransportAdapter (flext-grpc MANDATORY)
- [ ] WebSocket adapter (basic)
- [ ] REST/SOAP/GraphQL protocol handlers
- [ ] Provider-transport integration
- [ ] Quality gates: make validate passing

**Success Criteria**: Transport abstraction complete, HTTP/gRPC using FLEXT libraries

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

---

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

- **Overhead**: <5% performance overhead vs v1.0.0
- **Token Operations**: <10ms for token generation/validation
- **Provider Switching**: <1ms overhead for registry lookup
- **Memory**: No memory leaks, efficient caching

---

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

---

**Document Status**: ✅ Phase 1 Foundation - In Progress
**Next Review**: After Phase 1 completion
**Maintained By**: FLEXT Auth Team

---

_This architecture document is the authoritative reference for the flext-auth v2.0.0 transformation. All implementation must follow these patterns and principles._
