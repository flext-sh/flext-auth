"""FLEXT Auth - Authentication Library.

Root module providing authentication framework with multi-provider
support through unified, protocol-based architecture integrated with
FLEXT ecosystem patterns.

Architecture Layer: Layer 3+ (Application & Infrastructure)

Provides public API for flext-auth through:

Core Facade:
  FlextAuth - Main unified API for authentication operations
  - Provider registration and lifecycle management
  - Multi-protocol authentication support
  - Railway-oriented error handling with r[T]
  - Integration with flext-core patterns

Provider System (Protocol-Based):
  FlextAuthBaseProvider - Provider protocol (structural typing)
  FlextAuthRegistry - Provider registration and discovery
  FlextAuthProviderService - Provider orchestration
  - Extensible architecture: Add new providers without modifying core
  - Multiple provider support: JWT, OAuth2, OIDC, SAML, LDAP, Kerberos, etc.
  - Capability detection: Query provider capabilities at runtime
  - Configuration validation: Pydantic v2 provider configs

Service Layer (Services):
  FlextAuthIdentityService - User management and lifecycle
  FlextAuthTokenService - Token generation, validation, refresh
  FlextAuthSessionService - Session management and lifecycle
  - All services follow FlextService[T] base class
  - Return r[T] for error composition
  - Integration with FlextContainer dependency injection

Configuration & Constants:
  FlextAuthSettings - Singleton configuration (Pydantic v2 settings)
  FlextAuthConstants - System constants, error codes, defaults
  - Environment variable override support
  - Type-safe configuration access
  - Validation on initialization

Data Models (Domain-Driven Design):
  FlextAuthModels - Pydantic v2 models for all domain entities
  - Generic models for credential, token, session, user data
  - Complete validation with Field() constraints
  - Computed properties for derived data
  - Model validators for business logic

Type System & Protocols:
  FlextAuthTypes - Authentication-specific type definitions
  FlextAuthProtocols - Protocol definitions for structural typing
  - Domain-specific TypeVars for type safety
  - Complex type aliases for credential/token/session data
  - Protocol-based extensibility

Error Handling:
  FlextAuthExceptions - Authentication-specific exception hierarchy
  - AuthenticationError - Auth operation failures
  - AuthorizationError - Permission denied
  - ProviderNotFoundError - Provider registration failures
  - TokenError - Token-related failures
  - SessionError - Session management failures
  - CredentialError - Credential validation failures
  - ProviderError - Generic provider failures

Utilities & Mixins:
  FlextAuthUtilities - JWT and password processing utilities
  FlextAuthMixins - Reusable authentication behaviors
  - Password hashing with bcrypt
  - Password strength validation
  - Token processing helpers

Lifecycle Management:
  FlextAuthManagers - Authentication lifecycle managers
  - Provider lifecycle management
  - Session lifecycle management
  - Token lifecycle management

Infrastructure Integration:
  FlextAuthMiddleware - HTTP middleware for authentication
  FlextAuthTransports - Multi-transport support (HTTP, gRPC, WebSocket)
  - Integration with web frameworks
  - Transport-agnostic authentication
  - Multi-protocol support

Quick Start:
  FlextAuthQuickstart - Quick-start utilities for common scenarios
  - Pre-configured providers
  - Demo data initialization
  - Example authentication flows


PROVIDER-CENTRIC ARCHITECTURE


FLEXT-AUTH is built around a provider-centric architecture where all
authentication technologies are encapsulated in provider implementations that
conform to a unified protocol:

Core Components:
  - FlextAuth - Main facade API (single entry point)
  - FlextAuthRegistry - Provider registration and discovery
  - FlextAuthBaseProvider - Protocol defining provider capabilities
  - Provider Implementations - Technology-specific authentication logic

Architectural Principles:
  - All authentication flows through the provider registry system
  - Each provider implements the same protocol interface
  - Providers are registered dynamically at runtime
  - Provider capabilities are queried at runtime
  - No direct provider imports in main API (registry only)

Supported Providers (Phase 2-3 Expansion):
  - JWT - Production-ready token-based authentication
  - OAuth2 - Authorization code and client credentials flows
  - OIDC - OpenID Connect authentication
  - SAML - SAML 2.0 authentication
  - LDAP - LDAP directory authentication
  - API Key - API key-based authentication
  - Basic - HTTP Basic authentication
  - Certificate - X.509 certificate authentication
  - Kerberos - Kerberos network authentication


LAYER ARCHITECTURE (Clean Architecture)


Layer 4: Infrastructure (config.py, middleware.py, transports/)
    ├─ FlextAuthSettings (Pydantic Settings)
    ├─ FlextAuthMiddleware (HTTP middleware)
    └─ Transport implementations (HTTP, gRPC, WebSocket)
    ↓
Layer 3: Application (api.py, provider_service.py, managers.py)
    ├─ FlextAuth (Main facade)
    ├─ FlextAuthRegistry (Provider management)
    ├─ FlextAuthProviderService (Provider orchestration)
    └─ FlextAuthManagers (Lifecycle management)
    ↓
Layer 2: Domain (models.py, *_service.py, utilities.py)
    ├─ FlextAuthModels (Domain models)
    ├─ FlextAuthIdentityService (User management)
    ├─ FlextAuthTokenService (Token operations)
    ├─ FlextAuthSessionService (Session management)
    ├─ FlextAuthUtilities (Validation & conversion)
    └─ FlextAuthMixins (Reusable behaviors)
    ↓
Layer 1: Foundation (providers/base.py, exceptions.py, protocols.py)
    ├─ FlextAuthBaseProvider (Provider protocol)
    ├─ FlextAuthExceptions (Error hierarchy)
    └─ FlextAuthProtocols (Protocol definitions)
    ↓
Layer 0: Pure Constants (constants.py, typings.py)
    ├─ FlextAuthConstants (Error codes, defaults)
    └─ FlextAuthTypes (Type definitions)

Critical Rule: Higher layers import from lower layers ONLY. Violations
cause circular dependencies and violate Clean Architecture principles.


SOLID PRINCIPLES IMPLEMENTATION


Single Responsibility Principle (SRP):
  - Each class has ONE reason to change
  - api.py: FlextAuth facade only (coordinates providers)
  - *_service.py: Focused domain services (user, token, session)
  - Each provider implements ONE authentication technology

Open/Closed Principle (OCP):
  - Open for extension: Add providers via registry without modifying core
  - Closed for modification: Provider protocol is stable interface
  - FlextAuthBaseProvider defines extension point

Liskov Substitution Principle (LSP):
  - All providers implement FlextAuthBaseProvider protocol
  - Providers are substitutable: Use any provider through registry
  - Protocol compliance verified through structural typing

Interface Segregation Principle (ISP):
  - FlextAuthProtocols defines focused, client-specific interfaces
  - Providers implement only needed capabilities
  - Clients depend on minimal required methods

Dependency Inversion Principle (DIP):
  - High-level modules depend on abstractions (protocols)
  - Low-level modules (providers) implement protocols
  - FlextAuthRegistry manages provider lifecycle
  - r[T] abstracts error handling


PYDANTIC V2 BEST PRACTICES


Model Validation:
  - All models use Field() with descriptions and constraints
  - Custom validators for complex business logic
  - Model validators for cross-field validation
  - Computed properties via @computed_field

Type Safety:
  - Python 3.13+ type syntax throughout
  - Complete type annotations required (zero Any types)
  - Generic types for type-safe operations
  - TypedDict for complex dictionary structures

Configuration Management:
  - FlextAuthSettings uses ConfigDict for strict validation
  - Environment variable override support
  - Hierarchical configuration with inheritance
  - Validation on initialization (fails fast)


RAILWAY-ORIENTED PROGRAMMING PATTERN


All operations return r[T]:
  >>> from flext_auth import FlextAuth, r
  >>> auth = FlextAuth()
  >>> result = (
  ...     auth.authenticate(credentials)
  ...     .flat_map(lambda user: auth.generate_token(user))
  ...     .map(lambda token: format_response(token))
  ... )
  >>> if result.is_success:
  ...     response = result.value
  ... else:
  ...     error = result.error

Benefits:
  - Composable error handling (no exceptions in flow)
  - Type-safe error composition
  - Functional programming style
  - Integration with flext-core patterns


USAGE EXAMPLES


Example 1: Basic Authentication with JWT:
  >>> from flext_auth import FlextAuth, FlextAuthSettings
  >>>
  >>> # Initialize with JWT provider
  >>> config = FlextAuthSettings(jwt_secret="your-secret-key", jwt_algorithm="HS256")
  >>> auth = FlextAuth(config=config)
  >>>
  >>> # Authenticate user
  >>> creds = {"username": "user", "password": "pass"}
  >>> result = auth.authenticate(creds)
  >>> if result.is_success:
  ...     user = result.value
  ...     print(f"User {user.user_id} authenticated")

**Example 2: Multi-Provider Setup**:
  >>> from flext_auth import FlextAuth, FlextAuthRegistry
  >>> from flext_auth import FlextAuthJwtProvider, FlextAuthOAuth2Provider
  >>>
  >>> auth = FlextAuth()
  >>> registry = auth.registry
  >>>
  >>> # Register multiple providers
  >>> jwt_provider = FlextAuthJwtProvider({"secret": "key"})
  >>> registry.register("jwt", jwt_provider)
  >>>
  >>> oauth_provider = FlextAuthOAuth2Provider({...})
  >>> registry.register("oauth2", oauth_provider)
  >>>
  >>> # Use specific provider
  >>> result = auth.authenticate(creds, provider="jwt")

**Example 3: Token Validation & Refresh**:
  >>> from flext_auth import FlextAuth
  >>>
  >>> auth = FlextAuth()
  >>>
  >>> # Validate token
  >>> validate_result = auth.validate_token(access_token)
  >>> if validate_result.is_success:
  ...     claims = validate_result.value
  >>>
  >>> # Refresh token
  >>> refresh_result = auth.refresh_token(refresh_token)
  >>> if refresh_result.is_success:
  ...     new_token = refresh_result.value

**Example 4: Session Management**:
  >>> from flext_auth import FlextAuth
  >>>
  >>> auth = FlextAuth()
  >>> user_id = "user123"
  >>>
  >>> # Create session
  >>> session_result = auth.create_session(user_id)
  >>> if session_result.is_success:
  ...     session = session_result.value
  ...     print(f"Session {session.session_id} created")
  >>>
  >>> # Validate session
  >>> validate_result = auth.validate_session(session.session_id)
  >>> if validate_result.is_success:
  ...     is_valid = validate_result.value

**Example 5: User Management**:
  >>> from flext_auth import FlextAuth, FlextAuthModels
  >>>
  >>> auth = FlextAuth()
  >>>
  >>> # Register user
  >>> user_data = {
  ...     "username": "newuser",
  ...     "email": "user@example.com",
  ...     "password": "secure_password",
  ... }
  >>> register_result = auth.register_user(user_data)
  >>> if register_result.is_success:
  ...     user = register_result.value
  >>>
  >>> # Get user
  >>> get_result = auth.get_user(user.user_id)
  >>> if get_result.is_success:
  ...     fetched_user = get_result.value

**Example 6: Custom Provider Implementation**:
  >>> from flext_auth import FlextAuthBaseProvider, r, FlextAuthModels
  >>>
  >>> class CustomProvider(FlextAuthBaseProvider):
  ...     def authenticate(self, credentials: dict) -> r[FlextAuthModels.AuthToken]:
  ...         # Custom authentication logic
  ...         return r[FlextAuthModels.AuthToken].ok(token)
  ...
  ...     def validate(self, token: str) -> r[bool]:
  ...         # Custom validation logic
  ...         return r[bool].ok(True)
  ...
  ...     def supports(self) -> set[str]:
  ...         return {"authenticate", "validate"}
  ...
  ...     def get_metadata(self) -> dict[str, object]:
  ...         return {"name": "custom", "version": "1.0.0"}


Root Import Pattern (Ecosystem Standard)


Correct - Always use root imports (this module):
  from flext_auth import (
      FlextAuth,
      FlextAuthSettings,
      FlextAuthModels,
      FlextAuthTypes,
      FlextAuthConstants,
      FlextAuthExceptions,
  )

Forbidden - Never use internal module imports:
  from flext_auth.api import FlextAuth                # Breaks ecosystem
  from flext_auth.models import FlextAuthModels       # Breaks ecosystem
  from flext_auth.settings import FlextAuthSettings       # Breaks ecosystem
  from flext_auth.providers.jwt import FlextAuthJwtProvider  # FORBIDDEN

Why: 32+ ecosystem projects rely on root imports. Internal imports break the
entire ecosystem by creating circular dependencies and import order issues.
ALWAYS use root imports from this module (flext_auth/__init__.py).


QUALITY GATES & VALIDATION


Production Readiness (All Mandatory):
  Type Safety: Pyrefly strict mode (zero type errors)
  Linting: Ruff with zero violations
   Testing: Test coverage (75%+)
  Security: Bandit security scanning (no high/medium issues)
  Documentation: Complete API documentation
  SOLID Principles: All principles verified and documented
  Pydantic v2: Best practices throughout
  PEP 8: Strict compliance with 88-char line length


INTEGRATION WITH FLEXT ECOSYSTEM


Core Integration:
  - Uses flext-core r[T] for error composition
  - Uses flext-core FlextContainer for dependency injection
  - Uses flext-core FlextModels base class for domain models
  - Uses flext-core FlextService base class for all services
  - Uses flext-core FlextExceptions patterns for auth exceptions

Ecosystem Projects Using flext-auth:
  - flext-api: REST API authentication
  - flext-web: Web application authentication
  - flext-cli: CLI authentication
  - flext-ldap: LDAP authentication
  - All other FLEXT ecosystem projects requiring auth

Breaking Change Policy:
  - All changes to FlextAuth public API maintain backward compatibility
  - Deprecation cycle: 2 versions (6+ months) before removal
  - Migration tools provided for any necessary transitions


VERSIONING & METADATA


- Package: flext-auth (production-ready)
- Version: 0.9.0 (see __version__ for current)
- Python: 3.13+ exclusive
- Status: Enterprise authentication library for FLEXT ecosystem
- License: MIT (Copyright 2025 FLEXT Team)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import (
    FlextDecorators,
    FlextExceptions,
    FlextHandlers,
    FlextMixins,
    FlextResult,
    FlextService,
)

from flext_auth.__version__ import __version__, __version_info__
from flext_auth.api import FlextAuth
from flext_auth.constants import FlextAuthConstants
from flext_auth.managers import FlextAuthManagers
from flext_auth.middleware import FlextAuthMiddleware
from flext_auth.mixins import FlextAuthMixins
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols
from flext_auth.provider_service import FlextAuthProviderService
from flext_auth.providers import (
    FlextAuthApiKeyProvider,
    FlextAuthBaseProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthJwtProvider,
    FlextAuthKerberosProvider,
    FlextAuthLdapProvider,
    FlextAuthOAuth2Provider,
    FlextAuthOidcProvider,
    FlextAuthProviderMixin,
    FlextAuthSamlProvider,
)
from flext_auth.quickstart import FlextAuthQuickstart
from flext_auth.registry import FlextAuthRegistry
from flext_auth.session_service import FlextAuthSessionService
from flext_auth.settings import FlextAuthSettings
from flext_auth.token_service import FlextAuthTokenService
from flext_auth.typings import FlextAuthTypes
from flext_auth.user_service import FlextAuthIdentityService
from flext_auth.utilities import FlextAuthUtilities

# Domain-specific aliases (extending flext-core base classes)
u = FlextAuthUtilities  # Utilities (FlextAuthUtilities extends FlextUtilities)
m = FlextAuthModels  # Models (FlextAuthModels extends FlextModels)
c = FlextAuthConstants  # Constants (FlextAuthConstants extends FlextConstants)
t = FlextAuthTypes  # Types (FlextAuthTypes extends FlextTypes)
p = FlextAuthProtocols  # Protocols (FlextAuthProtocols extends FlextProtocols)

r = FlextResult  # Shared from flext-core
e = FlextExceptions  # Shared from flext-core
d = FlextDecorators  # Shared from flext-core
s = FlextService  # Shared from flext-core
x = FlextMixins  # Shared from flext-core
h = FlextHandlers  # Shared from flext-core

__all__ = [
    "FlextAuth",
    "FlextAuthApiKeyProvider",
    "FlextAuthBaseProvider",
    "FlextAuthBasicProvider",
    "FlextAuthCertificateProvider",
    "FlextAuthConstants",
    "FlextAuthIdentityService",
    "FlextAuthJwtProvider",
    "FlextAuthKerberosProvider",
    "FlextAuthLdapProvider",
    "FlextAuthManagers",
    "FlextAuthMiddleware",
    "FlextAuthMixins",
    "FlextAuthModels",
    "FlextAuthOAuth2Provider",
    "FlextAuthOidcProvider",
    "FlextAuthProtocols",
    "FlextAuthProviderMixin",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRegistry",
    "FlextAuthSamlProvider",
    "FlextAuthSessionService",
    "FlextAuthSettings",
    "FlextAuthTokenService",
    "FlextAuthTypes",
    "FlextAuthUtilities",
    "__version__",
    "__version_info__",
    # Domain-specific aliases
    "c",
    # Global aliases
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]
