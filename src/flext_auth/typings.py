"""FLEXT Auth Type Definitions - Comprehensive types using flext-core as foundation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

FlextAuthTypes class using maximum FlextTypes coverage for all library needs.
"""

from __future__ import annotations

from flext_core import FlextTypes

# =============================================================================
# FLEXT AUTH TYPES - Complete type system using maximum FlextTypes coverage
# =============================================================================


class FlextAuthTypes:
    """Complete type system for flext-auth using maximum FlextTypes coverage.

    Provides all types needed by the authentication library, leveraging
    flext-core types extensively for consistency and interoperability.
    """

    # =========================================================================
    # AUTHENTICATION TYPES - Based on FlextTypes.Auth
    # =========================================================================

    # User identity types
    type UserId = FlextTypes.Auth.UserId  # str - User identifier
    type Username = FlextTypes.Auth.Username  # str - Username
    type UserRole = FlextTypes.Auth.Role  # str - User role
    type Permission = FlextTypes.Auth.Permission  # str - Permission string
    type Scope = FlextTypes.Auth.Scope  # str - Authorization scope

    # Token types
    type AccessToken = FlextTypes.Auth.AccessToken  # str - JWT access token
    type RefreshToken = FlextTypes.Auth.RefreshToken  # str - JWT refresh token
    type TokenPayload = FlextTypes.Auth.TokenPayload  # dict[str, object] - JWT claims

    # =========================================================================
    # CORE PRIMITIVE TYPES - Based on FlextTypes.Core
    # =========================================================================

    # String types
    type String = FlextTypes.Core.String  # str - String type
    type Id = FlextTypes.Core.Id  # str - Generic identifier
    type Identifier = FlextTypes.Core.Identifier  # str - Entity identifier
    type UUID = FlextTypes.Core.UUID  # str - UUID string
    type ErrorMessage = FlextTypes.Core.ErrorMessage  # str - Error message
    type LogMessage = FlextTypes.Core.LogMessage  # str - Log message

    # Numeric types
    type Integer = int  # int - Integer type
    type Float = FlextTypes.Core.Float  # float - Float type

    # Boolean types
    type Boolean = FlextTypes.Core.Boolean  # bool - Boolean type

    # Collection types
    type List = FlextTypes.Core.List  # list[object] - List type
    type Dict = FlextTypes.Core.Dict  # dict[str, object] - Dictionary type
    type JsonValue = FlextTypes.Core.JsonValue  # JSON value union
    type JsonObject = FlextTypes.Core.JsonObject  # dict[str, JsonValue]
    type Object = FlextTypes.Core.Object  # object - Generic object
    type Value = FlextTypes.Core.Value  # Union value type

    # =========================================================================
    # DOMAIN TYPES - Based on FlextTypes.Domain
    # =========================================================================

    # Domain entity types
    type EntityId = FlextTypes.Domain.EntityId  # str - Entity identifier

    # =========================================================================
    # RESULT TYPES - Based on FlextTypes.Result
    # =========================================================================

    # Result pattern types
    type ResultType[T] = FlextTypes.Result.ResultType[T]  # FlextResult[T]
    type Success[T] = FlextTypes.Result.Success[T]  # Success result

    # =========================================================================
    # SERVICE TYPES - Based on FlextTypes.Service
    # =========================================================================

    # Service layer types
    type ServiceInstance = FlextTypes.Service.ServiceInstance  # object - Service
    type ServiceDict = FlextTypes.Service.ServiceDict  # dict[str, ServiceInstance]
    type FactoryDict = FlextTypes.Service.FactoryDict  # dict[str, Factory]
    type ServiceName = FlextTypes.Service.ServiceName  # str - Service name

    # =========================================================================
    # CONFIG TYPES - Based on FlextTypes.Config
    # =========================================================================

    # Configuration types
    type ConfigValue = FlextTypes.Config.ConfigValue  # Union config value
    type ConfigDict = FlextTypes.Config.ConfigDict  # dict[str, ConfigValue]
    type Environment = FlextTypes.Config.Environment  # Environment literal
    type LogLevel = FlextTypes.Config.LogLevel  # Log level literal
    type ValidationResult = FlextTypes.Config.ValidationResult  # bool

    # =========================================================================
    # VALIDATION TYPES - Based on FlextTypes.Validation
    # =========================================================================

    # Validation types
    type Email = FlextTypes.Validation.Email  # str - Email format
    type EmailValidationResult = (
        FlextTypes.Validation.EmailValidationResult
    )  # FlextResult[str]
    type Url = FlextTypes.Validation.Url  # str - URL format
    type Phone = FlextTypes.Validation.Phone  # str - Phone format
    type PositiveNumber = FlextTypes.Validation.PositiveNumber  # float | int
    type PredicateFunction = FlextTypes.Validation.PredicateFunction  # Callable
    type Pattern = FlextTypes.Validation.Pattern  # str - Regex pattern
    type ValidationRule = FlextTypes.Validation.ValidationRule  # str - Rule
    type ValidationMessage = FlextTypes.Validation.ValidationMessage  # str - Message
    type ValidationCode = FlextTypes.Validation.ValidationCode  # str - Code

    # =========================================================================
    # CONTAINER TYPES - Based on FlextTypes.Container
    # =========================================================================

    # Dependency injection types
    type ServiceKey = FlextTypes.Container.ServiceKey  # str - Service key
    type ServiceRegistration = (
        FlextTypes.Container.ServiceRegistration
    )  # FlextResult[None]
    type ServiceRetrieval = FlextTypes.Container.ServiceRetrieval  # FlextResult[object]
    type FactoryFunction = FlextTypes.Container.FactoryFunction  # Callable[[], object]
    type FactoryRegistration = (
        FlextTypes.Container.FactoryRegistration
    )  # FlextResult[None]

    # =========================================================================
    # HANDLER TYPES - Based on FlextTypes.Handler
    # =========================================================================

    # CQRS Handler types
    type Command = FlextTypes.Handler.Command  # object - Command
    type Query = FlextTypes.Handler.Query  # object - Query
    type Event = FlextTypes.Handler.Event  # dict[str, object] - Event
    type CommandHandler = FlextTypes.Handler.CommandHandler  # Callable
    type QueryHandler = FlextTypes.Handler.QueryHandler  # Callable
    type EventHandler = FlextTypes.Handler.EventHandler  # Callable
    type HandlerName = FlextTypes.Handler.HandlerName  # str - Handler name
    type HandlerMetadata = FlextTypes.Handler.HandlerMetadata  # dict[str, object]
    type Context = FlextTypes.Handler.Context  # dict[str, object]
    type ProcessingResult = FlextTypes.Handler.ProcessingResult  # object

    # =========================================================================
    # LOGGING TYPES - Based on FlextTypes.Logging
    # =========================================================================

    # Logging types
    type LogEntry = FlextTypes.Logging.LogEntry  # dict[str, object]
    type LogContext = FlextTypes.Logging.LogContext  # dict[str, str]
    type LogMetadata = FlextTypes.Logging.LogMetadata  # dict[str, object]
    type ContextDict = FlextTypes.Logging.ContextDict  # dict[str, object]
    type LogData = FlextTypes.Logging.LogData  # dict[str, object]

    # =========================================================================
    # NETWORK TYPES - Based on FlextTypes.Network
    # =========================================================================

    # Network types
    type IPAddress = FlextTypes.Network.IPAddress  # str - IP address
    type URL = FlextTypes.Network.URL  # str - URL
    type Headers = FlextTypes.Network.Headers  # dict[str, str]
    type RequestBody = FlextTypes.Network.RequestBody  # Union request body
    type ResponseBody = FlextTypes.Network.ResponseBody  # Union response body

    # =========================================================================
    # AUTH-SPECIFIC TYPES - Library-specific extensions
    # =========================================================================

    # Authentication-specific types
    type PasswordHash = String  # str - Bcrypt password hash
    type UserStatus = String  # str - User status (active, locked, etc.)
    type LoginAttempts = Integer  # int - Failed login attempts count
    type ExpiryMinutes = Integer  # int - Token expiry in minutes
    type SessionId = String  # str - Session identifier
    type UserAgent = String  # str - User agent string
    type IsActive = Boolean  # bool - Active status flag
    type HasPermission = Boolean  # bool - Permission check result
    type TokenType = String  # str - Token type (access, refresh)
    type LockoutDuration = Integer  # int - Account lockout duration

    # Authentication result types
    type AuthResult[T] = FlextTypes.Result.Success[T]  # Authentication operation result
    type UserResult = AuthResult[Dict]  # User operation result
    type TokenResult = AuthResult[String]  # Token operation result
    type SessionResult = AuthResult[Dict]  # Session operation result
    type LoginResult = AuthResult[Dict]  # Login operation result
    type RegisterResult = AuthResult[Dict]  # Registration operation result
    type LogoutResult = AuthResult[Dict]  # Logout operation result
    type PermissionResult = AuthResult[Boolean]  # Permission check result
    type ValidateResult = AuthResult[Dict]  # Token validation result

    # Authentication data types
    type AuthData = Dict  # dict[str, object] - Authentication response data
    type UserData = Dict  # dict[str, object] - User data dictionary
    type SessionData = Dict  # dict[str, object] - Session data dictionary
    type TokenData = Dict  # dict[str, object] - Token data dictionary
    type ClaimsData = Dict  # dict[str, object] - JWT claims data
    type CredentialsData = Dict  # dict[str, object] - Credentials data
    type RegistrationData = Dict  # dict[str, object] - Registration data

    # Authentication configuration types
    type AuthConfig = ConfigDict  # Authentication configuration
    type JWTConfig = ConfigDict  # JWT configuration
    type PasswordConfig = ConfigDict  # Password configuration
    type SessionConfig = ConfigDict  # Session configuration
    type SecurityConfig = ConfigDict  # Security configuration

    # Service types specific to authentication
    type AuthService = ServiceInstance  # Authentication service instance
    type PasswordService = ServiceInstance  # Password service instance
    type JWTService = ServiceInstance  # JWT service instance
    type SessionService = ServiceInstance  # Session service instance
    type UserService = ServiceInstance  # User service instance


# =============================================================================
# EXPORTS - Export the main class and commonly used types
# =============================================================================

__all__ = [
    "FlextAuthTypes",
]
