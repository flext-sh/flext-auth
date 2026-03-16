"""FLEXT Auth Protocols - Authentication domain protocols.

Protocol interfaces for authentication and authorization operations.
All protocols organized under single FlextAuthProtocols class per
FLEXT standardization. Uses structural typing only - no model imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol, override, runtime_checkable

import jwt
from flext_api import FlextApiProtocols
from flext_core import FlextProtocols, r, t, u

from flext_auth.models import FlextAuthModels as m


class FlextAuthProtocols(FlextApiProtocols):
    """Unified authentication protocols following FLEXT domain extension pattern.

    This class consolidates authentication-specific protocols while explicitly
    re-exporting foundation protocols for backward compatibility and clean access.

    Architecture:
    - RE-EXPORTS: Foundation protocols from flext-core for unified access
    - EXTENDS: Authentication-specific protocols in Auth namespace
    - MAINTAINS: Zero breaking changes through explicit re-export pattern
    - STRUCTURAL TYPING: No model imports - protocols define structural contracts

    Usage:
    from flext_auth import p

    # Foundation access (inherited)
    p.Result

    # Authentication-specific access
    p.Auth.User
    """

    class Auth:
        """Authentication domain-specific protocols.

        Provides protocols for user authentication, session management,
        token operations, and authentication services. All protocols use
        structural typing - no model imports required.
        """

        type AuthValue = object

        @runtime_checkable
        class Identity(FlextProtocols.Service[bool], Protocol):
            """Protocol for identity/user-like objects in authentication.

            Structural typing interface for identity objects. Models implement
            this protocol through attribute matching (structural typing).
            """

            id: str
            "Unique identity identifier."
            name: str
            "Identity name/username."
            contact: str
            "Contact information (e.g., email)."
            is_active: bool
            "Active status."
            roles: list[str]
            "Identity roles."
            failed_attempts: int
            "Failed login attempts count."
            locked_until: datetime
            "Lock expiration time (datetime.min means not locked)."

            @property
            def email(self) -> str:
                """Alias for contact property (backward compatibility)."""
                ...

            @property
            def username(self) -> str:
                """Alias for name property (backward compatibility)."""
                ...

            def is_locked(self) -> bool:
                """Check if identity is locked."""
                ...

            def set_credential(self, credential: str) -> FlextProtocols.Result[bool]:
                """Set credential with secure hashing."""
                ...

            def verify_credential(self, credential: str) -> FlextProtocols.Result[bool]:
                """Verify credential against stored hash."""
                ...

        @runtime_checkable
        class User(Identity, Protocol):
            """Protocol for user-like objects in authentication.

            Extends Identity with user-specific methods. Maintains
            backward compatibility with existing User interface.
            """

            @property
            def can_login(self) -> bool:
                """Check if user can attempt login."""
                ...

            def record_failed_login(self) -> None:
                """Record failed login attempt and apply lockout if needed."""
                ...

            def record_successful_login(self) -> None:
                """Record successful login and reset failed attempts."""
                ...

        @runtime_checkable
        class Session(FlextProtocols.Service[bool], Protocol):
            """Protocol for session-like objects in authentication."""

            id: str
            user_id: str
            session_token: str
            expires_at: datetime
            is_active: bool
            ip_address: str | None
            user_agent: str | None

            def extend_session(self, hours: int = 1) -> FlextProtocols.Result[bool]:
                """Extend session expiration time."""
                ...

            def is_expired(self) -> bool:
                """Check if session is expired."""
                ...

            @override
            def is_valid(self) -> bool:
                """Check if session is valid (active and not expired)."""
                ...

            def revoke(self) -> FlextProtocols.Result[bool]:
                """Revoke this session."""
                ...

        @runtime_checkable
        class Token(Protocol):
            """Protocol for token-like objects in authentication.

            Structural typing interface for authentication tokens.
            Supports both model and token implementations.
            """

            @property
            def expires_at(self) -> datetime:
                """Token expiration time."""
                ...

            @property
            def identity_id(self) -> str:
                """Identity ID (alias for user_id in token context)."""
                ...

            @property
            def is_expired(self) -> bool:
                """Check if token is expired."""
                ...

            @property
            def is_revoked(self) -> bool:
                """Whether token has been revoked."""
                ...

            @property
            def refresh_token(self) -> str:
                """Refresh token value if applicable."""
                ...

            @property
            def token(self) -> str:
                """Token value."""
                ...

            @property
            def token_type(self) -> str:
                """Token type (e.g. bearer, access)."""
                ...

            @property
            def user_id(self) -> str:
                """User identifier."""
                ...

        @runtime_checkable
        class AuthenticationResponse(Protocol):
            """Protocol for authentication response objects.

            Structural typing interface for authentication responses.
            Supports both TypedDict and model implementations.
            """

            user: Mapping[str, object]
            "User/identity data."
            session: Mapping[str, object]
            "Session data."
            jwt_token: str
            "JWT token string."
            authenticated: bool
            "Authentication status."
            success: bool
            "Operation success status."

        @runtime_checkable
        class Service(FlextProtocols.Service[bool], Protocol):
            """Protocol for authentication service-like objects."""

            def authenticate_user(
                self,
                username: str,
                password: str,
                client_ip: str | None = None,
                user_agent: str | None = None,
            ) -> FlextProtocols.Result[FlextAuthProtocols.Auth.Identity]:
                """Authenticate user and return identity.

                Returns Identity-compatible identity through structural typing.
                """
                ...

            def logout_user(self, session_id: str) -> FlextProtocols.Result[bool]:
                """Logout user by session ID.

                Returns:
                    FlextProtocols.Result[bool]: True if logout successful, False if failed, error on failure

                """
                ...

            def register_user(
                self,
                username: str,
                email: str,
                password: str,
                full_name: str | None = None,
                roles: list[str] | None = None,
            ) -> FlextProtocols.Result[FlextAuthProtocols.Auth.Identity]:
                """Register new user.

                Returns Identity-compatible identity through structural typing.
                """
                ...


p = FlextAuthProtocols
__all__ = ["FlextAuthProtocols", "p"]


class FlextAuthBaseProvider(Protocol):
    """Base protocol for all authentication providers.

    All authentication providers must implement this interface to ensure
    consistent behavior across different authentication technologies (JWT,
    OAuth2, SAML, etc.).
    """

    _provider_config: Mapping[str, t.Primitives] | None

    def __init__(self, config: Mapping[str, t.Primitives] | None = None) -> None:
        """Initialize provider with optional configuration.

        Args:
            config: Provider configuration (optional, provider-specific)

        """
        self._provider_config = config

    @property
    def config(self) -> Mapping[str, t.Primitives] | None:
        """Get provider configuration."""
        return self._provider_config

    @staticmethod
    def _extract_expiration_datetime(
        payload: Mapping[str, object],
    ) -> r[datetime]:
        exp_value = payload.get("exp")
        match exp_value:
            case int() as exp_ts if exp_ts > 0:
                timestamp = float(exp_ts)
            case float() as exp_ts if exp_ts > 0:
                timestamp = exp_ts
            case _:
                return r[datetime].fail("Token payload must include a valid exp claim")
        return u.try_(
            lambda: datetime.fromtimestamp(timestamp, UTC),
            catch=(ValueError, OSError, OverflowError, TypeError, RuntimeError),
        ).map_error(lambda exc: f"Token exp claim conversion failed: {exc}")

    @staticmethod
    def _extract_identity_id(payload: Mapping[str, object]) -> r[str]:
        for key in ("identity_id", "unique_id", "id", "user_id", "sub", "name"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return r[str].ok(value)
        return r[str].fail("User payload must include identity identifier")

    @staticmethod
    def _normalize_claim_value(value: t.Scalar | None) -> t.NormalizedValue | None:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (list, tuple)):
            normalized_items: list[t.Scalar | None] = []
            for item in value:
                normalized_item = FlextAuthBaseProvider._normalize_claim_value(item)
                if normalized_item is not None:
                    normalized_items.append(normalized_item)
            return normalized_items
        if isinstance(value, Mapping):
            normalized_mapping: dict[str, object] = {}
            for key, item in value.items():
                normalized_item = FlextAuthBaseProvider._normalize_claim_value(item)
                if normalized_item is not None:
                    normalized_mapping[key] = normalized_item
            return normalized_mapping
        return value

    def authenticate(self, credentials: m.Auth.CredentialValidation) -> r[p.Auth.Token]:
        """Authenticate user with provided credentials.

        This is the primary authentication method. It should validate the
        provided credentials and, if valid, return an authentication token.

        Args:
            credentials: Dictionary containing authentication credentials.
                        The exact structure depends on the provider type.

        Returns:
            r[p.Auth.Token]: Authentication token on success,
                                   error message on failure

        """
        ...

    def generate_token(
        self,
        payload: Mapping[str, object],
        token_type: str = "access",
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate a signed JWT token from the provided payload."""
        settings_result = self._token_settings()
        if settings_result.is_failure:
            return r[str].fail(settings_result.error or "Token settings are invalid")
        identity_result = self._extract_identity_id(payload)
        if identity_result.is_failure:
            return r[str].fail(
                identity_result.error or "Identity identifier is required"
            )
        secret_key, algorithm_name, issuer_name, audience_name, default_expiry = (
            settings_result.value
        )
        effective_expiry: int
        match expiry_minutes:
            case None:
                effective_expiry = default_expiry
            case int() as custom_expiry if custom_expiry > 0:
                effective_expiry = custom_expiry
            case _:
                return r[str].fail("expiry_minutes must be a positive integer")
        identity_id = identity_result.value
        name_value = payload.get("name")
        name = name_value if isinstance(name_value, str) and name_value else identity_id
        contact_value = payload.get("contact")
        if isinstance(contact_value, str) and contact_value:
            contact = contact_value
        else:
            email_value = payload.get("email")
            contact = (
                email_value
                if isinstance(email_value, str) and email_value
                else f"{identity_id}@local"
            )
        roles_value = payload.get("roles")
        user_roles: list[str]
        if isinstance(roles_value, list):
            user_roles = [
                role for role in roles_value if isinstance(role, str) and role
            ]
        else:
            user_roles = []
        now = datetime.now(UTC)
        claims: dict[str, object] = {}
        reserved_claims = {
            "sub",
            "identity_id",
            "name",
            "email",
            "roles",
            "token_type",
            "iat",
            "exp",
            "iss",
            "aud",
        }
        for key, value in payload.items():
            if key in reserved_claims:
                continue
            if not isinstance(value, (str, int, float, bool)):
                continue
            normalized_value = self._normalize_claim_value(value)
            if normalized_value is not None:
                claims[key] = normalized_value
        claims.update({
            "sub": identity_id,
            "identity_id": identity_id,
            "name": name,
            "email": contact,
            "roles": user_roles,
            "token_type": token_type or "access",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=effective_expiry)).timestamp()),
            "iss": issuer_name,
            "aud": audience_name,
        })

        def _encode_token() -> str:
            encoded_token = jwt.encode(claims, secret_key, algorithm=algorithm_name)
            if isinstance(encoded_token, str):
                return encoded_token
            return str(encoded_token)

        return u.try_(
            _encode_token,
            catch=(
                jwt.PyJWTError,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ),
        ).map_error(lambda exc: f"Token generation failed: {exc}")

    def generate_token_for_user(
        self,
        user: m.Auth.AuthIdentity | Mapping[str, t.ContainerValue],
        token_type: str = "access",
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate authentication token for a user.

        Create a new token for an authenticated user (post-authentication token generation).
        This is distinct from authenticate() which validates credentials.

        Args:
            user: User/identity dictionary with user data
            token_type: Token type (access, refresh, id, bearer)
            expiry_minutes: Token expiration time in minutes (optional)

        Returns:
            r[str]: Encoded token string on success, error on failure

        """
        settings_result = self._token_settings()
        if settings_result.is_failure:
            return r[str].fail(settings_result.error or "Token settings are invalid")
        payload_result = self._normalize_identity_payload(user)
        if payload_result.is_failure:
            return r[str].fail(payload_result.error or "Invalid user payload")
        return self.generate_token(
            payload=payload_result.value,
            token_type=token_type,
            expiry_minutes=expiry_minutes,
        )

    def refresh(self, token: str) -> r[p.Auth.Token]:
        """Refresh authentication token.

        Generate a new token based on an existing valid token. This operation
        is optional and should return an error if the provider doesn't support
        token refresh.

        Args:
            token: Existing token to refresh

        Returns:
            r[p.Auth.Token]: New token on success,
                                   error if refresh not supported or failed

        """
        claims_result = self._decode_token_claims(token)
        if claims_result.is_failure:
            return r[p.Auth.Token].fail(
                claims_result.error or "Source token validation failed"
            )
        source_claims = claims_result.value
        identity_result = self._extract_identity_id(source_claims)
        if identity_result.is_failure:
            return r[p.Auth.Token].fail(
                identity_result.error or "Token subject is missing"
            )
        refresh_type_value = source_claims.get("token_type")
        refresh_type = (
            refresh_type_value
            if isinstance(refresh_type_value, str) and refresh_type_value
            else "access"
        )
        generation_result = self.generate_token(
            payload=source_claims, token_type=refresh_type, expiry_minutes=None
        )
        if generation_result.is_failure:
            return r[p.Auth.Token].fail(
                generation_result.error or "Token refresh generation failed"
            )
        refreshed_claims_result = self._decode_token_claims(generation_result.value)
        if refreshed_claims_result.is_failure:
            return r[p.Auth.Token].fail(
                refreshed_claims_result.error or "Refreshed token validation failed"
            )
        expires_result = self._extract_expiration_datetime(
            refreshed_claims_result.value
        )
        if expires_result.is_failure:
            return r[p.Auth.Token].fail(
                expires_result.error or "Refreshed token exp claim is invalid"
            )
        refresh_token_value = source_claims.get("refresh_token")
        refresh_token = (
            refresh_token_value
            if isinstance(refresh_token_value, str) and refresh_token_value
            else token
        )

        def _build_refreshed_token() -> p.Auth.Token:
            return m.Auth.AuthToken(
                identity_id=identity_result.value,
                token=generation_result.value,
                token_type=refresh_type,
                expires_at=expires_result.value,
                is_revoked=False,
                refresh_token=refresh_token,
            )

        return u.try_(
            _build_refreshed_token,
            catch=(ValueError, TypeError),
        ).map_error(lambda exc: f"Refreshed token model mapping failed: {exc}")

    def revoke(self, _token: str) -> r[bool]:
        """Revoke authentication token.

        Invalidate the provided token, preventing further use. This operation
        is optional and should return an error if the provider doesn't support
        token revocation.

        Args:
            _token: Token to revoke

        Returns:
            r[bool]: True if revoked successfully,
                   False if revocation not supported or failed,
                   error message on failure

        """
        return r[bool].fail("Token revocation not supported")

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        Capabilities help consumers understand what operations are available
        for this provider. This allows graceful degradation when using providers
        with different feature sets.

        Returns:
            set[str]: Set of supported operations

        """
        return {"authenticate", "validate"}

    def validate(self, token: str) -> r[bool]:
        """Validate authentication token.

        Check if the provided token is valid and has not expired.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        ...

    def _decode_token_claims(self, token: str) -> r[Mapping[str, object]]:
        if not token.strip():
            return r[Mapping[str, t.ContainerValue]].fail(
                "Token must be a non-empty string"
            )
        settings_result = self._token_settings()
        if settings_result.is_failure:
            return r[Mapping[str, t.ContainerValue]].fail(
                settings_result.error or "Token settings are invalid"
            )
        secret_key, algorithm_name, issuer_name, audience_name, _default_expiry = (
            settings_result.value
        )
        try:
            decoded_payload = jwt.decode(
                token,
                secret_key,
                algorithms=[algorithm_name],
                audience=audience_name,
                issuer=issuer_name,
                options={"verify_iat": True, "verify_exp": True},
            )
        except jwt.ExpiredSignatureError:
            return r[Mapping[str, t.ContainerValue]].fail("Token has expired")
        except jwt.InvalidTokenError as exc:
            return r[Mapping[str, t.ContainerValue]].fail(f"Invalid token: {exc}")
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as exc:
            return r[Mapping[str, t.ContainerValue]].fail(
                f"Token validation failed: {exc}"
            )
        return r[Mapping[str, t.ContainerValue]].ok(decoded_payload)

    def _normalize_identity_payload(
        self, user: m.Auth.AuthIdentity | Mapping[str, t.ContainerValue]
    ) -> r[Mapping[str, object]]:
        if isinstance(user, Mapping):
            return r[Mapping[str, t.ContainerValue]].ok(user)
        return r[Mapping[str, t.ContainerValue]].ok(
            user.model_dump(exclude={"credential_hash", "token", "refresh_token"})
        )

    def _token_settings(self) -> r[tuple[str, str, str, str, int]]:
        config = self.config
        if config is None:
            return r[tuple[str, str, str, str, int]].fail(
                "Provider configuration is required for token operations"
            )
        secret_value = config.get("secret_key")
        match secret_value:
            case str() as secret if secret:
                secret_key = secret
            case _:
                return r[tuple[str, str, str, str, int]].fail(
                    "Token secret_key is not configured"
                )
        algorithm_value = config.get("algorithm", "HS256")
        match algorithm_value:
            case str() as algorithm if algorithm:
                algorithm_name = algorithm
            case _:
                return r[tuple[str, str, str, str, int]].fail(
                    "Token algorithm is invalid"
                )
        issuer_value = config.get("issuer", "flext-auth")
        match issuer_value:
            case str() as issuer if issuer:
                issuer_name = issuer
            case _:
                issuer_name = "flext-auth"
        audience_value = config.get("audience", "flext-auth")
        match audience_value:
            case str() as audience if audience:
                audience_name = audience
            case _:
                audience_name = "flext-auth"
        expiry_value = config.get("expiry_minutes")
        match expiry_value:
            case int() as expiry if expiry > 0:
                default_expiry = expiry
            case _:
                token_expiry_value = config.get("token_expiry_minutes")
                match token_expiry_value:
                    case int() as token_expiry if token_expiry > 0:
                        default_expiry = token_expiry
                    case _:
                        default_expiry = 60
        return r[tuple[str, str, str, str, int]].ok((
            secret_key,
            algorithm_name,
            issuer_name,
            audience_name,
            default_expiry,
        ))


class BaseTransportAdapter(Protocol):
    """Protocol for transport adapters.

    Transport adapters enable authentication operations over different
    communication protocols (HTTP, gRPC, WebSocket, etc.).

    All transport implementations must implement this protocol to ensure
    consistent interface across different transport mechanisms.

    Example:
        >>> class FlextWebTransportAdapter(BaseTransportAdapter):
        ...     def send_request(
        ...         self,
        ...         url: str,
        ...         method: str = "POST",
        ...         data: dict[str, t.Scalar] | None = None,
        ...         headers: dict[str, str] | None = None,
        ...     ) -> r[dict[str, t.Scalar]]:
        ...         # HTTP-specific implementation
        ...         pass

    """

    def get_transport_type(self) -> str:
        """Get the transport type identifier.

        Returns:
            str: Transport type (e.g., "http", "grpc", "websocket")

        """
        ...

    def send_request(
        self,
        url: str,
        method: str = "POST",
        data: Mapping[str, t.Scalar] | None = None,
        headers: Mapping[str, str] | None = None,
        **kwargs: t.Scalar,
    ) -> r[Mapping[str, t.Scalar]]:
        """Send a request using this transport.

        Args:
        url: Target URL or endpoint
        method: HTTP method or operation type
        data: Request payload data
        headers: Request headers or metadata
        **kwargs: Transport-specific additional parameters

        Returns:
        r containing response data or error

        """
        ...
