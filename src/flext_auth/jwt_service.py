"""JWT service with Python 3.13 zero boilerplate patterns."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID, uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flext_core.domain.pydantic_base import DomainValueObject
from pydantic import Field

from flext_auth.models import Claims, TokenInfo

if TYPE_CHECKING:
    from flext_auth.models import User


# Simple result class for validation
class ValidationResult:
    """Simple validation result."""

    def __init__(self, success: bool, error: str = "", data: Any | None = None) -> None:
        self.success = success
        self.error = error
        self.data = data

    @property
    def is_failure(self) -> bool:
        """Check if validation failed."""
        return not self.success

    @property
    def is_success(self) -> bool:
        """Check if validation succeeded."""
        return self.success


# Python 3.13 type aliases
TokenString = str
SecretKey = bytes | str


def _get_jwt_config() -> JWTConfig:
    # Use secure defaults since config is not available
    return JWTConfig(
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        secret_key="change-this-secret-in-production",
    )


PublicKey = bytes | str
PrivateKey = bytes | str


class TokenStorageProtocol(Protocol):
    """TokenStorageProtocol - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações:
        Atomic operations with rollback
    Padrões: Application services, orchestration

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    store_token(): Método específico da classe
    get_token(): Obtém dados
    revoke_token(): Método específico da classe
    is_blacklisted(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    service = TokenStorageProtocol(config)
    result = await service.process(data)
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    async def store_token(self, token_info: TokenInfo) -> None:
        """Store token information for tracking and validation.

        Args:
            token_info: Token information to store including metadata.

        """
        ...

    async def get_token(self, token_id: str) -> TokenInfo | None:
        """Retrieve token information by token ID.

        Args:
            token_id: The unique token identifier.

        Returns:
            TokenInfo if found, None otherwise.

        """
        ...

    async def revoke_token(self, token_id: str) -> None:
        """Revoke a token to prevent further use.

        Args:
            token_id: The unique token identifier to revoke.

        """
        ...

    async def is_blacklisted(self, token_id: str) -> bool:
        """Check if a token is blacklisted (revoked).

        Args:
            token_id: The unique token identifier to check.

        Returns:
            True if the token is blacklisted, False otherwise.

        """
        ...


class TokenPair(DomainValueObject):
    """Enterprise JWT token pair with comprehensive security validation.

    Immutable value object representing a complete authentication token set including
    access token, refresh token, and comprehensive metadata for enterprise security
    compliance and audit trail requirements.

    This value object ensures consistent token pair structure across all authentication
    flows while maintaining security best practices and comprehensive audit logging.
    """

    access_token: TokenString = Field(
        description="JWT access token for API authentication and authorization",
    )
    refresh_token: TokenString = Field(
        description="JWT refresh token for secure token renewal",
    )
    token_type: str = Field(
        default="Bearer",  # nosec S105 - not a password, token type constant
        description="Token type specification for HTTP Authorization header compliance",
    )
    expires_in: int = Field(
        default_factory=lambda: _get_jwt_config().access_token_expire_minutes * 60,
        description="Access token expiration duration in seconds for client cache management",
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert the token pair to a dictionary representation.

        Returns:
            Dictionary containing access_token, refresh_token, token_type, and expires_in.

        """
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
        }


class JWTConfig(DomainValueObject):
    """Enterprise JWT configuration with comprehensive security validation and domain integration.

    Immutable configuration value object encapsulating all JWT security parameters
    with enterprise-grade defaults, comprehensive validation, and domain constant
    integration for consistent security policy enforcement.
    """

    algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm ensuring cryptographic security compliance",
    )
    access_token_expire_minutes: int = Field(
        default=30,
        description="Access token expiration period balancing security and user experience",
    )
    refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration period for secure long-term authentication",
    )
    issuer: str = Field(
        default="flext-platform",
        description="JWT issuer identification for token validation",
    )
    audience: str = Field(
        default="flext-api",
        description="JWT audience specification for access control",
    )

    # Cryptographic keys for enterprise security
    secret_key: SecretKey = Field(
        default="change-this-secret-in-production",
        description="Secret key for HMAC-based JWT signing ensuring token integrity",
    )
    public_key: PublicKey | None = Field(
        default=None,
        description="RSA public key for JWT signature verification",
    )
    private_key: PrivateKey | None = Field(
        default=None,
        description="RSA private key for JWT signing operations",
    )

    # Advanced security options with domain integration
    leeway_seconds: int = Field(
        default=10,
        description="Clock skew tolerance for distributed system synchronization",
    )
    verify_signature: bool = Field(
        default=True,
        description="Enable JWT signature verification for security",
    )
    verify_exp: bool = Field(
        default=True,
        description="Enable JWT expiration validation",
    )
    verify_aud: bool = Field(default=True, description="Enable JWT audience validation")
    require_exp: bool = Field(
        default=True,
        description="Require expiration claim for security compliance",
    )


class JWTService:
    """JWT service with zero boilerplate using reflection."""

    def __init__(
        self,
        config: JWTConfig,
        storage: TokenStorageProtocol | None = None,
    ) -> None:
        self.config = config
        self.storage = storage

        # Generate RSA keys if using RS256 and not provided:
        if config.algorithm == "RS256" and not config.private_key:
            self._generate_rsa_keys()

    def _generate_rsa_keys(self) -> None:
        # ZERO TOLERANCE - Use configuration for RSA parameters
        config = _get_jwt_config()
        private_key = rsa.generate_private_key(
            public_exponent=getattr(config, "rsa_public_exponent", 65537),
            key_size=getattr(
                config,
                "rsa_key_size",
                2048,  # Secure default RSA key size
            ),
        )

        # Export private key
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Export public key
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Create new immutable config with keys (JWTConfig is a DomainValueObject)
        self.config = JWTConfig(
            algorithm=self.config.algorithm,
            access_token_expire_minutes=self.config.access_token_expire_minutes,
            refresh_token_expire_days=self.config.refresh_token_expire_days,
            issuer=self.config.issuer,
            audience=self.config.audience,
            secret_key=self.config.secret_key,
            public_key=public_key_bytes,
            private_key=private_key_bytes,
            leeway_seconds=self.config.leeway_seconds,
            verify_signature=self.config.verify_signature,
            verify_exp=self.config.verify_exp,
            verify_aud=self.config.verify_aud,
            require_exp=self.config.require_exp,
        )

    def create_access_token(
        self,
        user: User,
        additional_claims: Claims | None = None,
    ) -> TokenString:
        """Create a JWT access token for the user.

        Args:
            user: User to create the token for.
            additional_claims: Optional additional claims to include in the token.

        Returns:
            The encoded JWT access token string.

        """
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=self.config.access_token_expire_minutes)

        # Build claims
        jti_uuid = uuid4()
        claims = {
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "exp": expires_at,
            "iat": now,
            "nbf": now,
            "jti": str(jti_uuid),
            "token_type": "access",
        }

        # Add user claims
        claims.update(user.to_claims())

        # Add additional claims
        if additional_claims:
            claims.update(additional_claims)

        # Encode token
        key = self._get_signing_key()
        token = str(jwt.encode(claims, key, algorithm=self.config.algorithm))

        # Store token info if storage available:
        if self.storage:
            # Use the jti UUID we generated
            token_info = TokenInfo(
                token_id=jti_uuid,
                user_id=user.user_id,
                token_type="access",
                issued_at=now,
                expires_at=expires_at,
            )
            try:
                task = asyncio.create_task(self.storage.store_token(token_info))
                task.add_done_callback(lambda _: None)  # Prevent dangling task warning
            except RuntimeError:
                # No event loop running - skip storage for now
                # This typically happens in sync contexts like tests
                pass

        # PyJWT returns string in modern versions
        return token

    def create_refresh_token(self, user: User) -> TokenString:
        """Create a JWT refresh token for the user.

        Args:
            user: User to create the token for.

        Returns:
            The encoded JWT refresh token string.

        """
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=self.config.refresh_token_expire_days)

        # Build claims
        jti_uuid = uuid4()
        claims = {
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "exp": expires_at,
            "iat": now,
            "nbf": now,
            "jti": str(jti_uuid),
            "sub": str(user.user_id),
            "token_type": "refresh",
        }

        # Encode token
        key = self._get_signing_key()
        token = str(jwt.encode(claims, key, algorithm=self.config.algorithm))

        # Store token info if storage available:
        if self.storage:
            try:
                # Use the jti UUID we generated
                token_info = TokenInfo(
                    token_id=jti_uuid,
                    user_id=user.user_id,
                    token_type="refresh",
                    issued_at=now,
                    expires_at=expires_at,
                )
                task = asyncio.create_task(self.storage.store_token(token_info))
                task.add_done_callback(lambda _: None)  # Prevent dangling task warning
            except RuntimeError:
                # No event loop running - skip storage for now
                # This typically happens in sync contexts like tests
                pass

        # PyJWT returns string in modern versions
        return token

    def create_token_pair(
        self,
        user: User,
        additional_claims: Claims | None = None,
    ) -> TokenPair:
        """Create a complete token pair (access and refresh tokens) for the user.

        Args:
            user: User to create the tokens for.
            additional_claims: Optional additional claims to include in the access token.

        Returns:
            TokenPair containing both access and refresh tokens with metadata.

        """
        access_token = self.create_access_token(user, additional_claims)
        refresh_token = self.create_refresh_token(user)

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self.config.access_token_expire_minutes * 60,
        )

    def _encode_jwt_token(self, payload: Claims) -> TokenString:
        """Encode JWT token from payload.

        Args:
            payload: Claims dictionary to encode.

        Returns:
            Encoded JWT token string.

        """
        key = self._get_signing_key()
        return str(jwt.encode(payload, key, algorithm=self.config.algorithm))

    def _decode_jwt_token(self, token: TokenString) -> ValidationResult:
        """Decode JWT token and return validation result.

        Args:
            token: JWT token string to decode.

        Returns:
            ValidationResult with decoded claims on success or error info on failure.

        """
        try:
            key = self._get_verification_key()
            decoded: Claims = jwt.decode(
                token,
                key,
                algorithms=[self.config.algorithm],
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=timedelta(seconds=self.config.leeway_seconds),
                options={
                    "verify_signature": self.config.verify_signature,
                    "verify_exp": self.config.verify_exp,
                    "verify_aud": self.config.verify_aud,
                    "require_exp": self.config.require_exp,
                },
            )
            # Create success result with data attribute
            return ValidationResult(success=True, data=decoded)
        except Exception as e:
            self._handle_jwt_exceptions(e)
            # This line shouldn't be reached due to _handle_jwt_exceptions raising
            return ValidationResult(success=False, error=str(e))

    def _validate_token_type(self, claims: Claims, expected_type: str) -> None:
        if claims.get("token_type") != expected_type:
            msg = f"Invalid token type. Expected {expected_type}"
            raise jwt.InvalidTokenError(msg)

    async def _check_token_blacklist(self, claims: Claims) -> None:
        if self.storage:
            token_id = claims.get("jti")
            if token_id and await self.storage.is_blacklisted(token_id):
                msg = "Token has been revoked"
                raise jwt.InvalidTokenError(msg)

    def _handle_jwt_exceptions(self, exc: Exception) -> None:
        """Handle JWT exceptions and convert to InvalidTokenError with specific messages."""
        if isinstance(exc, jwt.ExpiredSignatureError):
            msg = "Token has expired"
        elif isinstance(exc, jwt.InvalidAudienceError):
            msg = "Invalid audience"
        elif isinstance(exc, jwt.InvalidIssuerError):
            msg = "Invalid issuer"
        elif isinstance(exc, jwt.InvalidSignatureError):
            msg = "Invalid token signature"
        elif isinstance(exc, jwt.DecodeError):
            msg = "Malformed token"
        elif isinstance(
            exc,
            ValueError
            | TypeError
            | RuntimeError
            | ImportError
            | KeyError
            | AttributeError,
        ):
            # ZERO TOLERANCE - Specific exception types for JWT token validation failures
            msg = f"Token validation failed: {exc}"
        else:
            msg = f"Unexpected token error: {exc}"

        raise jwt.InvalidTokenError(msg) from exc

    async def verify_token(
        self,
        token: TokenString,
        token_type: str = "access",
    ) -> Claims | None:
        """Verify and decode a JWT token.

        Args:
            token: The JWT token string to verify.
            token_type: Expected token type ('access' or 'refresh').

        Returns:
            Decoded token claims if valid, None if invalid.

        Raises:
            jwt.InvalidTokenError: If token verification fails.

        """
        try:
            # Decode and validate token
            decode_result = self._decode_jwt_token(token)

            if not decode_result.is_success:
                return None

            claims = decode_result.data

            # Ensure claims is not None before proceeding
            if claims is None:
                msg = "Token claims are None"
                raise ValueError(msg)

            # Validate token type
            self._validate_token_type(claims, token_type)

            # Check blacklist status
            await self._check_token_blacklist(claims)

        except jwt.InvalidTokenError:
            # Re-raise JWT errors as-is
            raise
        except (ValueError, TypeError, KeyError) as e:
            # Handle unexpected exceptions from cryptographic operations
            self._handle_jwt_exceptions(e)
            return None  # Explicit return for missing return statement
        else:
            return dict(claims)  # Explicit cast to ensure proper typing

    async def validate_token(
        self,
        token: TokenString,
        token_type: str = "access",
    ) -> ValidationResult:
        """Validate a JWT token and return a result object.

        Args:
            token: The JWT token string to validate.
            token_type: Expected token type ('access' or 'refresh').

        Returns:
            ValidationResult with success status and error message if failed.

        """
        try:
            claims = await self.verify_token(token, token_type)
            if claims is None:
                return ValidationResult(False, "Invalid token format or malformed token")
            return ValidationResult(True)
        except jwt.InvalidTokenError as e:
            return ValidationResult(False, f"Invalid token: {e}")

    async def refresh_tokens(self, refresh_token: TokenString, user: User) -> TokenPair:
        """Refresh tokens using a valid refresh token.

        Args:
            refresh_token: Valid refresh token to use for generating new tokens.
            user: User the token belongs to.

        Returns:
            New TokenPair with fresh access and refresh tokens.

        Raises:
            jwt.InvalidTokenError: If refresh token is invalid or doesn't belong to user.

        """
        # Verify refresh token
        claims = await self.verify_token(refresh_token, token_type="refresh")
        if not claims:
            msg = "Invalid refresh token"
            raise jwt.InvalidTokenError(msg)

        # Verify user matches
        if claims.get("sub") != str(user.user_id):
            msg = "Token does not belong to user"
            raise jwt.InvalidTokenError(msg)

        # Revoke old refresh token
        if self.storage:
            await self.storage.revoke_token(claims["jti"])

        # Create new token pair
        return self.create_token_pair(user)

    def refresh_token(
        self,
        _refresh_token: TokenString,
        user: User,
    ) -> tuple[TokenString, TokenString] | None:
        """Synchronous version of token refresh (simplified).

        Args:
            _refresh_token: Refresh token (not validated in this simplified version).
            user: User to create new tokens for.

        Returns:
            Tuple of (new_access_token, new_refresh_token) on success, None on failure.

        """
        try:
            # This is a simplified sync version - in production use async version
            new_access = self.create_access_token(user)
            new_refresh = self.create_refresh_token(user)
        except (jwt.InvalidTokenError, ValueError, TypeError, RuntimeError):
            return None
        else:
            return (new_access, new_refresh)

    async def revoke_token(self, token: TokenString) -> None:
        """Revoke a JWT token to prevent further use.

        Args:
            token: JWT token string to revoke.

        Raises:
            RuntimeError: If token storage is not configured.

        """
        if not self.storage:
            msg = "Token storage not configured for revocation"
            raise RuntimeError(msg)

        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            token_id = unverified.get("jti")
            if token_id:
                await self.storage.revoke_token(token_id)
        except (jwt.DecodeError, ValueError, TypeError, KeyError):
            # Invalid token format, ignore
            pass

    def extract_token_claims(self, token: TokenString) -> Claims | None:
        """Extract claims from a JWT token without signature verification.

        Args:
            token: JWT token string to extract claims from.

        Returns:
            Token claims dictionary if token is decodable, None otherwise.

        """
        try:
            decoded: dict[str, Any] = jwt.decode(
                token,
                options={"verify_signature": False},
            )
            return decoded
        except (jwt.DecodeError, ValueError, TypeError, KeyError):
            return None

    def _get_signing_key(self) -> str | bytes:
        if self.config.algorithm == "RS256":
            key = self.config.private_key
            return key if key is not None else ""
        key = self.config.secret_key
        return key if key is not None else ""

    def _get_verification_key(self) -> str | bytes:
        if self.config.algorithm == "RS256":
            key = self.config.public_key
            return key if key is not None else ""
        key = self.config.secret_key
        return key if key is not None else ""


# In-memory token storage for development


class JwtInMemoryTokenStorage:
    """JwtInMemoryTokenStorage - Service Layer.

    Implementa serviço de aplicação com lógica de negócio específica.
    Coordena operações complexas entre múltiplos componentes.

    Arquitetura: Service Layer Pattern
    Transações:
        Atomic operations with rollback
    Padrões: Application services, orchestration

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    store_token(): Método específico da classe
    get_token(): Obtém dados
    revoke_token(): Método específico da classe
    is_blacklisted(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    service = JwtInMemoryTokenStorage(config)
    result = await service.process(data)
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Service Layer Pattern estabelecidos no projeto.

    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenInfo] = {}
        self._blacklist: set[str] = set()

    async def store_token(self, token_info: TokenInfo) -> None:
        """Store token information in memory.

        Args:
            token_info: Token information to store including metadata.

        """
        # Convert UUID to string for dictionary key
        token_id_str = (
            str(token_info.token_id)
            if isinstance(token_info.token_id, UUID)
            else token_info.token_id
        )
        self._tokens[token_id_str] = token_info

    async def get_token(self, token_id: str) -> TokenInfo | None:
        """Retrieve token information by token ID from memory.

        Args:
            token_id: The unique token identifier.

        Returns:
            TokenInfo if found in memory, None otherwise.

        """
        return self._tokens.get(token_id)

    async def revoke_token(self, token_id: str) -> None:
        """Revoke a token by adding it to the blacklist.

        Args:
            token_id: The unique token identifier to revoke.

        """
        self._blacklist.add(token_id)
        if token_id in self._tokens:
            # TokenInfo is immutable, we need to replace it with a new instance
            token_info = self._tokens[token_id]
            # Create new TokenInfo with revoked_at set
            revoked_token_info = TokenInfo(
                token_id=token_info.token_id,
                user_id=token_info.user_id,
                token_type=token_info.token_type,
                issued_at=token_info.issued_at,
                expires_at=token_info.expires_at,
                revoked_at=datetime.now(UTC),
            )
            self._tokens[token_id] = revoked_token_info

    async def is_blacklisted(self, token_id: str) -> bool:
        """Check if a token is blacklisted (revoked).

        Args:
            token_id: The unique token identifier to check.

        Returns:
            True if the token is in the blacklist, False otherwise.

        """
        return token_id in self._blacklist
