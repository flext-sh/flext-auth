"""Security utilities with zero boilerplate using Python 3.13."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import ClassVar
from typing import Protocol
from typing import runtime_checkable

import jwt
from argon2 import PasswordHasher as Argon2Hasher
from argon2.exceptions import InvalidHash
from argon2.exceptions import VerificationError
from argon2.exceptions import VerifyMismatchError
from pydantic import Field

from flext_core.config import get_settings
from flext_auth.config import AuthSettings
from flext_core.domain.pydantic_base import DomainBaseModel
from flext_core.domain.pydantic_base import DomainValueObject

# Python 3.13 type alias for security types
Salt = bytes
Hash = str
Token = str


@runtime_checkable
class HashingProtocol(Protocol):
    """HashingProtocol - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    hash(): Método específico da classe
    verify(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = HashingProtocol()
    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    Protocol for password hashing implementations.

    """

    def hash(self, password: str) -> Hash:
        """Hash a password using secure algorithm.

        Args:
            password: Plain text password to hash.

        Returns:
            Hashed password string.

        """
        ...

    def verify(self, password: str, hash_str: Hash) -> bool:
        """Verify password against hash.

        Args:
            password: Plain text password to verify.
            hash_str: Hashed password to verify against.

        Returns:
            True if password matches hash, False otherwise.

        """
        ...


class PasswordHasher(DomainBaseModel):
    """PasswordHasher - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    time_cost (int): Atributo da classe.
    memory_cost (int): Atributo da classe.
    parallelism (int): Atributo da classe.
    hash_len (int): Atributo da classe.
    salt_len (int): Atributo da classe.
    _hasher (Argon2Hasher): Atributo da classe.

    Methods:
    -------
    hash(): Método específico da classe
    verify(): Método específico da classe
    needs_rehash(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = PasswordHasher()
    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    Advanced password hasher with zero boilerplate.

    """

    model_config: ClassVar = {"arbitrary_types_allowed": True}

    # Argon2 parameters for security
    time_cost: int = Field(default=2, description="Argon2 time cost parameter")
    memory_cost: int = Field(
        default=102400,
        description="Argon2 memory cost parameter (100 MB)",
    )
    parallelism: int = Field(default=8, description="Argon2 parallelism parameter")
    hash_len: int = Field(default=32, description="Hash length in bytes")
    salt_len: int = Field(default=16, description="Salt length in bytes")

    argon2_hasher: Argon2Hasher | None = Field(
        default=None,
        init=False,
        description="Argon2 hasher instance",
    )

    @property
    def _hasher(self) -> Argon2Hasher:
        if self.argon2_hasher is None:
            msg = "PasswordHasher not initialized. Call model_post_init first."
            raise RuntimeError(msg)
        return self.argon2_hasher

    def model_post_init(self, __context: object, /) -> None:
        """Initialize Argon2 hasher after model validation.

        Args:
            __context: Pydantic validation context (unused).

        """
        self.argon2_hasher = Argon2Hasher(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            salt_len=self.salt_len,
        )

    def hash(self, password: str) -> Hash:
        """Hash a password using Argon2.

        Args:
            password: Plain text password to hash.

        Returns:
            Argon2 hashed password string.

        """
        return self._hasher.hash(password)

    def verify(self, password: str, hash_str: Hash) -> bool:
        """Verify password against Argon2 hash.

        Args:
            password: Plain text password to verify.
            hash_str: Argon2 hash to verify against.

        Returns:
            True if password matches hash, False otherwise.

        """
        try:
            self._hasher.verify(hash_str, password)
        except (VerifyMismatchError, VerificationError, InvalidHash):
            return False
        else:
            return True

    def needs_rehash(self, hash_str: Hash) -> bool:
        """Check if hash needs to be updated with current parameters.

        Args:
            hash_str: Existing hash to check.

        Returns:
            True if hash should be updated, False otherwise.

        """
        try:
            return self._hasher.check_needs_rehash(hash_str)
        except InvalidHash:
            return True


class SecurityHeaders(DomainValueObject):
    """Security headers for gRPC/HTTP with automatic validation."""

    # Standard security headers
    x_content_type_options: str = Field(
        default="nosniff",
        description="Content type options header",
    )
    x_frame_options: str = Field(default="DENY", description="Frame options header")
    x_xss_protection: str = Field(
        default="1; mode=block",
        description="XSS protection header",
    )
    strict_transport_security: str = Field(
        default="max-age=31536000; includeSubDomains",
        description="HSTS header",
    )
    content_security_policy: str = Field(
        default="default-src 'self'",
        description="CSP header",
    )
    referrer_policy: str = Field(
        default="strict-origin-when-cross-origin",
        description="Referrer policy header",
    )
    permissions_policy: str = Field(
        default="geolocation=(), microphone=(), camera=()",
        description="Permissions policy header",
    )

    # Custom headers
    x_request_id: str = Field(
        default_factory=lambda: secrets.token_urlsafe(16),
        description="Request ID header",
    )
    x_correlation_id: str = Field(
        default_factory=lambda: secrets.token_urlsafe(16),
        description="Correlation ID header",
    )

    def to_dict(self) -> dict[str, str]:
        """Convert security headers to dictionary format.

        Returns:
            Dictionary containing all security headers.

        """
        return {
            "x-content-type-options": self.x_content_type_options,
            "x-frame-options": self.x_frame_options,
            "x-xss-protection": self.x_xss_protection,
            "strict-transport-security": self.strict_transport_security,
            "content-security-policy": self.content_security_policy,
            "referrer-policy": self.referrer_policy,
            "permissions-policy": self.permissions_policy,
            "x-request-id": self.x_request_id,
            "x-correlation-id": self.x_correlation_id,
        }


class TokenGenerator:
    """TokenGenerator - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    generate_token(): Método específico da classe
    generate_api_key(): Método específico da classe
    generate_refresh_token(): Método específico da classe
    constant_time_compare(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = TokenGenerator()
    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    Secure token generator using secrets module.

    """

    @staticmethod
    def generate_token(length: int = 32) -> Token:
        """Generate cryptographically secure token.

        Args:
            length: Length of token in bytes (default: 32).

        Returns:
            URL-safe base64 encoded token string.

        """
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_api_key() -> Token:
        """Generate API key with FLEXT prefix.

        Returns:
            API key string with 'flext_' prefix.

        """
        prefix = "flext"
        token = secrets.token_urlsafe(32)
        return f"{prefix}_{token}"

    @staticmethod
    def generate_refresh_token() -> Token:
        """Generate long-lived refresh token.

        Returns:
            URL-safe base64 encoded refresh token (64 bytes).

        """
        return secrets.token_urlsafe(64)

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """Compare strings in constant time to prevent timing attacks.

        Args:
            a: First string to compare.
            b: Second string to compare.

        Returns:
            True if strings are equal, False otherwise.

        """
        return secrets.compare_digest(a, b)


def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    to_encode = data.copy()
    config = get_settings(AuthSettings)

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=config.jwt.access_token_expire_minutes,
        )

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        config.jwt.secret_key.get_secret_value(),
        algorithm=config.jwt.algorithm,
    )
    return str(encoded_jwt)


def decode_jwt_token(
    token: str,
    secret_key: str,
    algorithm: str = "HS256",
) -> dict[str, Any] | None:
    try:
        result = jwt.decode(token, secret_key, algorithms=[algorithm])
        return dict(result) if result is not None else None
    except jwt.PyJWTError:
        return None


# Cryptographic utilities
def generate_secret_key(length: int = 32) -> bytes:
    return secrets.token_bytes(length)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_nonce() -> str:
    return secrets.token_hex(16)


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure token.

    Args:
        length: Length of the token in bytes.

    Returns:
        Hex-encoded token string (length * 2 characters).
    """
    return secrets.token_hex(length)


class SecurityManager:
    """Security manager that coordinates password hashing and token generation."""

    def __init__(self) -> None:
        """Initialize security manager with password hasher and token generator."""
        self.password_hasher = PasswordHasher()
        self.password_hasher.model_post_init(None)  # Initialize the Argon2 hasher
        self.token_generator = TokenGenerator()

    def hash_password(self, password: str) -> str:
        """Hash a password using the password hasher.

        Args:
            password: Plain text password to hash.

        Returns:
            Hashed password string.
        """
        return self.password_hasher.hash(password)

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain text password to verify.
            hashed_password: Hashed password to verify against.

        Returns:
            True if password matches hash, False otherwise.
        """
        return self.password_hasher.verify(password, hashed_password)

    def generate_token(self, length: int = 32) -> str:
        """Generate a secure token.

        Args:
            length: Length of the token in bytes.

        Returns:
            Hex-encoded token string.
        """
        return self.token_generator.generate_token(length)

    def generate_jwt(
        self, payload: dict[str, Any], secret: str, algorithm: str = "HS256"
    ) -> str:
        """Generate a JWT token.

        Args:
            payload: JWT payload data.
            secret: Secret key for signing.
            algorithm: Signing algorithm.

        Returns:
            Encoded JWT token string.
        """
        # TokenGenerator doesn't have generate_jwt, use create_access_token instead
        from flext_auth.security import create_access_token

        return create_access_token(payload)

    def verify_jwt(
        self, token: str, secret: str, algorithm: str = "HS256"
    ) -> dict[str, Any] | None:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify.
            secret: Secret key for verification.
            algorithm: Signing algorithm.

        Returns:
            Decoded payload if valid, None if invalid.
        """
        # TokenGenerator doesn't have verify_jwt, use decode_jwt_token instead
        from flext_auth.security import decode_jwt_token

        return decode_jwt_token(token, secret, algorithm)
