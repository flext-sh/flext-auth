"""Security utilities with zero boilerplate using Python 3.13."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

import jwt
from argon2 import PasswordHasher as Argon2Hasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from flx_core.config.domain_config import get_config
from flx_core.domain.pydantic_base import DomainBaseModel, DomainValueObject
from pydantic import Field

# Python 3.13 type alias for security types
type Salt = bytes
type Hash = str
type Token = str


@runtime_checkable
class HashingProtocol(Protocol):
    r"""HashingProtocol - Framework Component.

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
    instance = HashingProtocol()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Protocol for password hashing implementations."""

    def hash(self, password: str) -> Hash:
        """Hash a password securely.

        Generates a secure hash of the provided password using
        industry-standard hashing algorithms with proper salting.

        Args:
        ----
            password: Plain text password to hash

        Returns:
        -------
            Hash: Secure hash string suitable for storage

        """
        ...

    def verify(self, password: str, hash_str: Hash) -> bool:
        """Verify password against hash.

        Verifies that the provided password matches the stored hash
        using secure comparison methods to prevent timing attacks.

        Args:
        ----
            password: Plain text password to verify
            hash_str: Stored hash to verify against

        Returns:
        -------
            bool: True if password matches hash, False otherwise

        """
        ...


class PasswordHasher(DomainBaseModel):
    r"""PasswordHasher - Framework Component.

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
    instance = PasswordHasher()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Advanced password hasher with zero boilerplate."""

    model_config = {"arbitrary_types_allowed": True}

    # Argon2 parameters for security
    time_cost: int = Field(default=2, description="Argon2 time cost parameter")
    memory_cost: int = Field(
        default=102400,
        description="Argon2 memory cost parameter (100 MB)",
    )
    parallelism: int = Field(default=8, description="Argon2 parallelism parameter")
    hash_len: int = Field(default=32, description="Hash length in bytes")
    salt_len: int = Field(default=16, description="Salt length in bytes")

    argon2_hasher: Argon2Hasher = Field(
        default=None,
        init=False,
        description="Argon2 hasher instance",
    )

    @property
    def _hasher(self) -> Argon2Hasher:
        """Backward compatibility property."""
        return self.argon2_hasher

    def model_post_init(self, __context: object) -> None:
        """Initialize Argon2 hasher with parameters."""
        self.argon2_hasher = Argon2Hasher(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            salt_len=self.salt_len,
        )

    def hash(self, password: str) -> Hash:
        """Hash password using Argon2id algorithm.

        Hashes the provided password using the Argon2id algorithm with
        enterprise-grade security parameters for memory-hard hashing
        resistant to GPU and ASIC attacks.

        Args:
        ----
            password: Plain text password to hash

        Returns:
        -------
            Argon2id hash string suitable for secure storage

        """
        return self._hasher.hash(password)

    def verify(self, password: str, hash_str: Hash) -> bool:
        """Verify password against stored hash.

        Verifies the provided plain text password against the stored
        Argon2id hash using constant-time comparison to prevent
        timing attacks.

        Args:
        ----
            password: Plain text password to verify
            hash_str: Stored Argon2id hash string

        Returns:
        -------
            True if password matches hash, False otherwise

        """
        try:
            self._hasher.verify(hash_str, password)
        except (VerifyMismatchError, VerificationError, InvalidHash):
            return False
        else:
            return True

    def needs_rehash(self, hash_str: Hash) -> bool:
        """Check if hash needs rehashing with updated parameters."""
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
        """Convert to dictionary for gRPC metadata."""
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
    r"""TokenGenerator - Framework Component.

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
    instance = TokenGenerator()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Secure token generator using secrets module."""

    @staticmethod
    def generate_token(length: int = 32) -> Token:
        """Generate cryptographically secure token."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_api_key() -> Token:
        """Generate API key with FLX prefix.

        Generates a cryptographically secure API key with the FLX prefix
        for easy identification and consistent formatting across the
        platform.

        Returns
        -------
            API key string with flx_ prefix and secure random token

        """
        prefix = "flx"
        token = secrets.token_urlsafe(32)
        return f"{prefix}_{token}"

    @staticmethod
    def generate_refresh_token() -> Token:
        """Generate cryptographically secure refresh token.

        Generates a long-lived refresh token using 64 bytes of
        cryptographically secure random data for JWT token refresh
        operations.

        Returns
        -------
            URL-safe base64 encoded refresh token string

        """
        return secrets.token_urlsafe(64)

    @staticmethod
    def constant_time_compare(a: str, b: str) -> bool:
        """Compare two strings in constant time."""
        return secrets.compare_digest(a, b)


def create_access_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """Create a new JWT access token."""
    to_encode = data.copy()
    config = get_config()

    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=config.secrets.jwt_access_token_expire_minutes,
        )

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        config.secrets.jwt_secret_key,
        algorithm=config.secrets.jwt_algorithm,
    )
    return encoded_jwt.decode("utf-8")


def decode_jwt_token(
    token: str, secret_key: str, algorithm: str = "HS256"
) -> dict[str, Any] | None:
    """Decode a JWT token and return its payload."""
    try:
        return jwt.decode(token, secret_key, algorithms=[algorithm])
    except jwt.PyJWTError:
        return None


# Cryptographic utilities
def generate_secret_key(length: int = 32) -> bytes:
    """Generate a URL-safe secret key."""
    return secrets.token_bytes(length)


def hash_token(token: str) -> str:
    """Hash a token using SHA256 for safe storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_nonce() -> str:
    """Generate a secure nonce for cryptographic operations."""
    return secrets.token_hex(16)
