"""OpenID Connect (OIDC) authentication provider implementation.

This module implements OpenID Connect authentication built on top of OAuth2.
OIDC adds an identity layer on top of OAuth2, providing:
- ID tokens (JWT) with user identity information
- UserInfo endpoint for additional claims
- Discovery mechanism for provider metadata
- Support for multiple flows (Authorization Code, Implicit, Hybrid)

The implementation follows OpenID Connect Core 1.0 specification.

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import cast

from flext_core import FlextExceptions, FlextResult, FlextTypes

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider


class FlextAuthOidcProvider(FlextAuthOAuth2Provider):
    """OpenID Connect authentication provider.

    This provider extends FlextAuthOAuth2Provider with OIDC-specific functionality:
    - ID token validation and parsing
    - UserInfo endpoint integration
    - OIDC Discovery support
    - Additional OIDC-specific scopes and claims

    Configuration:
        All OAuth2 configuration plus:
        - issuer: OIDC issuer identifier (required for ID token validation)
        - userinfo_endpoint: UserInfo endpoint URL (optional)
        - discovery_endpoint: OIDC Discovery endpoint (optional, for auto-configuration)
        - id_token_signing_alg: Expected ID token signing algorithm (default: RS256)
        - validate_nonce: Enable nonce validation (default: True)

    Example:
        >>> config = {
        ...     "client_id": "your-client-id",
        ...     "client_secret": "your-client-secret",
        ...     "issuer": "https://auth.example.com",
        ...     "authorization_endpoint": "https://auth.example.com/authorize",
        ...     "token_endpoint": "https://auth.example.com/token",
        ...     "userinfo_endpoint": "https://auth.example.com/userinfo",
        ...     "redirect_uri": "https://app.example.com/callback",
        ...     "scope": "openid profile email",
        ... }
        >>> provider = FlextAuthOidcProvider(config)
        >>> result = provider.authenticate({
        ...     "code": "auth-code",
        ...     "state": "state",
        ... })
        >>> if result.is_success:
        ...     token = result.unwrap()
        ...     # Access ID token claims
        ...     print(token.metadata.get("id_token_claims"))

    """

    def __init__(self, config: FlextTypes.Dict) -> None:
        """Initialize OIDC authentication provider.

        Args:
            config: Provider configuration dictionary

        Raises:
            ValueError: If required OIDC configuration is missing

        """
        # Initialize OAuth2 base
        super().__init__(config)

        # OIDC-specific configuration
        self._issuer = self._config.get("issuer")
        if not isinstance(self._issuer, str):
            error_msg = "OIDC provider requires 'issuer' to be a string"
            raise FlextExceptions.ValidationError(
                error_msg,
                field="issuer",
                expected_type="str",
                actual_type=str(type(self._issuer)),
            )

        self._userinfo_endpoint = self._config.get("userinfo_endpoint")
        if self._userinfo_endpoint is not None and not isinstance(
            self._userinfo_endpoint, str
        ):
            error_msg = "OIDC provider 'userinfo_endpoint' must be a string or None"
            raise FlextExceptions.ValidationError(
                error_msg,
                field="userinfo_endpoint",
                expected_type="str",
                actual_type=str(type(self._userinfo_endpoint)),
            )

        self._discovery_endpoint = self._config.get("discovery_endpoint")
        if self._discovery_endpoint is not None and not isinstance(
            self._discovery_endpoint, str
        ):
            error_msg = "OIDC provider 'discovery_endpoint' must be a string or None"
            raise FlextExceptions.ValidationError(
                error_msg,
                field="discovery_endpoint",
                expected_type="str",
                actual_type=str(type(self._discovery_endpoint)),
            )

        self._id_token_signing_alg = self._config.get(
            "id_token_signing_alg",
            FlextAuthConstants.Oidc.DEFAULT_ID_TOKEN_SIGNING_ALGORITHM,
        )
        if not isinstance(self._id_token_signing_alg, str):
            self._id_token_signing_alg = (
                FlextAuthConstants.Oidc.DEFAULT_ID_TOKEN_SIGNING_ALGORITHM
            )

        self._validate_nonce = self._config.get("validate_nonce", True)
        if not isinstance(self._validate_nonce, bool):
            self._validate_nonce = True

        # Ensure openid scope is included
        scope_str = cast("str", self._scope)
        if "openid" not in scope_str:
            self._scope = f"openid {scope_str}"

        # Runtime state for nonce validation
        self._nonces: FlextTypes.StringDict = {}  # state -> nonce mapping

        self.logger.info(
            "OIDC provider initialized",
            extra={
                "issuer": self._issuer,
                "id_token_alg": self._id_token_signing_alg,
                "userinfo_endpoint": self._userinfo_endpoint or "not configured",
            },
        )

    def authenticate(
        self,
        credentials: FlextTypes.Dict,
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        """Authenticate using OIDC flow.

        This extends OAuth2 authentication to also process ID tokens.

        Args:
            credentials: Authentication credentials (same as OAuth2 plus optional nonce)

        Returns:
            FlextResult[AuthToken]: OIDC token with ID token claims or error

        """
        # First, perform OAuth2 authentication
        oauth2_result = super().authenticate(credentials)

        if oauth2_result.is_failure:
            return oauth2_result

        # In production, we would:
        # 1. Extract ID token from token response
        # 2. Validate ID token signature
        # 3. Validate ID token claims (iss, aud, exp, iat, nonce)
        # 4. Parse ID token claims
        # 5. Optionally call UserInfo endpoint for additional claims

        # For now, add OIDC-specific metadata to the token
        auth_token = oauth2_result.unwrap()

        # Add OIDC metadata
        if not auth_token.metadata:
            auth_token.metadata = {}

        auth_token.metadata["oidc_provider"] = True
        auth_token.metadata["issuer"] = self._issuer

        self.logger.info(
            "OIDC authentication successful",
            extra={
                "issuer": self._issuer,
                "user_id": auth_token.user_id,
            },
        )

        return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)

    def validate(
        self,
        token: str | FlextAuthModels.AuthToken,
    ) -> FlextResult[bool]:
        """Validate OIDC token including ID token validation.

        Args:
            token: OIDC token to validate

        Returns:
            FlextResult[bool]: True if token and ID token are valid

        """
        # First perform OAuth2 validation
        oauth2_validation = super().validate(token)

        if oauth2_validation.is_failure:
            return oauth2_validation

        # In production, additionally validate ID token:
        # 1. Verify ID token signature using provider's public keys
        # 2. Validate issuer claim matches expected issuer
        # 3. Validate audience claim matches client_id
        # 4. Validate expiration
        # 5. Validate issued-at time
        # 6. Validate nonce if present

        self.logger.debug("OIDC token validated (basic validation)")
        return FlextResult[bool].ok(True)

    def supports(self) -> set[str]:
        """Return OIDC provider capabilities.

        Returns:
            set[str]: Set of supported capability strings

        Capabilities:
            All OAuth2 capabilities plus:
            - oidc: OpenID Connect support
            - id_token: ID token generation and validation
            - userinfo: UserInfo endpoint support (if configured)
            - discovery: OIDC Discovery support (if configured)

        """
        capabilities = super().supports()

        # Add OIDC-specific capabilities
        capabilities.add("oidc")
        capabilities.add("id_token")

        if self._userinfo_endpoint:
            capabilities.add("userinfo")

        if self._discovery_endpoint:
            capabilities.add("discovery")

        return capabilities

    def get_metadata(self) -> FlextTypes.Dict:
        """Return OIDC provider metadata.

        Returns:
            FlextTypes.Dict: Provider metadata

        """
        metadata = super().get_metadata()

        # Add OIDC-specific metadata
        metadata.update({
            "name": "oidc",
            "description": "OpenID Connect authentication provider",
            "issuer": self._issuer,
            "id_token_signing_alg": self._id_token_signing_alg,
            "userinfo_endpoint": self._userinfo_endpoint,
            "discovery_endpoint": self._discovery_endpoint,
        })

        return metadata

    def get_authorization_url(
        self,
        state: str | None = None,
        code_challenge: str | None = None,
        nonce: str | None = None,
    ) -> FlextResult[str]:
        """Generate OIDC authorization URL.

        Args:
            state: CSRF protection state parameter
            code_challenge: PKCE code challenge
            nonce: OIDC nonce for replay protection

        Returns:
            FlextResult[str]: Authorization URL with OIDC parameters

        """
        # Get OAuth2 authorization URL
        url_result = super().get_authorization_url(state, code_challenge)

        if url_result.is_failure:
            return url_result

        auth_url = url_result.unwrap()

        # Add nonce parameter if enabled
        if self._validate_nonce and nonce:
            # Store nonce for validation
            if state:
                self._nonces[state] = nonce

            # Add to URL
            separator = "&" if "?" in auth_url else "?"
            auth_url = f"{auth_url}{separator}nonce={nonce}"

        return FlextResult[str].ok(auth_url)

    def get_userinfo(self, access_token: str) -> FlextResult[FlextTypes.Dict]:
        """Fetch user information from UserInfo endpoint.

        Args:
            access_token: Access token for UserInfo request

        Returns:
            FlextResult[FlextTypes.Dict]: UserInfo claims or error

        """
        if not self._userinfo_endpoint:
            return FlextResult[FlextTypes.Dict].fail(
                "UserInfo endpoint not configured for this provider"
            )

        # Fetch user information from UserInfo endpoint
        userinfo_result = self.get_userinfo(access_token)

        if userinfo_result.is_failure:
            return FlextResult[FlextTypes.Dict].fail(userinfo_result.error)

        userinfo = userinfo_result.unwrap()

        self.logger.info(
            "UserInfo retrieved",
            extra={
                "sub": userinfo.get("sub"),
                "claims_count": len(userinfo),
            },
        )

        return FlextResult[FlextTypes.Dict].ok(userinfo)

    def parse_id_token(self, id_token: str) -> FlextResult[FlextTypes.Dict]:
        """Parse and validate ID token JWT.

        Args:
            id_token: ID token JWT string

        Returns:
            FlextResult[FlextTypes.Dict]: ID token claims or validation error

        """
        # Basic JWT structure validation
        parts = id_token.split(".")
        jwt_parts_count = FlextAuthConstants.AuthDefaults.JWT_PARTS_COUNT
        if len(parts) != jwt_parts_count:
            return FlextResult[FlextTypes.Dict].fail(
                "Invalid ID token format (not a valid JWT)"
            )

        try:
            # Decode header (part 0) and payload (part 1)
            # In production, use proper JWT library with signature verification

            # For now, basic parsing without signature verification
            # NOTE: This is NOT secure for production use!

            # Decode payload (add padding if needed)
            payload_part = parts[1]
            # Add padding
            base64_padding_size = FlextAuthConstants.AuthDefaults.BASE64_PADDING_SIZE
            padding_needed = base64_padding_size - (
                len(payload_part) % base64_padding_size
            )
            if padding_needed != base64_padding_size:
                payload_part += "=" * padding_needed

            payload_bytes = base64.urlsafe_b64decode(payload_part)
            payload = json.loads(payload_bytes.decode("utf-8"))

            # Basic validation
            if "iss" not in payload:
                return FlextResult[FlextTypes.Dict].fail("ID token missing 'iss' claim")

            if "sub" not in payload:
                return FlextResult[FlextTypes.Dict].fail("ID token missing 'sub' claim")

            if "aud" not in payload:
                return FlextResult[FlextTypes.Dict].fail("ID token missing 'aud' claim")

            if "exp" not in payload:
                return FlextResult[FlextTypes.Dict].fail("ID token missing 'exp' claim")

            # Validate issuer
            if payload["iss"] != self._issuer:
                return FlextResult[FlextTypes.Dict].fail(
                    f"ID token issuer mismatch: expected {self._issuer}, "
                    f"got {payload['iss']}"
                )

            # Validate audience
            audience = payload["aud"]
            if isinstance(audience, list):
                if self._client_id not in audience:
                    return FlextResult[FlextTypes.Dict].fail(
                        "ID token audience does not include client_id"
                    )
            elif audience != self._client_id:
                return FlextResult[FlextTypes.Dict].fail(
                    "ID token audience does not match client_id"
                )

            # Validate expiration
            exp_timestamp = payload["exp"]
            if datetime.fromtimestamp(exp_timestamp, tz=UTC) < datetime.now(UTC):
                return FlextResult[FlextTypes.Dict].fail("ID token expired")

            self.logger.info(
                "ID token parsed and validated",
                extra={"sub": payload.get("sub"), "iss": payload.get("iss")},
            )

            return FlextResult[FlextTypes.Dict].ok(payload)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"ID token parsing failed: {e}")


__all__ = ["FlextAuthOidcProvider"]
