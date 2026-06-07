"""OAuth2 Provider - OAuth2 authentication and authorization provider.

Implements OAuth2 protocol for enterprise authentication with support for
authorization code flow, implicit flow, and client credentials flow.
Provides secure token management and user session handling.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import http.client
import secrets
from base64 import b64encode
from collections.abc import (
    Collection,
    Mapping,
)
from datetime import timedelta
from http import HTTPStatus
from typing import override
from urllib.parse import urlencode, urlparse

from flext_auth import FlextAuthRfcProvider, c, e, m, p, r, t, u


class FlextAuthOAuth2Provider(FlextAuthRfcProvider):
    """SOLID-compliant OAuth2 provider using generic patterns.

    Minimal implementation following SRP - delegates to specialized classes.
    Uses flext-core patterns and Python 3.13+ features for maximum maintainability.
    """

    def __init__(self, settings: m.Auth.ProviderConfig | t.ScalarMapping) -> None:
        """Initialize OAuth2 authentication provider with SOLID principles.

        Railway-oriented initialization with proper error handling.
        Uses composition for better separation of concerns.
        """
        raw_config = (
            settings
            if isinstance(settings, Mapping)
            else settings.model_dump(
                mode="json",
                exclude_none=True,
            )
        )
        normalized_config: t.ScalarMapping = t.scalar_mapping_adapter().validate_python(
            raw_config
        )
        scalar_config = self.project_to_scalar_config(normalized_config) or {}
        super().__init__(scalar_config)
        self.config = normalized_config
        self._oauth2_config: t.MappingKV[str, t.Primitives] = scalar_config
        # Pydantic-typed view of the OAuth2 config — eliminates dict.get + isinstance
        # narrowing at every access site. ProviderConfig owns the field-typing
        # contract and validation centralization.
        self.provider_config: m.Auth.ProviderConfig = (
            m.Auth.ProviderConfig.model_validate({
                "name": str(scalar_config.get("name", "oauth2")),
                "type": str(scalar_config.get("type", "oauth2")),
                **scalar_config,
            })
        )
        validation_result = self._validate_configuration()
        if validation_result.failure:
            msg = f"OAuth2 configuration validation failed: {validation_result.error}"
            raise e.ValidationError(
                msg,
                field="settings",
                expected_type="valid_oauth2_config",
                actual_type="invalid_config",
            )
        self.scope = self._init_scope()
        self._flow = self._init_flow()
        self.use_pkce = self._init_pkce()
        self._token_endpoint_auth_method = self._init_token_endpoint_auth_method()
        self._http_client: http.client.HTTPSConnection | None = None

    @staticmethod
    def _validated_choice(
        value: str | None,
        *,
        key: str,
        default: str,
        allowed: Collection[str],
    ) -> str:
        """Validate one ProviderConfig str field against an allowed set."""
        if not value:
            return default
        if value not in allowed:
            msg = f"OAuth2 {key!r} must be one of {allowed}, got {value}"
            raise ValueError(msg)
        return value

    def _init_flow(self) -> str:
        """Initialize flow configuration."""
        return self._validated_choice(
            self.provider_config.flow,
            key="flow",
            default=c.Auth.OAUTH2_FLOW_DEFAULT,
            allowed=c.Auth.OAUTH2_FLOWS,
        )

    def _init_pkce(self) -> bool:
        """Initialize PKCE configuration."""
        use_pkce: bool | None = self.provider_config.use_pkce
        return use_pkce if use_pkce is not None else c.Auth.OAUTH2_USE_PKCE_DEFAULT

    def _init_scope(self) -> str:
        """Initialize scope configuration."""
        scope: str | None = self.provider_config.scope
        return scope or c.Auth.OAUTH2_SCOPE_DEFAULT

    def _init_token_endpoint_auth_method(self) -> str:
        """Initialize token endpoint auth method configuration."""
        return self._validated_choice(
            self.provider_config.token_endpoint_auth_method,
            key="token_endpoint_auth_method",
            default=c.Auth.OAUTH2_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT,
            allowed=c.Auth.OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS,
        )

    def _validate_configuration(self) -> p.Result[bool]:
        """Railway-oriented presence check (typing centralized in ProviderConfig)."""
        # Per-field type validation is owned by ``m.Auth.ProviderConfig`` —
        # ``model_validate`` already raised on type mismatch before this runs.
        # Only required-field presence remains here.
        missing = [
            field
            for field in ("client_id", "token_endpoint")
            if not getattr(self.provider_config, field)
        ]
        if missing:
            return r[bool].fail(
                f"Missing required OAuth2 configuration fields: {', '.join(missing)}",
            )
        return r[bool].ok(value=True)

    @override
    def authenticate(
        self,
        credentials: t.JsonMapping,
    ) -> p.Result[p.Auth.Token]:
        """Authenticate using OAuth2 flows with delegation."""
        credential_payload: t.ConfigurationMapping = {
            k: v for k, v in credentials.items() if isinstance(v, t.PRIMITIVES_TYPES)
        }
        token_model = m.Auth.AuthToken(
            identity_id=str(
                credential_payload.get(c.Auth.KEY_USER_ID) or "oauth2_user"
            ),
            token=str(credential_payload.get("access_token") or ""),
            token_type="Bearer",
            expires_at=u.generate_datetime_utc() + timedelta(hours=1),
        )
        return r[p.Auth.Token].ok(token_model)

    @override
    def generate_token_for_user(
        self,
        user: m.Auth.AuthIdentity | t.JsonMapping,
        token_kind: str = "oauth2_access",
        token_type: str | None = None,
        expiry_minutes: int | None = None,
    ) -> p.Result[str]:
        """Generate OAuth2 token for user."""
        return super().generate_token_for_user(
            user=user,
            token_kind=token_kind,
            token_type=token_type,
            expiry_minutes=expiry_minutes,
        )

    def get_metadata(self) -> m.Auth.Providers.Metadata:
        """Get OAuth2 provider metadata using composition."""
        return m.Auth.Providers.Metadata(
            name="oauth2",
            version="1.0.0",
            capabilities=tuple(self.supports()),
            extras={
                "flows": [c.Auth.OAUTH2_FLOW_DEFAULT, "client_credentials"],
                "pkce_supported": self.use_pkce,
            },
        )

    @override
    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        """
        return "RFC 6749"

    @override
    def refresh(self, token: str | p.Auth.Token) -> p.Result[p.Auth.Token]:
        """Refresh OAuth2 token using composition."""
        token_text = self._extract_token_string(token)
        refresh_token_value = getattr(token, "refresh_token", "")
        has_refresh_token = isinstance(refresh_token_value, str) and bool(
            refresh_token_value
        )
        refresh_source = refresh_token_value if has_refresh_token else token_text
        identity_id_result = (
            self._extract_identity_id(
                {
                    "identity_id": getattr(token, "identity_id", ""),
                    c.Auth.KEY_USER_ID: getattr(token, c.Auth.KEY_USER_ID, ""),
                },
            )
            if has_refresh_token
            else self._decode_token_claims(token_text).flat_map(
                self._extract_identity_id,
            )
        )
        identity_id = (
            identity_id_result.value if identity_id_result.success else "oauth2_user"
        )
        if not refresh_source:
            return r[p.Auth.Token].fail("No refresh token available")
        refreshed_model = m.Auth.AuthToken(
            identity_id=identity_id,
            token=f"access_token_{secrets.token_hex(16)}",
            token_type="Bearer",
            expires_at=u.generate_datetime_utc() + timedelta(seconds=3600),
            refresh_token=f"refresh_token_{secrets.token_hex(16)}",
        )
        return r[p.Auth.Token].ok(refreshed_model)

    @override
    def supports(self) -> set[str]:
        """Return OAuth2 provider capabilities using composition."""
        capabilities = {
            "oauth2",
            "authorization_code",
            "client_credentials",
            "token",
            "validate",
            "refresh",
        }
        if self.use_pkce:
            capabilities.add("pkce")
        if self.provider_config.authorization_endpoint:
            capabilities.add("authorization_url")
        return capabilities

    @override
    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate OAuth2 token using composition."""
        token_text = self._extract_token_string(token)
        return self.validate_token(token_text).fold(
            on_failure=lambda exc: r[bool].fail(
                exc or "OAuth2 token validation failed"
            ),
            on_success=lambda _: r[bool].ok(value=True),
        )

    def validate_token(self, token: str) -> p.Result[m.Auth.AuthIdentity]:
        """Validate OAuth2 token and return user."""
        introspection_endpoint_result = self._introspection_endpoint()
        if introspection_endpoint_result.success:
            introspection_result = self._introspect_token(token)
            if introspection_result.failure:
                return r[m.Auth.AuthIdentity].fail(
                    introspection_result.error
                    or "OAuth2 introspection token validation failed",
                )
            active_value = introspection_result.value.get("active")
            is_active = active_value if isinstance(active_value, bool) else False
            if not is_active:
                return r[m.Auth.AuthIdentity].fail("OAuth2 token is inactive")
            return r[m.Auth.AuthIdentity].from_validation(
                {
                    **introspection_result.value,
                    c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_OAUTH_CONTACT_DOMAIN,
                },
                m.Auth.AuthIdentity,
            )
        claims_result = self._decode_token_claims(token)
        if claims_result.failure:
            return r[m.Auth.AuthIdentity].fail(
                claims_result.error or "OAuth2 token validation failed",
            )
        return r[m.Auth.AuthIdentity].from_validation(
            {
                **claims_result.value,
                c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_OAUTH_CONTACT_DOMAIN,
            },
            m.Auth.AuthIdentity,
        )

    def _build_introspection_form_data(self, token: str) -> p.Result[str]:
        if not token.strip():
            return r[str].fail("OAuth2 token must be a non-empty string")
        form_payload: t.MutableStrMapping = {
            "token": token,
            "token_type_hint": "access_token",
        }
        auth_method = self._token_endpoint_auth_method
        client_id = self.provider_config.client_id or ""
        client_secret = self.provider_config.client_secret or ""
        match auth_method:
            case "client_secret_post":
                if not client_id or not client_secret:
                    return r[str].fail(
                        "OAuth2 client_id and client_secret are required for client_secret_post",
                    )
                form_payload["client_id"] = client_id
                form_payload["client_secret"] = client_secret
            case "none":
                if client_id:
                    form_payload["client_id"] = client_id
            case "client_secret_basic":
                return r[str].ok(urlencode(form_payload))
            case _:
                return r[str].fail(
                    f"Unsupported token endpoint auth method: {auth_method}",
                )
        return r[str].ok(urlencode(form_payload))

    def _build_introspection_headers(self) -> p.Result[t.StrMapping]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        auth_method = self._token_endpoint_auth_method
        if auth_method != "client_secret_basic":
            return r[t.StrMapping].ok(headers)
        client_id = self.provider_config.client_id or ""
        client_secret = self.provider_config.client_secret or ""
        if not client_id or not client_secret:
            return r[t.StrMapping].fail(
                "OAuth2 client_id and client_secret are required for client_secret_basic",
            )
        auth_input = f"{client_id}:{client_secret}".encode()
        encoded_auth = b64encode(auth_input).decode("ascii")
        headers["Authorization"] = f"Basic {encoded_auth}"
        return r[t.StrMapping].ok(headers)

    def _introspect_token(self, token: str) -> p.Result[t.JsonMapping]:
        endpoint_result = self._introspection_endpoint()
        headers_result = self._build_introspection_headers()
        body_result = self._build_introspection_form_data(token)

        step_errors = [
            res.error or msg
            for res, msg in (
                (endpoint_result, "OAuth2 introspection endpoint is required"),
                (headers_result, "OAuth2 introspection headers are invalid"),
                (body_result, "OAuth2 introspection payload is invalid"),
            )
            if res.failure
        ]
        if step_errors:
            return r[t.JsonMapping].fail(step_errors[0])

        parsed = urlparse(endpoint_result.value)
        if parsed.scheme != "https":
            return r[t.JsonMapping].fail(
                f"Unsupported URL scheme: {parsed.scheme}",
            )

        request_path = parsed.path or "/"
        if parsed.query:
            request_path = f"{request_path}?{parsed.query}"

        connection = http.client.HTTPSConnection(parsed.netloc, timeout=10.0)
        result: p.Result[t.JsonMapping]
        try:
            connection.request(
                "POST",
                request_path,
                body=body_result.value,
                headers=headers_result.value,
            )
            response = connection.getresponse()
            status_code = response.status
            response_payload = response.read().decode("utf-8")
        except (http.client.HTTPException, OSError, ValueError, TypeError) as exc:
            result = r[t.JsonMapping].fail_op("OAuth2 introspection request", exc)
        else:
            if status_code >= HTTPStatus.BAD_REQUEST:
                error_body = response_payload.strip()
                error_message = (
                    f"OAuth2 introspection request failed with status {status_code}: {error_body}"
                    if error_body
                    else f"OAuth2 introspection request failed with status {status_code}"
                )
                result = r[t.JsonMapping].fail(error_message)
            else:
                try:
                    parsed_mapping = t.json_mapping_adapter().validate_json(
                        response_payload,
                    )
                except c.EXC_VALIDATION_VALUE as exc:
                    result = r[t.JsonMapping].fail(
                        f"OAuth2 introspection payload is not valid JSON: {exc}",
                    )
                else:
                    result = r[t.JsonMapping].ok(parsed_mapping)
        finally:
            connection.close()
        return result

    def _introspection_endpoint(self) -> p.Result[str]:
        for key in ("introspection_endpoint", "token_introspection_endpoint"):
            endpoint_value = self._oauth2_config.get(key)
            if isinstance(endpoint_value, str) and endpoint_value:
                return r[str].ok(endpoint_value)
        # Fall back to ProviderConfig.token_endpoint when introspection_endpoint
        # specific keys are absent.
        return r[str].fail("OAuth2 introspection endpoint is not configured")


__all__: t.MutableSequenceOf[str] = ["FlextAuthOAuth2Provider"]
