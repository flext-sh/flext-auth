"""OAuth2 token introspection helpers."""

from __future__ import annotations

import http.client
from base64 import b64encode
from http import HTTPStatus
from urllib.parse import urlencode, urlparse

from flext_auth import c, m, p, r, t


class FlextAuthOAuth2Introspection:
    """OAuth2 token introspection helper owner."""

    _oauth2_config: t.MappingKV[str, t.Primitives]
    _token_endpoint_auth_method: str
    provider_config: m.Auth.ProviderConfig

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


__all__: list[str] = ["FlextAuthOAuth2Introspection"]
