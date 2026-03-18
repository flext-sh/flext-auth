"""Tests for FlextAuthTypes.

Tests the authentication types module following FLEXT standards.
"""

from __future__ import annotations

from flext_api import FlextApiTypes
from flext_tests import tm

from flext_auth import FlextAuthTypes as t_auth


class TestFlextAuthTypes:
    """Test FlextAuthTypes class and its nested type classes."""

    def test_inherits_from_flext_types(self) -> None:
        tm.that(FlextApiTypes in t_auth.__mro__, eq=True)

    def test_authentication_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Auth"), eq=True)
        tm.that(hasattr(t_auth, "UserManagement"), eq=True)
        tm.that(hasattr(t_auth, "SessionManagement"), eq=True)
        tm.that(hasattr(t_auth, "TokenManagement"), eq=True)
        tm.that(hasattr(t_auth, "Authorization"), eq=True)
        tm.that(hasattr(t_auth, "Security"), eq=True)

    def test_typed_dict_classes_exist(self) -> None:
        tm.that(hasattr(t_auth, "ProviderConfig"), eq=True)
        tm.that(hasattr(t_auth.Auth.Responses, "Authentication"), eq=True)

    def test_provider_config_structure(self) -> None:
        config = t_auth.ProviderConfig(name="test", type="basic")
        tm.that(config.name, eq="test")
        tm.that(config.type, eq="basic")

    def test_project_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Project"), eq=True)
        tm.that(hasattr(t_auth.Project, "ProjectType"), eq=True)
        tm.that(hasattr(t_auth.Project, "AuthProjectConfig"), eq=True)

    def test_providers_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Providers"), eq=True)
        tm.that(hasattr(t_auth.Auth.Providers, "Metadata"), eq=True)
        tm.that(hasattr(t_auth.Auth.Providers, "Registration"), eq=True)

    def test_credentials_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Credentials"), eq=True)
        tm.that(hasattr(t_auth.Auth.Credentials, "Basic"), eq=True)
        tm.that(hasattr(t_auth.Auth.Credentials, "MultiFactor"), eq=True)

    def test_tokens_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Tokens"), eq=True)
        tm.that(hasattr(t_auth.Auth.Tokens, "Claims"), eq=True)
        tm.that(hasattr(t_auth.Auth.Tokens, "Introspection"), eq=True)

    def test_sessions_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Sessions"), eq=True)
        tm.that(hasattr(t_auth.Auth.Sessions, "Activity"), eq=True)

    def test_responses_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Responses"), eq=True)
        tm.that(hasattr(t_auth.Auth.Responses, "Authentication"), eq=True)
        tm.that(hasattr(t_auth.Auth.Responses, "AuthenticationPayload"), eq=True)

    def test_managers_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Managers"), eq=True)
        tm.that(hasattr(t_auth.Auth.Managers, "UserData"), eq=True)
        tm.that(hasattr(t_auth.Auth.Managers, "SessionData"), eq=True)
        tm.that(hasattr(t_auth.Auth.Managers, "LogEntry"), eq=True)
        tm.that(hasattr(t_auth.Auth.Managers, "AuditEntry"), eq=True)
        tm.that(hasattr(t_auth.Auth.Managers, "AttemptData"), eq=True)
        tm.that(hasattr(t_auth.Auth.Managers, "AttemptWindow"), eq=True)

    def test_domain_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Domain"), eq=True)
        tm.that(hasattr(t_auth.Auth.Domain, "ProviderType"), eq=True)
        tm.that(hasattr(t_auth.Auth.Domain, "Role"), eq=True)
        tm.that(hasattr(t_auth.Auth.Domain, "Permission"), eq=True)

    def test_oauth2_token_response(self) -> None:
        tm.that(hasattr(t_auth, "OAuth2TokenResponse"), eq=True)
        annotations = t_auth.Auth.OAuth2TokenResponse.__annotations__
        tm.that("access_token" in annotations, eq=True)
        tm.that("token_type" in annotations, eq=True)
        tm.that("expires_in" in annotations, eq=True)

    def test_kerberos_ticket_data(self) -> None:
        tm.that(hasattr(t_auth, "KerberosTicketData"), eq=True)
        annotations = t_auth.Auth.KerberosTicketData.__annotations__
        tm.that("ticket" in annotations, eq=True)
        tm.that("principal" in annotations, eq=True)
        tm.that("realm" in annotations, eq=True)

    def test_http_response_data(self) -> None:
        tm.that(hasattr(t_auth, "HttpResponseData"), eq=True)
        annotations = t_auth.Auth.HttpResponseData.__annotations__
        tm.that("status_code" in annotations, eq=True)
        tm.that("headers" in annotations, eq=True)
        tm.that("body" in annotations, eq=True)
