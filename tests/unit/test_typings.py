"""Tests for FlextAuthTypes.

Tests the authentication types module following FLEXT standards.
"""

from __future__ import annotations

from flext_api import FlextApiTypes
from flext_auth import FlextAuthTypes as t_auth


class TestFlextAuthTypes:
    """Test FlextAuthTypes class and its nested type classes."""

    def test_inherits_from_flext_types(self) -> None:
        assert issubclass(t_auth, FlextApiTypes)

    def test_authentication_types_exist(self) -> None:
        assert hasattr(t_auth, "Auth")
        assert hasattr(t_auth, "UserManagement")
        assert hasattr(t_auth, "SessionManagement")
        assert hasattr(t_auth, "TokenManagement")
        assert hasattr(t_auth, "Authorization")
        assert hasattr(t_auth, "Security")

    def test_typed_dict_classes_exist(self) -> None:
        assert hasattr(t_auth, "ProviderConfig")
        assert hasattr(t_auth.Auth.Responses, "Authentication")

    def test_provider_config_structure(self) -> None:
        config = t_auth.ProviderConfig(name="test", type="basic")
        assert config.name == "test"
        assert config.type == "basic"

    def test_project_types_exist(self) -> None:
        assert hasattr(t_auth, "Project")
        assert hasattr(t_auth.Project, "ProjectType")
        assert hasattr(t_auth.Project, "AuthProjectConfig")

    def test_providers_types_exist(self) -> None:
        assert hasattr(t_auth, "Providers")
        assert hasattr(t_auth.Auth.Providers, "Metadata")
        assert hasattr(t_auth.Auth.Providers, "Registration")

    def test_credentials_types_exist(self) -> None:
        assert hasattr(t_auth, "Credentials")
        assert hasattr(t_auth.Auth.Credentials, "Basic")
        assert hasattr(t_auth.Auth.Credentials, "MultiFactor")

    def test_tokens_types_exist(self) -> None:
        assert hasattr(t_auth, "Tokens")
        assert hasattr(t_auth.Auth.Tokens, "Claims")
        assert hasattr(t_auth.Auth.Tokens, "Introspection")

    def test_sessions_types_exist(self) -> None:
        assert hasattr(t_auth, "Sessions")
        assert hasattr(t_auth.Auth.Sessions, "Activity")

    def test_responses_types_exist(self) -> None:
        assert hasattr(t_auth, "Responses")
        assert hasattr(t_auth.Auth.Responses, "Authentication")
        assert hasattr(t_auth.Auth.Responses, "AuthenticationPayload")

    def test_managers_types_exist(self) -> None:
        assert hasattr(t_auth, "Managers")
        assert hasattr(t_auth.Auth.Managers, "UserData")
        assert hasattr(t_auth.Auth.Managers, "SessionData")
        assert hasattr(t_auth.Auth.Managers, "LogEntry")
        assert hasattr(t_auth.Auth.Managers, "AuditEntry")
        assert hasattr(t_auth.Auth.Managers, "AttemptData")
        assert hasattr(t_auth.Auth.Managers, "AttemptWindow")

    def test_domain_types_exist(self) -> None:
        assert hasattr(t_auth, "Domain")
        assert hasattr(t_auth.Auth.Domain, "ProviderType")
        assert hasattr(t_auth.Auth.Domain, "Role")
        assert hasattr(t_auth.Auth.Domain, "Permission")

    def test_oauth2_token_response(self) -> None:
        assert hasattr(t_auth, "OAuth2TokenResponse")
        annotations = t_auth.Auth.OAuth2TokenResponse.__annotations__
        assert "access_token" in annotations
        assert "token_type" in annotations
        assert "expires_in" in annotations

    def test_kerberos_ticket_data(self) -> None:
        assert hasattr(t_auth, "KerberosTicketData")
        annotations = t_auth.Auth.KerberosTicketData.__annotations__
        assert "ticket" in annotations
        assert "principal" in annotations
        assert "realm" in annotations

    def test_http_response_data(self) -> None:
        assert hasattr(t_auth, "HttpResponseData")
        annotations = t_auth.Auth.HttpResponseData.__annotations__
        assert "status_code" in annotations
        assert "headers" in annotations
        assert "body" in annotations
