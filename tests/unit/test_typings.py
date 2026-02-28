"""Tests for FlextAuthTypes.

Tests the authentication types module following FLEXT standards.
"""

from __future__ import annotations

from flext_auth.typings import FlextAuthTypes as t_auth
from flext_core import t


class TestFlextAuthTypes:
    """Test FlextAuthTypes class and its nested type classes."""

    def test_inherits_from_flext_types(self) -> None:
        assert issubclass(t_auth, t)

    def test_authentication_types_exist(self) -> None:
        assert hasattr(t_auth, "Auth")
        assert hasattr(t_auth, "UserManagement")
        assert hasattr(t_auth, "SessionManagement")
        assert hasattr(t_auth, "TokenManagement")
        assert hasattr(t_auth, "Authorization")
        assert hasattr(t_auth, "Security")

    def test_typed_dict_classes_exist(self) -> None:
        assert hasattr(t_auth, "ProviderConfig")
        assert hasattr(t_auth.Responses, "Authentication")

    def test_provider_config_structure(self) -> None:
        config = t_auth.ProviderConfig(name="test", type="basic")
        assert config.name == "test"
        assert config.type == "basic"

    def test_authentication_response_structure(self) -> None:
        response = t_auth.Responses.Authentication(success=True, message="OK")
        assert response.success is True
        assert response.message == "OK"
        assert hasattr(t_auth, "UserDict")
        assert hasattr(t_auth, "SessionDict")
        assert hasattr(t_auth, "AuthenticationResponseDict")

    def test_user_dict_structure(self) -> None:
        user_dict = t_auth.UserDict
        annotations = user_dict.__annotations__
        assert "name" in annotations
        assert "contact" in annotations
        assert "full_name" in annotations
        assert "is_active" in annotations
        assert "roles" in annotations

    def test_session_dict_structure(self) -> None:
        session_dict = t_auth.SessionDict
        annotations = session_dict.__annotations__
        assert "identity_id" in annotations
        assert "session_token" in annotations
        assert "expires_at" in annotations
        assert "is_active" in annotations

    def test_authentication_response_dict_structure(self) -> None:
        response_dict = t_auth.AuthenticationResponseDict
        annotations = response_dict.__annotations__
        assert "success" in annotations
        assert "identity" in annotations
        assert "token" in annotations
        assert "message" in annotations
        assert "metadata" in annotations

    def test_project_types_exist(self) -> None:
        assert hasattr(t_auth, "Project")
        assert hasattr(t_auth.Project, "ProjectType")
        assert hasattr(t_auth.Project, "AuthProjectConfig")

    def test_providers_types_exist(self) -> None:
        assert hasattr(t_auth, "Providers")
        assert hasattr(t_auth.Providers, "Metadata")
        assert hasattr(t_auth.Providers, "Registration")

    def test_credentials_types_exist(self) -> None:
        assert hasattr(t_auth, "Credentials")
        assert hasattr(t_auth.Credentials, "Basic")
        assert hasattr(t_auth.Credentials, "MultiFactor")

    def test_tokens_types_exist(self) -> None:
        assert hasattr(t_auth, "Tokens")
        assert hasattr(t_auth.Tokens, "Claims")
        assert hasattr(t_auth.Tokens, "Introspection")

    def test_sessions_types_exist(self) -> None:
        assert hasattr(t_auth, "Sessions")
        assert hasattr(t_auth.Sessions, "Activity")

    def test_responses_types_exist(self) -> None:
        assert hasattr(t_auth, "Responses")
        assert hasattr(t_auth.Responses, "Authentication")
        assert hasattr(t_auth.Responses, "AuthenticationPayload")

    def test_managers_types_exist(self) -> None:
        assert hasattr(t_auth, "Managers")
        assert hasattr(t_auth.Managers, "UserData")
        assert hasattr(t_auth.Managers, "SessionData")
        assert hasattr(t_auth.Managers, "LogEntry")
        assert hasattr(t_auth.Managers, "AuditEntry")
        assert hasattr(t_auth.Managers, "AttemptData")
        assert hasattr(t_auth.Managers, "AttemptWindow")

    def test_domain_types_exist(self) -> None:
        assert hasattr(t_auth, "Domain")
        assert hasattr(t_auth.Domain, "ProviderType")
        assert hasattr(t_auth.Domain, "Role")
        assert hasattr(t_auth.Domain, "Permission")

    def test_oauth2_token_response(self) -> None:
        assert hasattr(t_auth, "OAuth2TokenResponse")
        annotations = t_auth.OAuth2TokenResponse.__annotations__
        assert "access_token" in annotations
        assert "token_type" in annotations
        assert "expires_in" in annotations

    def test_kerberos_ticket_data(self) -> None:
        assert hasattr(t_auth, "KerberosTicketData")
        annotations = t_auth.KerberosTicketData.__annotations__
        assert "ticket" in annotations
        assert "principal" in annotations
        assert "realm" in annotations

    def test_http_response_data(self) -> None:
        assert hasattr(t_auth, "HttpResponseData")
        annotations = t_auth.HttpResponseData.__annotations__
        assert "status_code" in annotations
        assert "headers" in annotations
        assert "body" in annotations
