"""Tests for FlextAuthTypes.

Tests the authentication types module following FLEXT standards.
"""

from __future__ import annotations

from flext_api import FlextApiTypes
from flext_tests import tm

from tests import t


class TestFlextAuthTypes:
    """Test FlextAuthTypes class and its nested type classes."""

    def test_inherits_from_flext_types(self) -> None:
        tm.that(t.__mro__, has=FlextApiTypes)

    def test_authentication_types_exist(self) -> None:
        tm.that(hasattr(t, "Auth"), eq=True)
        tm.that(hasattr(t.Auth, "UserManagement"), eq=True)
        tm.that(hasattr(t.Auth, "SessionManagement"), eq=True)
        tm.that(hasattr(t.Auth, "TokenManagement"), eq=True)
        tm.that(hasattr(t.Auth, "Authorization"), eq=True)
        tm.that(hasattr(t.Auth, "Security"), eq=True)

    def test_typed_dict_classes_exist(self) -> None:
        tm.that(hasattr(t.Auth.Responses, "AuthenticationPayload"), eq=True)

    def test_project_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Project"), eq=True)
        tm.that(hasattr(t.Auth.Project, "ProjectType"), eq=True)
        # AuthProjectConfig was removed; ProjectType remains

    def test_providers_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Providers"), eq=True)
        tm.that(hasattr(t.Auth.Providers, "Capability"), eq=True)
        tm.that(hasattr(t.Auth.Providers, "Key"), eq=True)

    def test_credentials_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Credentials"), eq=True)

    def test_tokens_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Tokens"), eq=True)
        tm.that(hasattr(t.Auth.Tokens, "Claims"), eq=True)
        tm.that(hasattr(t.Auth.Tokens, "Introspection"), eq=True)

    def test_sessions_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Sessions"), eq=True)
        tm.that(hasattr(t.Auth.Sessions, "Activity"), eq=True)

    def test_responses_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Responses"), eq=True)
        tm.that(hasattr(t.Auth.Responses, "AuthenticationPayload"), eq=True)

    def test_managers_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Managers"), eq=True)
        tm.that(hasattr(t.Auth.Managers, "UserData"), eq=True)
        tm.that(hasattr(t.Auth.Managers, "SessionData"), eq=True)
        tm.that(hasattr(t.Auth.Managers, "LogEntry"), eq=True)
        tm.that(hasattr(t.Auth.Managers, "AuditEntry"), eq=True)
        tm.that(hasattr(t.Auth.Managers, "AttemptData"), eq=True)
        tm.that(hasattr(t.Auth.Managers, "AttemptWindow"), eq=True)

    def test_domain_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "Domain"), eq=True)
        tm.that(hasattr(t.Auth.Domain, "ProviderType"), eq=True)
        tm.that(hasattr(t.Auth.Domain, "Role"), eq=True)
        tm.that(hasattr(t.Auth.Domain, "Permission"), eq=True)

    def test_token_management_types_exist(self) -> None:
        tm.that(hasattr(t.Auth, "TokenManagement"), eq=True)
        tm.that(hasattr(t.Auth, "Tokens"), eq=True)
        tm.that(hasattr(t.Auth.Tokens, "Claims"), eq=True)
        tm.that(hasattr(t.Auth.Tokens, "Introspection"), eq=True)
