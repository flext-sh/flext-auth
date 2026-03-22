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
        tm.that(hasattr(t_auth.Auth.Responses, "AuthenticationPayload"), eq=True)

    def test_project_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Project"), eq=True)
        tm.that(hasattr(t_auth.Project, "ProjectType"), eq=True)
        # AuthProjectConfig was removed; ProjectType remains

    def test_providers_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Providers"), eq=True)
        tm.that(hasattr(t_auth.Auth.Providers, "Capability"), eq=True)
        tm.that(hasattr(t_auth.Auth.Providers, "Key"), eq=True)

    def test_credentials_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Credentials"), eq=True)

    def test_tokens_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Tokens"), eq=True)
        tm.that(hasattr(t_auth.Auth.Tokens, "Claims"), eq=True)
        tm.that(hasattr(t_auth.Auth.Tokens, "Introspection"), eq=True)

    def test_sessions_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Sessions"), eq=True)
        tm.that(hasattr(t_auth.Auth.Sessions, "Activity"), eq=True)

    def test_responses_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "Responses"), eq=True)
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

    def test_token_management_types_exist(self) -> None:
        tm.that(hasattr(t_auth, "TokenManagement"), eq=True)
        tm.that(hasattr(t_auth.Auth, "Tokens"), eq=True)
        tm.that(hasattr(t_auth.Auth.Tokens, "Claims"), eq=True)
        tm.that(hasattr(t_auth.Auth.Tokens, "Introspection"), eq=True)
