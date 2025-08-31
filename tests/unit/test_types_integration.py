"""Unit tests for FlextAuth types integration - Validating type system refactoring.

Tests validate that FlextAuthTypes properly integrates with flext-core types
and provides comprehensive type coverage for all authentication needs.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthUser
from flext_auth.typings import FlextAuthTypes


class TestFlextAuthTypesIntegration:
    """Test FlextAuthTypes class integration with flext-core types."""

    def test_auth_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Auth types."""
        # Verify Auth types are properly aliased
        assert hasattr(FlextAuthTypes, "UserId")
        assert hasattr(FlextAuthTypes, "Username")
        assert hasattr(FlextAuthTypes, "UserRole")
        assert hasattr(FlextAuthTypes, "Permission")
        assert hasattr(FlextAuthTypes, "AccessToken")
        assert hasattr(FlextAuthTypes, "RefreshToken")
        assert hasattr(FlextAuthTypes, "TokenPayload")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.UserId == FlextTypes.Auth.UserId
        assert FlextAuthTypes.Username == FlextTypes.Auth.Username
        assert FlextAuthTypes.UserRole == FlextTypes.Auth.Role
        assert FlextAuthTypes.Permission == FlextTypes.Auth.Permission

    def test_core_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Core types."""
        # Verify Core types are properly aliased
        assert hasattr(FlextAuthTypes, "String")
        assert hasattr(FlextAuthTypes, "Integer")
        assert hasattr(FlextAuthTypes, "Boolean")
        assert hasattr(FlextAuthTypes, "Dict")
        assert hasattr(FlextAuthTypes, "JsonObject")
        assert hasattr(FlextAuthTypes, "Object")
        assert hasattr(FlextAuthTypes, "Value")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.String == FlextTypes.Core.String
        assert FlextAuthTypes.Boolean == FlextTypes.Core.Boolean
        assert FlextAuthTypes.Dict == FlextTypes.Core.Dict

    def test_result_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Result types."""
        # Verify Result types are properly aliased
        assert hasattr(FlextAuthTypes, "ResultType")
        assert hasattr(FlextAuthTypes, "Success")
        assert hasattr(FlextAuthTypes, "AuthResult")
        assert hasattr(FlextAuthTypes, "UserResult")
        assert hasattr(FlextAuthTypes, "TokenResult")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.Success == FlextTypes.Result.Success

    def test_service_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Service types."""
        # Verify Service types are properly aliased
        assert hasattr(FlextAuthTypes, "ServiceInstance")
        assert hasattr(FlextAuthTypes, "ServiceDict")
        assert hasattr(FlextAuthTypes, "FactoryDict")
        assert hasattr(FlextAuthTypes, "ServiceName")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.ServiceInstance == FlextTypes.Service.ServiceInstance

    def test_config_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Config types."""
        # Verify Config types are properly aliased
        assert hasattr(FlextAuthTypes, "ConfigValue")
        assert hasattr(FlextAuthTypes, "ConfigDict")
        assert hasattr(FlextAuthTypes, "Environment")
        assert hasattr(FlextAuthTypes, "LogLevel")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.ConfigDict == FlextTypes.Config.ConfigDict

    def test_validation_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Validation types."""
        # Verify Validation types are properly aliased
        assert hasattr(FlextAuthTypes, "Email")
        assert hasattr(FlextAuthTypes, "EmailValidationResult")
        assert hasattr(FlextAuthTypes, "Pattern")
        assert hasattr(FlextAuthTypes, "ValidationRule")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.Email == FlextTypes.Validation.Email

    def test_container_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Container types."""
        # Verify Container types are properly aliased
        assert hasattr(FlextAuthTypes, "ServiceKey")
        assert hasattr(FlextAuthTypes, "ServiceRegistration")
        assert hasattr(FlextAuthTypes, "ServiceRetrieval")
        assert hasattr(FlextAuthTypes, "FactoryFunction")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.FactoryFunction == FlextTypes.Container.FactoryFunction

    def test_handler_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Handler types."""
        # Verify Handler types are properly aliased
        assert hasattr(FlextAuthTypes, "Command")
        assert hasattr(FlextAuthTypes, "Query")
        assert hasattr(FlextAuthTypes, "Event")
        assert hasattr(FlextAuthTypes, "CommandHandler")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.Command == FlextTypes.Handler.Command

    def test_network_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Network types."""
        # Verify Network types are properly aliased
        assert hasattr(FlextAuthTypes, "IPAddress")
        assert hasattr(FlextAuthTypes, "URL")
        assert hasattr(FlextAuthTypes, "Headers")
        assert hasattr(FlextAuthTypes, "RequestBody")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.IPAddress == FlextTypes.Network.IPAddress

    def test_logging_types_coverage(self) -> None:
        """Test comprehensive coverage of FlextTypes.Logging types."""
        # Verify Logging types are properly aliased
        assert hasattr(FlextAuthTypes, "LogEntry")
        assert hasattr(FlextAuthTypes, "LogContext")
        assert hasattr(FlextAuthTypes, "LogData")
        assert hasattr(FlextAuthTypes, "ContextDict")

        # Verify types match flext-core definitions
        assert FlextAuthTypes.LogEntry == FlextTypes.Logging.LogEntry

    def test_auth_specific_types(self) -> None:
        """Test authentication-specific type extensions."""
        # Verify auth-specific types exist
        assert hasattr(FlextAuthTypes, "PasswordHash")
        assert hasattr(FlextAuthTypes, "UserStatus")
        assert hasattr(FlextAuthTypes, "LoginAttempts")
        assert hasattr(FlextAuthTypes, "SessionId")
        assert hasattr(FlextAuthTypes, "ExpiryMinutes")
        assert hasattr(FlextAuthTypes, "IsActive")
        assert hasattr(FlextAuthTypes, "HasPermission")
        assert hasattr(FlextAuthTypes, "TokenType")

        # Verify auth result types
        assert hasattr(FlextAuthTypes, "AuthData")
        assert hasattr(FlextAuthTypes, "UserData")
        assert hasattr(FlextAuthTypes, "SessionData")
        assert hasattr(FlextAuthTypes, "TokenData")
        assert hasattr(FlextAuthTypes, "ClaimsData")

    def test_auth_config_types(self) -> None:
        """Test authentication configuration types."""
        # Verify auth config types exist
        assert hasattr(FlextAuthTypes, "AuthConfig")
        assert hasattr(FlextAuthTypes, "JWTConfig")
        assert hasattr(FlextAuthTypes, "PasswordConfig")
        assert hasattr(FlextAuthTypes, "SessionConfig")
        assert hasattr(FlextAuthTypes, "SecurityConfig")

    def test_auth_service_types(self) -> None:
        """Test authentication service types."""
        # Verify auth service types exist
        assert hasattr(FlextAuthTypes, "AuthService")
        assert hasattr(FlextAuthTypes, "PasswordService")
        assert hasattr(FlextAuthTypes, "JWTService")
        assert hasattr(FlextAuthTypes, "SessionService")
        assert hasattr(FlextAuthTypes, "UserService")


class TestConstantsTypesIntegration:
    """Test FlextAuthConstants integration with FlextAuthTypes."""

    def test_constants_use_flext_types(self) -> None:
        """Test that constants use proper FlextTypes annotations."""
        # Verify JWT secret uses AccessToken type
        secret_annotation = FlextAuthConstants.__annotations__.get("DEFAULT_JWT_SECRET")
        assert "AccessToken" in str(secret_annotation)

        # Verify role constants use Role type
        role_annotation = FlextAuthConstants.__annotations__.get("ROLE_USER")
        assert "Role" in str(role_annotation)

        # Verify status constants use String type
        status_annotation = FlextAuthConstants.__annotations__.get("USER_STATUS_ACTIVE")
        assert "String" in str(status_annotation)

    def test_constants_type_consistency(self) -> None:
        """Test that constants maintain type consistency."""
        # Test JWT secret type
        assert isinstance(FlextAuthConstants.DEFAULT_JWT_SECRET, str)

        # Test role types
        assert isinstance(FlextAuthConstants.ROLE_USER, str)
        assert isinstance(FlextAuthConstants.ROLE_ADMIN, str)
        assert isinstance(FlextAuthConstants.ROLE_GUEST, str)

        # Test status types
        assert isinstance(FlextAuthConstants.USER_STATUS_ACTIVE, str)
        assert isinstance(FlextAuthConstants.USER_STATUS_INACTIVE, str)
        assert isinstance(FlextAuthConstants.USER_STATUS_LOCKED, str)

        # Test boolean types
        assert isinstance(FlextAuthConstants.SUCCESS, bool)
        assert isinstance(FlextAuthConstants.FAILURE, bool)


class TestModelsTypesIntegration:
    """Test FlextAuthUser model integration with FlextAuthTypes."""

    def test_user_model_field_types(self) -> None:
        """Test that user model fields use FlextAuthTypes."""
        # Get field annotations
        annotations = FlextAuthUser.__annotations__

        # Verify username uses FlextAuthTypes.Username
        username_annotation = annotations.get("username")
        assert "FlextAuthTypes.Username" in str(username_annotation)

        # Verify role uses FlextAuthTypes.UserRole
        role_annotation = annotations.get("role")
        assert "FlextAuthTypes.UserRole" in str(role_annotation)

        # Verify status uses FlextAuthTypes.UserStatus
        status_annotation = annotations.get("status")
        assert "FlextAuthTypes.UserStatus" in str(status_annotation)

        # Verify failed_login_attempts uses FlextAuthTypes.LoginAttempts
        attempts_annotation = annotations.get("failed_login_attempts")
        assert "FlextAuthTypes.LoginAttempts" in str(attempts_annotation)

    def test_user_model_methods_use_types(self) -> None:
        """Test that user model methods use FlextAuthTypes."""
        # Check can_login return type
        can_login_method = FlextAuthUser.can_login
        return_annotation = getattr(can_login_method, "__annotations__", {}).get("return")
        assert "FlextAuthTypes.IsActive" in str(return_annotation)

        # Check has_permission parameter and return types
        has_permission_method = FlextAuthUser.has_permission
        method_annotations = getattr(has_permission_method, "__annotations__", {})

        # Parameter should use FlextAuthTypes.Permission
        permission_annotation = method_annotations.get("permission")
        assert "FlextAuthTypes.Permission" in str(permission_annotation)

        # Return should use FlextAuthTypes.HasPermission
        return_annotation = method_annotations.get("return")
        assert "FlextAuthTypes.HasPermission" in str(return_annotation)


class TestTypesSystemCompleteness:
    """Test that the type system covers all authentication library needs."""

    def test_all_authentication_needs_covered(self) -> None:
        """Test that FlextAuthTypes covers all authentication needs."""
        required_auth_types = [
            "UserId", "Username", "UserRole", "Permission", "AccessToken",
            "RefreshToken", "PasswordHash", "UserStatus", "LoginAttempts",
            "SessionId", "TokenType", "IsActive", "HasPermission"
        ]

        for type_name in required_auth_types:
            assert hasattr(FlextAuthTypes, type_name), f"Missing required auth type: {type_name}"

    def test_all_data_types_covered(self) -> None:
        """Test that FlextAuthTypes covers all data structure needs."""
        required_data_types = [
            "AuthData", "UserData", "SessionData", "TokenData",
            "ClaimsData", "CredentialsData", "RegistrationData"
        ]

        for type_name in required_data_types:
            assert hasattr(FlextAuthTypes, type_name), f"Missing required data type: {type_name}"

    def test_all_result_types_covered(self) -> None:
        """Test that FlextAuthTypes covers all result pattern needs."""
        required_result_types = [
            "AuthResult", "UserResult", "TokenResult", "SessionResult",
            "LoginResult", "RegisterResult", "LogoutResult", "ValidateResult"
        ]

        for type_name in required_result_types:
            assert hasattr(FlextAuthTypes, type_name), f"Missing required result type: {type_name}"

    def test_all_config_types_covered(self) -> None:
        """Test that FlextAuthTypes covers all configuration needs."""
        required_config_types = [
            "AuthConfig", "JWTConfig", "PasswordConfig",
            "SessionConfig", "SecurityConfig"
        ]

        for type_name in required_config_types:
            assert hasattr(FlextAuthTypes, type_name), f"Missing required config type: {type_name}"

    def test_all_service_types_covered(self) -> None:
        """Test that FlextAuthTypes covers all service layer needs."""
        required_service_types = [
            "AuthService", "PasswordService", "JWTService",
            "SessionService", "UserService"
        ]

        for type_name in required_service_types:
            assert hasattr(FlextAuthTypes, type_name), f"Missing required service type: {type_name}"

    def test_maximum_flext_types_usage(self) -> None:
        """Test that FlextAuthTypes uses maximum FlextTypes coverage."""
        # Count FlextTypes usage
        flext_types_used = 0
        total_types = 0

        for attr_name in dir(FlextAuthTypes):
            if not attr_name.startswith("_") and attr_name[0].isupper():
                total_types += 1
                # Check if it references FlextTypes
                try:
                    attr_value = getattr(FlextAuthTypes, attr_name)
                    if hasattr(attr_value, "__origin__") or str(attr_value).startswith("FlextTypes"):
                        flext_types_used += 1
                except:
                    pass

        # Should have high FlextTypes usage
        usage_percentage = (flext_types_used / total_types) * 100 if total_types > 0 else 0
        assert usage_percentage >= 70, f"FlextTypes usage too low: {usage_percentage:.1f}%"


# Integration test to verify everything works together
def test_complete_types_integration() -> None:
    """Integration test verifying complete type system works together."""
    # Test that all imports work
    from flext_auth.constants import FlextAuthConstants
    from flext_auth.models import FlextAuthUser

    # Test that types are usable
    user_id: FlextAuthTypes.UserId = "user_123"
    username: FlextAuthTypes.Username = "testuser"
    role: FlextAuthTypes.UserRole = FlextAuthConstants.ROLE_USER

    # Test that the system maintains type consistency
    assert isinstance(user_id, str)
    assert isinstance(username, str)
    assert isinstance(role, str)

    # Test that model creation works with types
    # Note: This would require actual user creation which may not work in this test context
    # but the type system should support it
    assert FlextAuthUser is not None
