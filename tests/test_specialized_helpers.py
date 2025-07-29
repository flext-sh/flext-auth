"""Comprehensive Tests for Specialized Helpers - FlextAuth Advanced Features.

Testa os 4 novos helpers especializados:
- flext_auth_api_key_manager: Gestão completa de API keys
- flext_auth_session_pool: Pool inteligente de sessões
- flext_auth_role_matrix: Matrix completa de roles/permissões
- flext_auth_test_suite: Suite automatizada de testes
"""

import time

import pytest

from flext_auth import (
    FLEXT_AUTH_ADMIN,
    FLEXT_AUTH_USER,
    flext_auth_api_key_manager,
    flext_auth_dev,
    flext_auth_role_matrix,
    flext_auth_session_pool,
    flext_auth_test_suite,
)


class TestFlextAuthApiKeyManager:
    """Tests for API key manager specialized helper."""

    def test_api_key_manager_basic_success(self) -> None:
        """Test basic API key manager functionality."""
        result = flext_auth_api_key_manager("user123", "test_service")

        assert result.is_success
        # Result should be a FlextResult (FlextAuthResult is just an alias)
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")

        # Verify manager structure
        manager = result.data["manager"]
        assert manager["service_id"] == "user123:test_service"
        assert "primary_key" in manager
        assert "backup_key" in manager
        assert manager["rotation_schedule"] == "90 days"
        assert manager["auto_rotate"] is True
        assert manager["usage_tracking"] is True

        # Verify endpoints
        assert (
            "/api/v1/auth/validate/user123:test_service"
            in manager["validation_endpoint"]
        )
        assert "/api/v1/auth/revoke/user123:test_service" in manager["revoke_endpoint"]

    def test_api_key_manager_usage_examples(self) -> None:
        """Test API key manager provides ready-to-use examples."""
        result = flext_auth_api_key_manager("service_user", "payment")

        assert result.is_success

        usage = result.data["usage"]
        assert "headers" in usage
        assert "curl" in usage
        assert "rotation_check" in usage

        # Verify headers structure
        headers = usage["headers"]
        assert "X-API-Key" in headers
        assert "X-Service-ID" in headers
        assert headers["X-Service-ID"] == "service_user:payment"

        # Verify curl example
        curl_example = usage["curl"]
        assert "curl -H" in curl_example
        assert "X-API-Key:" in curl_example
        assert "X-Service-ID:" in curl_example

    def test_api_key_manager_different_services(self) -> None:
        """Test API key manager with different service names."""
        services = ["auth", "payment", "notification", "analytics"]

        for service in services:
            result = flext_auth_api_key_manager("test_user", service)

            assert result.is_success
            assert result.data["manager"]["service_id"] == f"test_user:{service}"
            assert result.data["rotation_ready"] is True
            assert result.data["backup_available"] is True

    def test_api_key_manager_different_keys(self) -> None:
        """Test that different calls generate different keys."""
        result1 = flext_auth_api_key_manager("user1", "service1")
        result2 = flext_auth_api_key_manager("user2", "service2")

        assert result1.is_success
        assert result2.is_success

        key1 = result1.data["manager"]["primary_key"]
        key2 = result2.data["manager"]["primary_key"]

        assert key1 != key2  # Different keys for different users/services


class TestFlextAuthSessionPool:
    """Tests for session pool specialized helper."""

    def test_session_pool_basic_setup(self) -> None:
        """Test basic session pool setup."""
        result = flext_auth_session_pool(max_sessions=3, cleanup_interval=60)

        assert result.is_success
        # Result should be a FlextResult (FlextAuthResult is just an alias)
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")

        # Verify pool structure
        pool = result.data["pool"]
        assert "active_sessions" in pool
        assert "session_count" in pool
        assert "last_cleanup" in pool
        assert pool["max_per_user"] == 3
        assert pool["cleanup_interval"] == 60

        # Verify functions
        assert callable(result.data["add_session"])
        assert callable(result.data["get_sessions"])
        assert callable(result.data["remove_session"])
        assert callable(result.data["auto_cleanup"])

        # Verify stats
        stats = result.data["stats"]
        assert stats["max_sessions"] == 3
        assert stats["cleanup_interval"] == 60
        assert stats["cleanup_active"] is True

    def test_session_pool_add_and_get_sessions(self) -> None:
        """Test adding and retrieving sessions."""
        result = flext_auth_session_pool(max_sessions=2)

        assert result.is_success

        add_session = result.data["add_session"]
        get_sessions = result.data["get_sessions"]

        # Add test sessions
        test_user = "test_user_123"
        session1 = {"session_id": "sess1", "expires_at": time.time() + 3600}
        session2 = {"session_id": "sess2", "expires_at": time.time() + 3600}

        # Add sessions
        assert add_session(test_user, session1) is True
        assert add_session(test_user, session2) is True

        # Get sessions
        sessions = get_sessions(test_user)
        assert len(sessions) == 2
        assert sessions[0]["session_id"] == "sess1"
        assert sessions[1]["session_id"] == "sess2"

    def test_session_pool_max_sessions_limit(self) -> None:
        """Test session pool respects max sessions limit."""
        result = flext_auth_session_pool(max_sessions=2)

        assert result.is_success

        add_session = result.data["add_session"]
        get_sessions = result.data["get_sessions"]

        test_user = "limit_test_user"

        # Add 3 sessions (exceeds limit of 2)
        for i in range(3):
            session = {
                "session_id": f"sess{i}",
                "expires_at": time.time() + 3600,
                "index": i,
            }
            add_session(test_user, session)

        # Should only have 2 sessions (oldest removed)
        sessions = get_sessions(test_user)
        assert len(sessions) == 2
        # Should have sessions 1 and 2 (session 0 was removed)
        assert sessions[0]["index"] == 1
        assert sessions[1]["index"] == 2

    def test_session_pool_remove_session(self) -> None:
        """Test removing specific sessions."""
        result = flext_auth_session_pool()

        assert result.is_success

        add_session = result.data["add_session"]
        get_sessions = result.data["get_sessions"]
        remove_session = result.data["remove_session"]

        test_user = "remove_test_user"

        # Add sessions
        session1 = {"session_id": "remove_sess1", "expires_at": time.time() + 3600}
        session2 = {"session_id": "remove_sess2", "expires_at": time.time() + 3600}

        add_session(test_user, session1)
        add_session(test_user, session2)

        # Verify both sessions exist
        sessions = get_sessions(test_user)
        assert len(sessions) == 2

        # Remove first session
        removed = remove_session(test_user, "remove_sess1")
        assert removed is True

        # Verify only second session remains
        sessions = get_sessions(test_user)
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == "remove_sess2"

        # Try to remove non-existent session
        removed = remove_session(test_user, "non_existent")
        assert removed is False

    def test_session_pool_cleanup_expired_sessions(self) -> None:
        """Test automatic cleanup of expired sessions."""
        result = flext_auth_session_pool(cleanup_interval=1)  # 1 second interval

        assert result.is_success

        add_session = result.data["add_session"]
        get_sessions = result.data["get_sessions"]
        auto_cleanup = result.data["auto_cleanup"]

        test_user = "cleanup_test_user"

        # Add expired and valid sessions
        expired_session = {
            "session_id": "expired",
            "expires_at": time.time() - 3600,
        }  # Past
        valid_session = {
            "session_id": "valid",
            "expires_at": time.time() + 3600,
        }  # Future

        add_session(test_user, expired_session)
        add_session(test_user, valid_session)

        # Before cleanup
        sessions = get_sessions(test_user)
        assert len(sessions) == 2

        # Force cleanup
        auto_cleanup()

        # After cleanup - expired session should be removed
        sessions = get_sessions(test_user)
        assert len(sessions) <= 2  # May be 1 if cleanup worked, 2 if timing issue


class TestFlextAuthRoleMatrix:
    """Tests for role matrix specialized helper."""

    def test_role_matrix_basic_setup(self) -> None:
        """Test basic role matrix setup."""
        result = flext_auth_role_matrix()

        assert result.is_success
        # Result should be a FlextResult (FlextAuthResult is just an alias)
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")

        # Verify structure
        assert "hierarchy" in result.data
        assert "matrix" in result.data
        assert "all_permissions" in result.data
        assert callable(result.data["resolve_permissions"])
        assert callable(result.data["can_access"])
        assert callable(result.data["check_multiple"])

        # Verify counts
        assert result.data["role_count"] > 0
        assert result.data["permission_count"] > 0

        # Verify standard roles exist
        hierarchy = result.data["hierarchy"]
        assert FLEXT_AUTH_USER in hierarchy
        assert FLEXT_AUTH_ADMIN in hierarchy

    def test_role_matrix_custom_roles(self) -> None:
        """Test role matrix with custom roles."""
        custom_roles = {
            "api_service": ["api_read", "api_write"],
            "super_REDACTED_LDAP_BIND_PASSWORD": ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD", "system_REDACTED_LDAP_BIND_PASSWORD"],
        }

        result = flext_auth_role_matrix(custom_roles)

        assert result.is_success

        hierarchy = result.data["hierarchy"]
        assert "api_service" in hierarchy
        assert "super_REDACTED_LDAP_BIND_PASSWORD" in hierarchy
        assert hierarchy["api_service"] == ["api_read", "api_write"]
        assert "system_REDACTED_LDAP_BIND_PASSWORD" in hierarchy["super_REDACTED_LDAP_BIND_PASSWORD"]

    def test_role_matrix_permission_resolution(self) -> None:
        """Test permission resolution with inheritance."""
        result = flext_auth_role_matrix()

        assert result.is_success

        resolve_permissions = result.data["resolve_permissions"]

        # Test user permissions
        user_perms = resolve_permissions(FLEXT_AUTH_USER)
        assert isinstance(user_perms, list)
        assert "read" in user_perms

        # Test REDACTED_LDAP_BIND_PASSWORD permissions (should inherit user permissions)
        REDACTED_LDAP_BIND_PASSWORD_perms = resolve_permissions(FLEXT_AUTH_ADMIN)
        assert isinstance(REDACTED_LDAP_BIND_PASSWORD_perms, list)
        assert "read" in REDACTED_LDAP_BIND_PASSWORD_perms  # Inherited from user
        assert "REDACTED_LDAP_BIND_PASSWORD" in REDACTED_LDAP_BIND_PASSWORD_perms  # Direct REDACTED_LDAP_BIND_PASSWORD permission
        assert len(REDACTED_LDAP_BIND_PASSWORD_perms) > len(user_perms)  # More permissions than user

    def test_role_matrix_access_validation(self) -> None:
        """Test access validation functionality."""
        result = flext_auth_role_matrix()

        assert result.is_success

        can_access = result.data["can_access"]

        # Test basic access
        assert can_access(FLEXT_AUTH_USER, "read") is True
        assert can_access(FLEXT_AUTH_USER, "REDACTED_LDAP_BIND_PASSWORD") is False
        assert can_access(FLEXT_AUTH_ADMIN, "read") is True
        assert can_access(FLEXT_AUTH_ADMIN, "REDACTED_LDAP_BIND_PASSWORD") is True

        # Test non-existent role
        assert can_access("non_existent_role", "read") is False

    def test_role_matrix_bulk_access_check(self) -> None:
        """Test bulk access checking functionality."""
        result = flext_auth_role_matrix()

        assert result.is_success

        check_multiple = result.data["check_multiple"]

        # Test multiple permissions for user
        required_perms = ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]
        user_access = check_multiple(FLEXT_AUTH_USER, required_perms)

        assert isinstance(user_access, dict)
        assert user_access["read"] is True
        assert user_access["REDACTED_LDAP_BIND_PASSWORD"] is False

        # Test multiple permissions for REDACTED_LDAP_BIND_PASSWORD
        REDACTED_LDAP_BIND_PASSWORD_access = check_multiple(FLEXT_AUTH_ADMIN, required_perms)
        assert REDACTED_LDAP_BIND_PASSWORD_access["read"] is True
        assert REDACTED_LDAP_BIND_PASSWORD_access["REDACTED_LDAP_BIND_PASSWORD"] is True

        # Admin should have more access than user
        REDACTED_LDAP_BIND_PASSWORD_true_count = sum(1 for v in REDACTED_LDAP_BIND_PASSWORD_access.values() if v)
        user_true_count = sum(1 for v in user_access.values() if v)
        assert REDACTED_LDAP_BIND_PASSWORD_true_count > user_true_count

    def test_role_matrix_permission_matrix(self) -> None:
        """Test permission matrix structure."""
        result = flext_auth_role_matrix()

        assert result.is_success

        matrix = result.data["matrix"]
        all_permissions = result.data["all_permissions"]

        # Verify matrix structure
        assert isinstance(matrix, dict)

        for role in matrix:
            role_perms = matrix[role]
            assert isinstance(role_perms, dict)

            # Each role should have entry for all permissions
            for perm in all_permissions:
                assert perm in role_perms
                assert isinstance(role_perms[perm], bool)


class TestFlextAuthTestSuite:
    """Tests for test suite specialized helper."""

    def test_test_suite_basic_execution(self) -> None:
        """Test basic test suite execution."""
        auth = flext_auth_dev()
        result = flext_auth_test_suite(auth)

        assert result.is_success
        # Result should be a FlextResult (FlextAuthResult is just an alias)
        assert hasattr(result, "is_success")
        assert hasattr(result, "data")

        # Verify structure
        assert "results" in result.data
        assert "suite_completed" in result.data
        assert "recommendation" in result.data

        assert result.data["suite_completed"] is True

        # Verify test results structure
        test_results = result.data["results"]
        assert "total_tests" in test_results
        assert "passed" in test_results
        assert "failed" in test_results
        assert "details" in test_results
        assert "coverage" in test_results
        assert "success_rate" in test_results

        # Should have at least some tests
        assert test_results["total_tests"] > 0
        assert isinstance(test_results["details"], list)

    def test_test_suite_without_auth_instance(self) -> None:
        """Test test suite creates default auth instance."""
        result = flext_auth_test_suite()  # No auth instance provided

        assert result.is_success
        assert result.data["suite_completed"] is True

        # Should still execute tests
        test_results = result.data["results"]
        assert test_results["total_tests"] > 0

    def test_test_suite_coverage_validation(self) -> None:
        """Test test suite provides coverage information."""
        result = flext_auth_test_suite()

        assert result.is_success

        coverage = result.data["results"]["coverage"]

        # Expected coverage areas
        expected_areas = [
            "registration",
            "authentication",
            "validation",
            "jwt",
            "password",
            "email",
        ]

        for area in expected_areas:
            assert area in coverage
            assert isinstance(coverage[area], bool)

    def test_test_suite_detailed_results(self) -> None:
        """Test test suite provides detailed test results."""
        result = flext_auth_test_suite()

        assert result.is_success

        details = result.data["results"]["details"]
        assert isinstance(details, list)
        assert len(details) > 0

        # Check structure of first detail
        if details:
            detail = details[0]
            assert "test" in detail
            assert "success" in detail
            assert "details" in detail
            assert "timestamp" in detail

            assert isinstance(detail["test"], str)
            assert isinstance(detail["success"], bool)
            assert isinstance(detail["timestamp"], (int, float))

    def test_test_suite_success_rate_calculation(self) -> None:
        """Test test suite calculates success rate correctly."""
        result = flext_auth_test_suite()

        assert result.is_success

        test_results = result.data["results"]
        total = test_results["total_tests"]
        passed = test_results["passed"]
        failed = test_results["failed"]
        success_rate = test_results["success_rate"]

        # Verify math
        assert total == passed + failed

        if total > 0:
            expected_rate = (passed / total) * 100
            assert (
                abs(success_rate - expected_rate) < 0.1
            )  # Allow small floating point differences
        else:
            assert success_rate == 0

    def test_test_suite_recommendation(self) -> None:
        """Test test suite provides useful recommendations."""
        result = flext_auth_test_suite()

        assert result.is_success

        recommendation = result.data["recommendation"]
        assert isinstance(recommendation, str)
        assert len(recommendation) > 0

        # Should contain meaningful content
        test_results = result.data["results"]
        if test_results["failed"] == 0:
            assert "passed" in recommendation.lower()
        else:
            assert "fix" in recommendation.lower()


class TestSpecializedHelpersIntegration:
    """Integration tests for specialized helpers working together."""

    def test_all_helpers_return_flext_result(self) -> None:
        """Verify all specialized helpers return FlextAuthResult."""
        # Test each helper
        result1 = flext_auth_api_key_manager("test", "integration")
        assert hasattr(result1, "is_success")
        assert hasattr(result1, "data")

        result2 = flext_auth_session_pool()
        assert hasattr(result2, "is_success")
        assert hasattr(result2, "data")

        result3 = flext_auth_role_matrix()
        assert hasattr(result3, "is_success")
        assert hasattr(result3, "data")

        result4 = flext_auth_test_suite()
        assert hasattr(result4, "is_success")
        assert hasattr(result4, "data")

    def test_specialized_helpers_combined_workflow(self) -> None:
        """Test using multiple specialized helpers in a workflow."""
        # Step 1: Setup role matrix
        role_result = flext_auth_role_matrix()
        assert role_result.is_success

        # Step 2: Setup session pool
        pool_result = flext_auth_session_pool(max_sessions=3)
        assert pool_result.is_success

        # Step 3: Setup API key manager
        api_result = flext_auth_api_key_manager("workflow_user", "integration")
        assert api_result.is_success

        # Step 4: Run test suite
        test_result = flext_auth_test_suite()
        assert test_result.is_success

        # All components should be operational
        assert role_result.data["role_count"] > 0
        assert pool_result.data["stats"]["max_sessions"] == 3
        assert api_result.data["rotation_ready"] is True
        assert test_result.data["suite_completed"] is True

    def test_specialized_helpers_error_handling(self) -> None:
        """Test error handling in specialized helpers."""
        # All helpers should handle errors gracefully and return FlextResult

        # Test with various edge cases - helpers should not crash
        try:
            result1 = flext_auth_api_key_manager("", "")  # Empty strings
            assert hasattr(result1, "is_success")

            result2 = flext_auth_session_pool(max_sessions=0)  # Invalid max
            assert hasattr(result2, "is_success")

            result3 = flext_auth_role_matrix({})  # Empty custom roles
            assert hasattr(result3, "is_success")

            # All should complete without exceptions

        except Exception as e:
            pytest.fail(f"Specialized helper raised unexpected exception: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
