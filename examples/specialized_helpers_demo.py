"""Specialized Helpers Demo - FlextAuth Advanced Use Cases.

Demonstra os helpers especializados para casos avançados.
Cada helper elimina centenas de linhas de código.

NOVAS FUNCIONALIDADES:
- API Key Manager: Gestão completa com rotação automática
- Session Pool: Pool inteligente com limpeza automática
- Role Matrix: Hierarquia completa de roles/permissões
- Test Suite: Bateria automatizada de testes de validação
"""

import asyncio

# Imports from root namespace ONLY - FlextAuth pattern
from flext_auth import (
    FLEXT_AUTH_ADMIN,
    FLEXT_AUTH_USER,
    flext_auth_api_key_manager,
    flext_auth_dev,
    flext_auth_role_matrix,
    flext_auth_session_pool,
    flext_auth_test_suite,
)


def demo_api_key_manager() -> None:
    """Demo 1: API Key Manager com rotação automática."""
    # ANTES: 80+ linhas de gerenciamento manual de chaves
    # AGORA: 1 linha
    result = flext_auth_api_key_manager("service_123", "payment_api")

    if result.is_success:
        result.data["manager"]
        result.data["usage"]


def demo_session_pool() -> None:
    """Demo 2: Session Pool com limpeza automática."""
    # ANTES: 120+ linhas de gerenciamento manual de sessões
    # AGORA: 1 linha
    result = flext_auth_session_pool(max_sessions=3, cleanup_interval=60)

    if result.is_success:
        result.data["pool"]
        add_session = result.data["add_session"]
        get_sessions = result.data["get_sessions"]
        result.data["stats"]

        # Demo usage
        test_user = "user_123"

        # Add test sessions
        for i in range(4):  # Exceeds max to test auto-cleanup
            session_data = {
                "session_id": f"session_{i}",
                "created_at": f"2024-01-0{i + 1}T10:00:00Z",
                "expires_at": 1735689600.0 + (i * 3600),  # Different expiry times
                "user_agent": f"Browser{i}",
            }
            add_session(test_user, session_data)

        # Get current sessions
        current_sessions = get_sessions(test_user)

        for _session in current_sessions:
            pass


def demo_role_matrix() -> None:
    """Demo 3: Role Matrix com hierarquia completa."""
    # ANTES: 200+ linhas de setup manual de roles/permissões
    # AGORA: 1 linha
    custom_roles = {
        "superuser": ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD", "manage_system"],
        "api_service": ["read", "write", "api_access"],
    }

    result = flext_auth_role_matrix(custom_roles)

    if result.is_success:
        hierarchy = result.data["hierarchy"]
        result.data["matrix"]
        resolve_permissions = result.data["resolve_permissions"]
        result.data["can_access"]
        check_multiple = result.data["check_multiple"]

        for role in hierarchy:
            pass

        test_roles = [FLEXT_AUTH_USER, FLEXT_AUTH_ADMIN, "superuser"]
        for role in test_roles:
            resolve_permissions(role)

        # Bulk access check
        required_perms = ["read", "write", "delete"]
        check_multiple(FLEXT_AUTH_ADMIN, required_perms)


async def demo_test_suite() -> None:
    """Demo 4: Test Suite automatizada."""
    # ANTES: 300+ linhas de código de teste manual
    # AGORA: 1 linha
    auth_instance = flext_auth_dev()
    result = flext_auth_test_suite(auth_instance)

    if result.is_success:
        test_results = result.data["results"]

        coverage = test_results["coverage"]
        for _covered in coverage.values():
            pass

        for detail in test_results["details"]:
            "✅" if detail["success"] else "❌"


def demo_integration_workflow() -> None:
    """Demo 5: Workflow integrado usando múltiplos helpers."""
    # Step 1: Setup role matrix
    role_result = flext_auth_role_matrix()
    if not role_result.is_success:
        return

    # Step 2: Setup session pool
    pool_result = flext_auth_session_pool(max_sessions=5)
    if not pool_result.is_success:
        return

    # Step 3: Setup API key manager
    api_result = flext_auth_api_key_manager("integrated_service", "workflow_api")
    if not api_result.is_success:
        return

    # Integration complete

    # Show combined capabilities
    role_result.data["can_access"]
    add_session = pool_result.data["add_session"]
    api_result.data["usage"]["headers"]

    # Add a sample session
    sample_session = {
        "session_id": "integration_session_001",
        "created_at": "2024-01-01T12:00:00Z",
        "expires_at": 1735689600.0,
        "integration": True,
    }
    add_session("integration_user", sample_session)


def demo_code_reduction_metrics() -> None:
    """Demo 6: Métricas de redução de código."""
    traditional_lines = {
        "API Key Management": 80,
        "Session Pool Setup": 120,
        "Role Matrix Creation": 200,
        "Test Suite Implementation": 300,
        "Integration Workflow": 150,
    }

    flext_lines = {
        "API Key Management": 1,  # flext_auth_api_key_manager()
        "Session Pool Setup": 1,  # flext_auth_session_pool()
        "Role Matrix Creation": 1,  # flext_auth_role_matrix()
        "Test Suite Implementation": 1,  # flext_auth_test_suite()
        "Integration Workflow": 4,  # All helpers combined
    }

    total_traditional = 0
    total_flext = 0

    for feature in traditional_lines:
        trad = traditional_lines[feature]
        flext = flext_lines[feature]
        ((trad - flext) / trad) * 100

        total_traditional += trad
        total_flext += flext

    ((total_traditional - total_flext) / total_traditional) * 100


async def main() -> None:
    """Run all specialized helper demos."""
    # Individual demos
    demo_api_key_manager()
    demo_session_pool()
    demo_role_matrix()
    await demo_test_suite()
    demo_integration_workflow()
    demo_code_reduction_metrics()


if __name__ == "__main__":
    asyncio.run(main())
