"""Real-world usage examples demonstrating massive code reduction.

Shows side-by-side comparison of traditional vs FlextAuth anti-boilerplate approaches.
"""

import asyncio

from flext_auth import (
    flext_auth_create_auth_context,
    flext_auth_create_role_hierarchy,
    flext_auth_quick_start,
    flext_auth_validate_permissions,
)


def traditional_approach_example() -> None:
    """Traditional authentication setup - 50+ lines."""
    # This would typically require:

    # 1. Password hashing setup (10 lines)
    # 2. JWT configuration (15 lines)
    # 3. Database/repository setup (20 lines)
    # 4. Service layer configuration (15 lines)
    # 5. Error handling boilerplate (10 lines)
    # Total: ~70 lines


def flext_auth_approach_example():
    """FlextAuth approach - 1 line."""
    return flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)


async def traditional_user_registration() -> bool:
    """Traditional user registration with validation - 40+ lines."""
    # This would typically require:
    # 1. Email validation function (10 lines)
    # 2. Password strength checking (15 lines)
    # 3. User creation logic (10 lines)
    # 4. Error handling (5 lines)
    # Total: ~40 lines

    return False


async def flext_auth_registration():
    """FlextAuth registration - 1 method call."""
    auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    result = await auth.register_validated(
        "john_doe",
        "john@company.com",
        "SecurePassword123!",
        role="user",
    )

    return result.is_success


def traditional_permission_checking():
    """Traditional permission system - 30+ lines."""
    # This would typically require:
    # 1. Role definition (10 lines)
    # 2. Permission mapping (10 lines)
    # 3. Validation logic (10 lines)
    # Total: ~30 lines

    role_permissions = {
        "REDACTED_LDAP_BIND_PASSWORD": ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"],
        "user": ["read"],
    }

    def check_permission(user_role, required_permission):
        permissions = role_permissions.get(user_role, [])
        return required_permission in permissions

    return check_permission("REDACTED_LDAP_BIND_PASSWORD", "delete")


def flext_auth_permission_checking():
    """FlextAuth permission system - 2 lines."""
    hierarchy = flext_auth_create_role_hierarchy()
    return flext_auth_validate_permissions("REDACTED_LDAP_BIND_PASSWORD", "delete", hierarchy)


def traditional_auth_context():
    """Traditional auth context creation - 25+ lines."""
    # This would typically require:
    # 1. JWT decoding (8 lines)
    # 2. User lookup (7 lines)
    # 3. Permission calculation (10 lines)
    # Total: ~25 lines

    return {"user_id": "123", "role": "REDACTED_LDAP_BIND_PASSWORD"}


def flext_auth_auth_context():
    """FlextAuth auth context - 1 line."""
    # Create a sample token for demo
    from flext_auth import flext_auth_generate_jwt

    secret = "demo-secret-123456789012345678901234567890123456789012345678901234567890"
    token = flext_auth_generate_jwt(
        {"user_id": "123", "username": "demo", "role": "REDACTED_LDAP_BIND_PASSWORD"},
        secret=secret,
    )

    return flext_auth_create_auth_context(token, secret, include_permissions=True)


def middleware_comparison() -> None:
    """Middleware creation comparison."""
    # Traditional middleware: 40+ lines of authentication logic

    # FlextAuth middleware: 3 lines
    auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    from flext_auth import flext_auth_middleware_factory

    flext_auth_middleware_factory(auth)


async def complete_workflow_comparison() -> None:
    """Complete authentication workflow comparison."""
    # Traditional: 150+ lines total

    # FlextAuth: 8 lines total
    auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)  # 1 line

    result = await auth.register_validated(  # 1 method call
        "demo_user",
        "demo@example.com",
        "SecurePass123!",
        role="REDACTED_LDAP_BIND_PASSWORD",
    )

    if result.is_success:
        login = await auth.login_and_validate(
            "demo_user", "SecurePass123!",
        )  # 1 method call

        if login.is_success:
            token = login.data["token"]
            secret = auth._jwt_service._secret_key

            # Complete auth context with permissions
            flext_auth_create_auth_context(token, secret)  # 1 line

            # Permission check
            flext_auth_validate_permissions("REDACTED_LDAP_BIND_PASSWORD", "delete")  # 1 line


def practical_web_integration() -> None:
    """Practical web framework integration example."""
    # Setup auth in one line
    auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    # Create middleware factory
    from flext_auth import flext_auth_middleware_factory

    flext_auth_middleware_factory(auth)

    # Example request handler simulation
    class MockRequest:
        def __init__(self, token) -> None:
            self.headers = {"Authorization": f"Bearer {token}"}

    # This would integrate with FastAPI, Flask, Django, etc.


# =============================================================================
# ULTRA ANTI-BOILERPLATE EXAMPLES
# =============================================================================


def ultra_boilerplate_reduction_examples() -> None:
    """Demonstra a redução massiva de boilerplate."""
    # 1. One-liner setup completo - 1 linha vs 150+ linhas
    result = flext_auth_one_liner("demo_user", "demo@example.com", "SecurePass123!")

    # 2. API instantâneo - 1 linha vs 50+ linhas
    flext_auth_instant_api("my_service", "api")

    # 3. Token checking ultra-simples - 1 linha vs 30+ linhas
    if result.get("token"):
        flext_auth_check_token(result["token"])

    # 4. Factory functions - 1 linha vs 20+ linhas cada
    flext_auth_dev()
    flext_auth_prod()
    flext_auth_web()
    flext_auth_api()

    # 5. Web session from request - 1 linha vs 40+ linhas
    flext_auth_web_session({"username": "demo_user", "password": "SecurePass123!"})


def decorator_examples() -> None:
    """Demonstra uso de decorators anti-boilerplate."""

    # Decorators reduzem 15-25 linhas de verificação para 1 linha
    @flext_auth_required()
    def protected_endpoint(request, auth_context) -> str:
        return f"Hello {auth_context.get('username', 'User')}"

    @flext_auth_role_required(ADMIN_ROLE)
    def REDACTED_LDAP_BIND_PASSWORD_only_endpoint(request, auth_context) -> str:
        return "Admin dashboard content"

    @flext_auth_permission_required("delete")
    def delete_endpoint(request, auth_context) -> str:
        return "Item deleted successfully"


def mixin_examples() -> None:
    """Demonstra uso de mixins anti-boilerplate."""

    # Mixin adiciona capacidades auth com herança simples - reduz 50+ linhas
    class MyController(FlextAuthMixin):
        def handle_request(self, token) -> str:
            # 1 linha vs 10+ linhas
            user = self.get_current_user(token)
            if not user:
                return "Unauthorized"

            # 1 linha vs 15+ linhas
            if not self.check_permission(token, "read"):
                return "Forbidden"

            return f"Hello {user.get('username', 'User')}"

        def create_user_session_example(self, username, password):
            # 1 linha vs 20+ linhas
            return self.create_session(username, password)

    MyController()


def defaults_examples() -> None:
    """Demonstra uso de defaults ultra-simples."""
    # Configs prontos - 1 linha vs 10+ linhas cada

    # Payloads prontos - 1 linha vs 5+ linhas cada

    # Headers prontos - 1 linha vs 3+ linhas
    token = "sample.jwt.token"
    FlextAuthDefaults.auth_headers(token)
    FlextAuthDefaults.api_headers("sample-api-key")

    # Responses prontos - 1 linha vs 5+ linhas
    FlextAuthDefaults.error_response("Sample error")


def massive_reduction_summary() -> None:
    """Sumário da redução massiva de código."""
    traditional_lines = {
        "Setup completo": 150,
        "API creation": 50,
        "Token validation": 30,
        "Web session": 40,
        "Auth decorators": 75,  # 3 decorators × 25 linhas cada
        "Mixin capabilities": 50,
        "Config setup": 40,  # 4 configs × 10 linhas cada
        "Headers/responses": 20,
    }

    flext_lines = {
        "Setup completo": 1,  # flext_auth_one_liner()
        "API creation": 1,  # flext_auth_instant_api()
        "Token validation": 1,  # flext_auth_check_token()
        "Web session": 1,  # flext_auth_web_session()
        "Auth decorators": 3,  # 3 decorators
        "Mixin capabilities": 1,  # class MyController(FlextAuthMixin)
        "Config setup": 4,  # 4 factory functions
        "Headers/responses": 4,  # FlextAuthDefaults usage
    }

    total_traditional = sum(traditional_lines.values())
    total_flext = sum(flext_lines.values())
    ((total_traditional - total_flext) / total_traditional) * 100

    for feature in traditional_lines:
        trad = traditional_lines[feature]
        flext = flext_lines[feature]
        reduction = trad - flext
        (reduction / trad) * 100


async def main() -> None:
    """Run all comparison examples."""
    # Traditional vs FLEXT basic comparisons
    traditional_approach_example()
    flext_auth_approach_example()

    await traditional_user_registration()
    await flext_auth_registration()

    traditional_permission_checking()
    flext_auth_permission_checking()

    traditional_auth_context()
    flext_auth_auth_context()

    middleware_comparison()

    # Complete workflow
    await complete_workflow_comparison()

    # Web integration
    practical_web_integration()

    # ANTI-BOILERPLATE DEMONSTRATIONS
    ultra_boilerplate_reduction_examples()
    decorator_examples()
    mixin_examples()
    defaults_examples()
    massive_reduction_summary()


if __name__ == "__main__":
    asyncio.run(main())
