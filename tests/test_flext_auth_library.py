"""Testes robustos e abrangentes para a biblioteca flext-auth.

# Constants
EXPECTED_DATA_COUNT = 3

Testa TODAS as funcionalidades da interface pública única.
Garante que a redução massiva de código funciona perfeitamente.
"""

import asyncio
from collections.abc import Callable
from datetime import datetime

import pytest

from flext_auth import (
    FlextAuth,
    FlextAuthUser,
    flext_auth_create_secure_session,
    flext_auth_decode_jwt,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_middleware_factory,
    flext_auth_quick_start,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
)

EXPECTED_DATA_COUNT = 3


class TestFlextAuthClassePrincipal:
    """Testes para a classe principal FlextAuth."""

    @pytest.fixture
    def auth(self) -> FlextAuth:
        """Instância FlextAuth para testes."""
        return FlextAuth()

    @pytest.fixture
    def auth_with_config(self) -> FlextAuth:
        """Instância FlextAuth com configuração customizada."""
        config = {
            "jwt": {
                "secret_key": "test-secret-key-super-secure-123456789",
                "access_token_expire_minutes": 15,
            },
            "security": {
                "password_rounds": 4,  # Rápido para testes
                "max_failed_attempts": 2,
            },
        }
        return FlextAuth(config)

    @pytest.mark.asyncio
    async def test_registro_usuario_sucesso(self, auth: FlextAuth) -> None:
        """Testa registro de usuário com sucesso."""
        result = await auth.register("testuser", "test@example.com", "SecurePass123!")

        assert result.is_success
        assert result.data is not None
        if result.data.username != "testuser":
            raise AssertionError(f"Expected {'testuser'}, got {result.data.username}")
        assert result.data.email == "test@example.com"
        assert result.data.is_active()

    @pytest.mark.asyncio
    async def test_registro_usuario_duplicado(self, auth: FlextAuth) -> None:
        """Testa registro de usuário duplicado."""
        # Primeiro registro
        result1 = await auth.register("duplicate", "dup@example.com", "Pass123!")
        assert result1.is_success

        # Segundo registro (deve falhar)
        result2 = await auth.register("duplicate", "dup2@example.com", "Pass456!")
        assert not result2.is_success
        if "already exists" not in result2.error:
            raise AssertionError(f"Expected {'already exists'} in {result2.error}")

    @pytest.mark.asyncio
    async def test_login_sucesso(self, auth: FlextAuth) -> None:
        """Testa login com sucesso."""
        # Registra usuário
        await auth.register("loginuser", "login@example.com", "LoginPass123!")

        # Faz login
        result = await auth.login("loginuser", "LoginPass123!")

        assert result.is_success
        if "user" not in result.data:
            raise AssertionError(f"Expected {'user'} in {result.data}")
        assert "session" in result.data
        if "tokens" not in result.data:
            raise AssertionError(f"Expected {'tokens'} in {result.data}")
        if result.data["user"]["username"] != "loginuser":
            raise AssertionError(
                f"Expected {'loginuser'}, got {result.data['user']['username']}"
            )
        if "access_token" not in result.data["tokens"]:
            raise AssertionError(
                f"Expected {'access_token'} in {result.data['tokens']}"
            )
        assert "refresh_token" in result.data["tokens"]

    @pytest.mark.asyncio
    async def test_login_credenciais_invalidas(self, auth: FlextAuth) -> None:
        """Testa login com credenciais inválidas."""
        result = await auth.login("inexistente", "senha_errada")

        assert not result.is_success
        if "Invalid username or password" not in result.error:
            raise AssertionError(
                f"Expected {'Invalid username or password'} in {result.error}"
            )

    @pytest.mark.asyncio
    async def test_validacao_token_sucesso(self, auth: FlextAuth) -> None:
        """Testa validação de token válido."""
        # Setup: registra e faz login
        await auth.register("tokenuser", "token@example.com", "TokenPass123!")
        login_result = await auth.login("tokenuser", "TokenPass123!")
        token = login_result.data["tokens"]["access_token"]

        # Valida token
        result = await auth.validate(token)

        assert result.is_success
        if result.data["username"] != "tokenuser":
            raise AssertionError(
                f"Expected {'tokenuser'}, got {result.data['username']}"
            )
        if "user_id" not in result.data:
            raise AssertionError(f"Expected {'user_id'} in {result.data}")
        assert "role" in result.data
        if "session_id" not in result.data:
            raise AssertionError(f"Expected {'session_id'} in {result.data}")

    @pytest.mark.asyncio
    async def test_validacao_token_invalido(self, auth: FlextAuth) -> None:
        """Testa validação de token inválido."""
        result = await auth.validate("token_invalido_123")

        assert not result.is_success
        if "Token validation failed" not in result.error:
            raise AssertionError(
                f"Expected {'Token validation failed'} in {result.error}"
            )

    @pytest.mark.asyncio
    async def test_logout_sucesso(self, auth: FlextAuth) -> None:
        """Testa logout com sucesso."""
        # Setup
        await auth.register("logoutuser", "logout@example.com", "LogoutPass123!")
        login_result = await auth.login("logoutuser", "LogoutPass123!")
        token = login_result.data["tokens"]["access_token"]

        # Logout
        result = await auth.logout(token)

        assert result.is_success

        # Token deve estar inválido após logout
        validation = await auth.validate(token)
        assert not validation.is_success

    @pytest.mark.asyncio
    async def test_refresh_token_sucesso(self, auth: FlextAuth) -> None:
        """Testa refresh de token com sucesso."""
        # Setup
        await auth.register("refreshuser", "refresh@example.com", "RefreshPass123!")
        login_result = await auth.login("refreshuser", "RefreshPass123!")
        refresh_token = login_result.data["tokens"]["refresh_token"]

        # Add delay to ensure different timestamps

        await asyncio.sleep(1.0)

        # Refresh
        result = await auth.refresh(refresh_token)

        assert result.is_success
        if "access_token" not in result.data:
            raise AssertionError(f"Expected {'access_token'} in {result.data}")
        assert "refresh_token" in result.data
        # Tokens devem ser diferentes dos originais
        assert (
            result.data["access_token"] != login_result.data["tokens"]["access_token"]
        )

    @pytest.mark.asyncio
    async def test_mudanca_senha_sucesso(self, auth: FlextAuth) -> None:
        """Testa mudança de senha com sucesso."""
        # Setup
        await auth.register("passuser", "pass@example.com", "OldPass123!")
        login_result = await auth.login("passuser", "OldPass123!")
        user_id = login_result.data["user"]["id"]

        # Muda senha
        result = await auth.change_password(user_id, "OldPass123!", "NewPass456!")

        assert result.is_success

        # Testa login com nova senha
        new_login = await auth.login("passuser", "NewPass456!")
        assert new_login.is_success

        # Testa que senha antiga não funciona mais
        old_login = await auth.login("passuser", "OldPass123!")
        assert not old_login.is_success

    @pytest.mark.asyncio
    async def test_mudanca_senha_senha_atual_incorreta(self, auth: FlextAuth) -> None:
        """Testa mudança de senha com senha atual incorreta."""
        # Setup
        await auth.register("passuser2", "pass2@example.com", "CurrentPass123!")
        login_result = await auth.login("passuser2", "CurrentPass123!")
        user_id = login_result.data["user"]["id"]

        # Tenta mudar com senha atual errada
        result = await auth.change_password(user_id, "SenhaErrada!", "NewPass456!")

        assert not result.is_success
        if "incorrect" not in result.error.lower():
            raise AssertionError(f"Expected {'incorrect'} in {result.error.lower()}")

    @pytest.mark.asyncio
    async def test_listar_sessoes_usuario(self, auth: FlextAuth) -> None:
        """Testa listagem de sessões do usuário."""
        # Setup
        await auth.register("sessionuser", "session@example.com", "SessionPass123!")
        login_result = await auth.login("sessionuser", "SessionPass123!")
        user_id = login_result.data["user"]["id"]

        # Lista sessões
        result = await auth.get_user_sessions(user_id)

        assert result.is_success
        if len(result.data) != 1:
            raise AssertionError(f"Expected {1}, got {len(result.data)}")
        session = result.data[0]
        assert session["id"] is not None
        if session["status"] != "active":
            raise AssertionError(f"Expected {'active'}, got {session['status']}")
        if not (session["is_valid"]):
            raise AssertionError(f"Expected True, got {session['is_valid']}")

    @pytest.mark.asyncio
    async def test_limpeza_sessoes_expiradas(self, auth: FlextAuth) -> None:
        """Testa limpeza de sessões expiradas."""
        result = await auth.cleanup_sessions()

        assert result.is_success
        assert isinstance(result.data, int)  # Número de sessões limpas


class TestFlextAuthQuickStart:
    """Testes para o helper flext_auth_quick_start."""

    def test_quick_start_default(self: FlextAuth) -> None:
        """Testa quick start com configuração padrão."""
        auth = flext_auth_quick_start()

        assert isinstance(auth, FlextAuth)
        # Admin deve estar criado automaticamente (testamos com login)

        # Executa login assíncrono para verificar REDACTED_LDAP_BIND_PASSWORD
        async def verify_REDACTED_LDAP_BIND_PASSWORD() -> bool:
            result = await auth.login("REDACTED_LDAP_BIND_PASSWORD", "Admin123!")
            return result.is_success

        # Testa se REDACTED_LDAP_BIND_PASSWORD existe
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        REDACTED_LDAP_BIND_PASSWORD_exists = loop.run_until_complete(verify_REDACTED_LDAP_BIND_PASSWORD())
        loop.close()

        assert REDACTED_LDAP_BIND_PASSWORD_exists

    def test_quick_start_custom_REDACTED_LDAP_BIND_PASSWORD(self: FlextAuth) -> None:
        """Testa quick start com REDACTED_LDAP_BIND_PASSWORD customizado."""
        auth = flext_auth_quick_start(
            REDACTED_LDAP_BIND_PASSWORD_username="superREDACTED_LDAP_BIND_PASSWORD",
            REDACTED_LDAP_BIND_PASSWORD_email="super@REDACTED_LDAP_BIND_PASSWORD.com",
            REDACTED_LDAP_BIND_PASSWORD_password="SuperSecret123!",
        )

        assert isinstance(auth, FlextAuth)


class TestFlextAuthHelpers:
    """Testes para helpers utilitários."""

    def test_hash_password(self: FlextAuth) -> None:
        """Testa hash de senha."""
        password = "TestPassword123!"
        hashed = flext_auth_hash_password(password)

        assert hashed != ""
        assert hashed != password
        assert len(hashed) > 50  # Hash bcrypt típico
        assert hashed.startswith("$2b$")  # Formato bcrypt

    def test_hash_password_rounds_customizado(self: FlextAuth) -> None:
        """Testa hash com rounds customizado."""
        password = "TestPassword123!"
        hashed_4 = flext_auth_hash_password(password, rounds=4)
        hashed_12 = flext_auth_hash_password(password, rounds=12)

        assert hashed_4 != hashed_12
        if "$2b$04$" not in hashed_4:
            raise AssertionError(f"Expected {'$2b$04$'} in {hashed_4}")
        assert "$2b$12$" in hashed_12

    def test_verify_password_correto(self: FlextAuth) -> None:
        """Testa verificação de senha correta."""
        password = "CorrectPassword123!"
        hashed = flext_auth_hash_password(password)

        if not (flext_auth_verify_password(password, hashed)):
            raise AssertionError(
                f"Expected True, got {flext_auth_verify_password(password, hashed)}"
            )

    def test_verify_password_incorreto(self: FlextAuth) -> None:
        """Testa verificação de senha incorreta."""
        password = "CorrectPassword123!"
        wrong_password = "WrongPassword456!"
        hashed = flext_auth_hash_password(password)

        if flext_auth_verify_password(wrong_password, hashed):
            raise AssertionError(
                f"Expected False, got {flext_auth_verify_password(wrong_password, hashed)}"
            )

    def test_generate_jwt_basico(self: FlextAuth) -> None:
        """Testa geração básica de JWT."""
        payload = {"user_id": "123", "username": "test"}
        token = flext_auth_generate_jwt(payload)

        assert token != ""
        if len(token.split(".")) != EXPECTED_DATA_COUNT:  # Header.Payload.Signature
            raise AssertionError(f"Expected {3}, got {len(token.split('.'))}")

    def test_generate_jwt_com_expiracao(self: FlextAuth) -> None:
        """Testa geração de JWT com expiração customizada."""
        payload = {"user_id": "123", "username": "test"}
        token = flext_auth_generate_jwt(payload, expires_minutes=60)

        assert token != ""
        if len(token.split(".")) != EXPECTED_DATA_COUNT:
            raise AssertionError(f"Expected {3}, got {len(token.split('.'))}")

    def test_decode_jwt_valido(self: FlextAuth) -> None:
        """Testa decodificação de JWT válido."""
        secret = "test-secret-key-123456789"
        payload = {"user_id": "123", "username": "testuser", "role": "REDACTED_LDAP_BIND_PASSWORD"}

        token = flext_auth_generate_jwt(payload, secret=secret)
        decoded = flext_auth_decode_jwt(token, secret)

        assert decoded is not None
        if decoded["user_id"] != "123":
            raise AssertionError(f"Expected {'123'}, got {decoded['user_id']}")
        assert decoded["username"] == "testuser"
        if decoded["role"] != "REDACTED_LDAP_BIND_PASSWORD":
            raise AssertionError(f"Expected {'REDACTED_LDAP_BIND_PASSWORD'}, got {decoded['role']}")
        if "expires" not in decoded:
            raise AssertionError(f"Expected {'expires'} in {decoded}")
        assert "issued" in decoded

    def test_decode_jwt_invalido(self: FlextAuth) -> None:
        """Testa decodificação de JWT inválido."""
        decoded = flext_auth_decode_jwt("token.invalido.123", "secret")

        assert decoded is None

    def test_validate_email_validos(self: FlextAuth) -> None:
        """Testa validação de emails válidos."""
        emails_validos = [
            "user@example.com",
            "test.user@domain.co.uk",
            "REDACTED_LDAP_BIND_PASSWORD+test@empresa.com.br",
            "123@numbers.org",
        ]

        for email in emails_validos:
            assert flext_auth_validate_email(email) is True, (
                f"Email deveria ser válido: {email}"
            )

    def test_validate_email_invalidos(self: FlextAuth) -> None:
        """Testa validação de emails inválidos."""
        emails_invalidos = [
            "",
            "invalid",
            "@domain.com",
            "user@",
            "user@domain",
            "user@.com",
            "user.domain.com",
        ]

        for email in emails_invalidos:
            assert flext_auth_validate_email(email) is False, (
                f"Email deveria ser inválido: {email}"
            )

    def test_validate_password_strength_forte(self) -> None:
        """Testa validação de senha forte."""
        password = "MinhaPasswordMuitoSegura123!@#"
        result = flext_auth_validate_password_strength(password)

        if not (result["valid"]):
            raise AssertionError(f"Expected True, got {result['valid']}")
        if result["score"] < 4:
            raise AssertionError(f"Expected {result['score']} >= {4}")
        if result["strength"] not in {"strong", "very strong", "excellent"}:
            raise AssertionError(
                f"Expected {result['strength']} in {{'strong', 'very strong', 'excellent'}}"
            )
        if len(result["feedback"]) != 0:
            raise AssertionError(f"Expected {0}, got {len(result['feedback'])}")

    def test_validate_password_strength_fraca(self) -> None:
        """Testa validação de senha fraca."""
        password = "123"
        result = flext_auth_validate_password_strength(password)

        if result["valid"]:
            raise AssertionError(f"Expected False, got {result['valid']}")
        assert result["score"] < 4
        assert len(result["feedback"]) > 0  # Deve ter sugestões

    def test_create_secure_session(self) -> None:
        """Testa criação de sessão segura."""
        session = flext_auth_create_secure_session("user123", "joao", "REDACTED_LDAP_BIND_PASSWORD", 48)

        if session["user_id"] != "user123":
            raise AssertionError(f"Expected {'user123'}, got {session['user_id']}")
        assert session["username"] == "joao"
        if session["role"] != "REDACTED_LDAP_BIND_PASSWORD":
            raise AssertionError(f"Expected {'REDACTED_LDAP_BIND_PASSWORD'}, got {session['role']}")
        assert len(session["session_id"]) > 20  # Token seguro
        assert session["created_at"] is not None
        assert session["expires_at"] is not None
        if session["permissions"] != []:
            raise AssertionError(f"Expected {[]}, got {session['permissions']}")

        # Verifica se expires_at está no futuro
        created = datetime.fromisoformat(session["created_at"])
        expires = datetime.fromisoformat(session["expires_at"])
        assert expires > created

    def test_middleware_creator(self) -> None:
        """Testa criação de middleware."""
        auth = FlextAuth()
        middleware = flext_auth_middleware_factory(auth)

        assert callable(middleware)
        # O middleware retorna uma função
        middleware_func = middleware(lambda x: x)
        assert callable(middleware_func)


class TestFlextAuthCompatibilidade:
    """Testes para compatibilidade e warnings."""

    def test_deprecated_classes_emit_warnings(self) -> None:
        """Testa se classes depreciadas emitem warnings."""

        with pytest.warns(DeprecationWarning, match="FlextAuthUser is deprecated"):
            user = FlextAuthUser(
                id="test",
                username="test",
                email="test@example.com",
                password_hash="hash",
            )

        if user.username != "test":
            raise AssertionError(f"Expected {'test'}, got {user.username}")


class TestFlextAuthIntegracao:
    """Testes de integração end-to-end."""

    @pytest.mark.asyncio
    async def test_fluxo_completo_autenticacao(self) -> None:
        """Testa fluxo completo: registro -> login -> validação -> logout."""
        auth = FlextAuth()

        # 1. Registro
        register_result = await auth.register(
            "integracaouser",
            "integracao@example.com",
            "IntegracaoPass123!",
        )
        assert register_result.is_success

        # 2. Login
        login_result = await auth.login("integracaouser", "IntegracaoPass123!")
        assert login_result.is_success
        token = login_result.data["tokens"]["access_token"]

        # 3. Validação
        validate_result = await auth.validate(token)
        assert validate_result.is_success
        if validate_result.data["username"] != "integracaouser":
            raise AssertionError(
                f"Expected {'integracaouser'}, got {validate_result.data['username']}"
            )

        # 4. Logout
        logout_result = await auth.logout(token)
        assert logout_result.is_success

        # 5. Validação pós-logout (deve falhar)
        post_logout_validate = await auth.validate(token)
        assert not post_logout_validate.is_success

    @pytest.mark.asyncio
    async def test_multiplos_usuarios_simultaneos(self) -> None:
        """Testa múltiplos usuários simultâneos."""
        auth = FlextAuth()

        # Registra múltiplos usuários
        usuarios = []
        for i in range(5):
            username = f"user{i}"
            email = f"user{i}@example.com"
            password = f"Password{i}123!"

            result = await auth.register(username, email, password)
            assert result.is_success
            usuarios.append((username, password))

        # Login simultâneo
        sessions = []
        for username, password in usuarios:
            login_result = await auth.login(username, password)
            assert login_result.is_success
            sessions.append(login_result.data["tokens"]["access_token"])

        # Valida todas as sessões
        for i, token in enumerate(sessions):
            validate_result = await auth.validate(token)
            assert validate_result.is_success
            if validate_result.data["username"] != f"user{i}":
                raise AssertionError(
                    f"Expected {f'user{i}'}, got {validate_result.data['username']}"
                )

        # Logout de todas as sessões
        for token in sessions:
            logout_result = await auth.logout(token)
            assert logout_result.is_success

    def test_helpers_chain_workflow(self) -> None:
        """Testa workflow com helpers encadeados."""
        # 1. Validação de email
        email = "workflow@example.com"
        if not (flext_auth_validate_email(email)):
            raise AssertionError(
                f"Expected True, got {flext_auth_validate_email(email)}"
            )

        # 2. Validação de senha
        password = "WorkflowPassword123!"
        strength = flext_auth_validate_password_strength(password)
        if not (strength["valid"]):
            raise AssertionError(f"Expected True, got {strength['valid']}")

        # 3. Hash da senha
        hashed = flext_auth_hash_password(password)
        assert hashed != ""

        # 4. Verificação do hash
        if not (flext_auth_verify_password(password, hashed)):
            raise AssertionError(
                f"Expected True, got {flext_auth_verify_password(password, hashed)}"
            )

        # 5. Criação de JWT
        payload = {"user_id": "workflow123", "email": email}
        secret = "workflow-secret-key-123456789"
        token = flext_auth_generate_jwt(payload, secret=secret)
        assert token != ""

        # 6. Decodificação do JWT
        decoded = flext_auth_decode_jwt(token, secret)
        assert decoded is not None
        if decoded["user_id"] != "workflow123":
            raise AssertionError(f"Expected {'workflow123'}, got {decoded['user_id']}")

        # 7. Criação de sessão
        session = flext_auth_create_secure_session(
            decoded["user_id"],
            "workflow_user",
            "user",
            24,
        )
        if session["user_id"] != "workflow123":
            raise AssertionError(f"Expected {'workflow123'}, got {session['user_id']}")
        assert session["username"] == "workflow_user"


class TestFlextAuthPerformance:
    """Testes de performance para operações críticas."""

    def test_hash_password_performance(self, benchmark: Callable) -> None:
        """Testa performance do hash de senha."""

        def hash_operation() -> str:
            return flext_auth_hash_password("TestPassword123!", rounds=4)

        result = benchmark(hash_operation)
        assert result != ""

    def test_verify_password_performance(self, benchmark: Callable) -> None:
        """Testa performance da verificação de senha."""
        password = "TestPassword123!"
        hashed = flext_auth_hash_password(password, rounds=4)

        def verify_operation() -> bool:
            return flext_auth_verify_password(password, hashed)

        result = benchmark(verify_operation)
        if not (result):
            raise AssertionError(f"Expected True, got {result}")

    def test_jwt_operations_performance(self, benchmark: Callable) -> None:
        """Testa performance das operações JWT."""
        payload = {"user_id": "perf123", "username": "perfuser"}
        secret = "performance-secret-key-123456789"

        def jwt_cycle() -> bool:
            token = flext_auth_generate_jwt(payload, secret=secret)
            decoded = flext_auth_decode_jwt(token, secret)
            return decoded is not None

        result = benchmark(jwt_cycle)
        if not (result):
            raise AssertionError(f"Expected True, got {result}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
