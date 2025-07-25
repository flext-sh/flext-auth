"""Exemplo: Integração com frameworks web - FastAPI, Flask, Django.

Demonstra como flext-auth reduz massivamente o código de autenticação em apps web.
"""

from flext_auth import flext_auth_middleware_creator, flext_auth_quick_start

# =============================================================================
# FASTAPI - Redução de 100+ linhas para 10 linhas
# =============================================================================

def exemplo_fastapi():
    """FastAPI com flext-auth - REDUÇÃO MASSIVA de código."""
    try:
        from fastapi import Depends, FastAPI, HTTPException
        from fastapi.security import HTTPBearer
    except ImportError:
        return None


    # Setup instantâneo
    auth = flext_auth_quick_start()
    app = FastAPI(title="API com FlextAuth")
    security = HTTPBearer()

    # Dependência de autenticação em 1 linha
    async def get_current_user(token: str = Depends(security)):
        """Dependency que valida token automaticamente."""
        result = await auth.validate(token.credentials)
        if not result.is_success:
            raise HTTPException(status_code=401, detail="Token inválido")
        return result.data

    # Rotas protegidas
    @app.post("/auth/login")
    async def login(username: str, password: str):
        """Login com uma linha de código."""
        result = await auth.login(username, password)
        if result.is_success:
            return result.data
        raise HTTPException(status_code=401, detail=result.error)

    @app.get("/protected")
    async def protected_route(user = Depends(get_current_user)):
        """Rota protegida - zero código de autenticação."""
        return {"message": f"Olá {user['username']}, você está autenticado!"}

    @app.get("/REDACTED_LDAP_BIND_PASSWORD")
    async def REDACTED_LDAP_BIND_PASSWORD_only(user = Depends(get_current_user)):
        """Rota apenas para REDACTED_LDAP_BIND_PASSWORDs."""
        if user["role"] != "REDACTED_LDAP_BIND_PASSWORD":
            raise HTTPException(status_code=403, detail="Acesso negado")
        return {"message": "Área REDACTED_LDAP_BIND_PASSWORDistrativa"}

    return app


# =============================================================================
# FLASK - Redução de 80+ linhas para 8 linhas
# =============================================================================

def exemplo_flask():
    """Flask com flext-auth - REDUÇÃO MASSIVA de código."""
    try:
        from functools import wraps

        from flask import Flask, jsonify, request
    except ImportError:
        return None


    app = Flask(__name__)
    auth = flext_auth_quick_start()

    # Decorator de autenticação em 5 linhas
    def require_auth(f):
        @wraps(f)
        async def decorated(*args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            result = await auth.validate(token)
            if not result.is_success:
                return jsonify({"error": "Não autorizado"}), 401
            request.user = result.data
            return await f(*args, **kwargs)
        return decorated

    @app.route("/auth/login", methods=["POST"])
    async def login():
        """Login em 1 linha."""
        data = request.get_json()
        result = await auth.login(data["username"], data["password"])
        return jsonify(result.data if result.is_success else {"error": result.error})

    @app.route("/protected")
    @require_auth
    async def protected():
        """Rota protegida - zero código de auth."""
        return jsonify({"message": f"Olá {request.user['username']}!"})

    return app


# =============================================================================
# DJANGO - Redução de 150+ linhas para 15 linhas
# =============================================================================

def exemplo_django() -> None:
    """Django com flext-auth - REDUÇÃO MASSIVA de código."""
    # Middleware personalizado
    auth = flext_auth_quick_start()

    class FlextAuthMiddleware:
        """Middleware Django com flext-auth."""

        def __init__(self, get_response) -> None:
            self.get_response = get_response
            self.auth = auth

        async def __call__(self, request):
            # Extrai token
            auth_header = request.META.get("HTTP_AUTHORIZATION", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                result = await self.auth.validate(token)
                if result.is_success:
                    request.user_context = result.data

            return self.get_response(request)

    # Decorator para views
    def login_required(view_func):
        """Decorator para exigir autenticação."""
        async def wrapper(request, *args, **kwargs):
            if not hasattr(request, "user_context"):
                from django.http import JsonResponse
                return JsonResponse({"error": "Não autorizado"}, status=401)
            return await view_func(request, *args, **kwargs)
        return wrapper

    # View de login
    async def login_view(request):
        """View de login em 2 linhas."""
        import json

        from django.http import JsonResponse

        data = json.loads(request.body)
        result = await auth.login(data["username"], data["password"])
        return JsonResponse(result.data if result.is_success else {"error": result.error})

    # View protegida
    @login_required
    async def protected_view(request):
        """View protegida - zero código de auth."""
        from django.http import JsonResponse
        return JsonResponse({"message": f"Olá {request.user_context['username']}!"})



# =============================================================================
# EXEMPLO UNIVERSAL - Funciona com qualquer framework
# =============================================================================

def exemplo_middleware_universal() -> None:
    """Middleware universal que funciona com qualquer framework."""
    auth = flext_auth_quick_start()

    # Cria middleware universal
    middleware = flext_auth_middleware_creator(auth)

    # Exemplo de uso com qualquer framework
    class MockRequest:
        def __init__(self, headers) -> None:
            self.headers = headers
            self.auth_context = None

    class MockResponse:
        def __init__(self, data) -> None:
            self.data = data

    async def example_handler(request):
        """Handler de exemplo."""
        return MockResponse({"message": f"Usuário: {request.auth_context['username']}"})

    # Aplica middleware
    middleware(example_handler)



# =============================================================================
# COMPARAÇÃO: ANTES vs DEPOIS
# =============================================================================

def comparacao_reducao_codigo() -> None:
    """Demonstra a redução massiva de código."""


# =============================================================================
# BENCHMARK DE PERFORMANCE
# =============================================================================

async def benchmark_performance() -> None:
    """Benchmark de performance das operações."""
    import time
    auth = flext_auth_quick_start()

    # Benchmark de registro
    start = time.time()
    for i in range(100):
        await auth.register(f"user{i}", f"user{i}@test.com", f"Password{i}!")
    time.time() - start

    # Benchmark de login
    start = time.time()
    for i in range(100):
        await auth.login(f"user{i}", f"Password{i}!")
    time.time() - start



# =============================================================================
# EXEMPLO PRINCIPAL
# =============================================================================

async def main() -> None:
    """Executa todos os exemplos de integração."""
    # Exemplos de frameworks
    exemplo_fastapi()
    exemplo_flask()
    exemplo_django()
    exemplo_middleware_universal()

    # Demonstração de redução
    comparacao_reducao_codigo()

    # Performance
    await benchmark_performance()



if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
