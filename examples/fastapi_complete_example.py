"""Exemplo completo FastAPI com flext-auth.

Demonstra como criar uma API REST completa com autenticação
em apenas 25 linhas usando flext-auth vs 150+ linhas tradicionalmente.
"""

import asyncio
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

# FLEXT: Import único com tudo que precisamos
from flext_auth import (
    flext_auth_quick_start,
)

# =============================================================================
# CONFIGURAÇÃO EM 3 LINHAS vs 50+ TRADICIONAL
# =============================================================================

# 1. Setup completo de auth em 1 linha
auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

# 2. FastAPI app
app = FastAPI(title="FLEXT Auth Demo API", version="1.0.0")

# 3. Security scheme
security = HTTPBearer()

# =============================================================================
# MODELOS SIMPLES
# =============================================================================


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# =============================================================================
# DEPENDENCY INJECTION EM 5 LINHAS vs 30+ TRADICIONAL
# =============================================================================


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Validate token and return user context."""
    token = credentials.credentials
    result = await auth.validate(token)

    if not result.is_success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return result.data


# =============================================================================
# ENDPOINTS PRINCIPAIS - 10 LINHAS vs 80+ TRADICIONAL
# =============================================================================


@app.post("/register", response_model=dict)
async def register_user(user: UserCreate):
    """Register new user with automatic validation."""
    # FLEXT: Registro com validação integrada em 1 linha!
    result = await auth.register_validated(
        username=user.username,
        email=user.email,
        password=user.password,
        role=user.role,
        require_strong_password=True,
    )

    if not result.is_success:
        raise HTTPException(status_code=400, detail=result.error)

    return {
        "message": "User registered successfully",
        "user": {
            "username": result.data["user"]["username"],
            "email": result.data["user"]["email"],
            "role": result.data["user"]["role"],
        },
        "password_strength": result.data["password_strength"],
    }


@app.post("/login", response_model=Token)
async def login_user(user: UserLogin):
    """Login and return access token."""
    # FLEXT: Login com validação em 1 linha!
    result = await auth.login_and_validate(user.username, user.password)

    if not result.is_success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=result.error,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return Token(access_token=result.data["token"])


@app.get("/me")
async def get_current_user_info(
    current_user: Annotated[dict, Depends(get_current_user)],
):
    """Get current user information."""
    return {
        "user_id": current_user["user_id"],
        "username": current_user["username"],
        "role": current_user["role"],
        "permissions": current_user["permissions"],
    }


@app.post("/logout")
async def logout_user(current_user: Annotated[dict, Depends(get_current_user)]):
    """Logout current user."""
    # Para este exemplo, apenas retornamos sucesso
    # Em implementação real, o token seria invalidado
    return {"message": "Logged out successfully"}


@app.get("/protected")
async def protected_route(current_user: Annotated[dict, Depends(get_current_user)]):
    """Protected route example."""
    return {
        "message": f"Hello {current_user['username']}!",
        "role": current_user["role"],
        "permissions": current_user["permissions"],
    }


@app.get("/REDACTED_LDAP_BIND_PASSWORD-only")
async def REDACTED_LDAP_BIND_PASSWORD_only_route(current_user: Annotated[dict, Depends(get_current_user)]):
    """Admin-only route example."""
    if current_user["role"] != "REDACTED_LDAP_BIND_PASSWORD":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return {
        "message": "Welcome REDACTED_LDAP_BIND_PASSWORD!",
        "REDACTED_LDAP_BIND_PASSWORD_data": "Sensitive REDACTED_LDAP_BIND_PASSWORD information",
    }


# =============================================================================
# HEALTH CHECK
# =============================================================================


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "auth": "ready"}


# =============================================================================
# MIDDLEWARE OPCIONAL (comentado para simplicidade)
# =============================================================================

# Para uso avançado, você pode adicionar middleware automático:
# middleware = flext_auth_middleware_factory(auth)
# app.add_middleware(middleware)

# =============================================================================
# DEMONSTRAÇÃO DE USO
# =============================================================================


async def demo_usage() -> None:
    """Demonstra uso da API."""


if __name__ == "__main__":
    # Para desenvolvimento
    import uvicorn

    asyncio.run(demo_usage())

    # Inicia o servidor
    uvicorn.run(
        "fastapi_complete_example:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )

# =============================================================================
# EXEMPLO DE TESTE DA API
# =============================================================================

"""
Para testar a API:

1. Instalar dependências:
   pip install fastapi uvicorn

2. Executar:
   python fastapi_complete_example.py

3. Teste com curl:

# Registrar usuário
curl -X POST "http://localhost:8000/register" \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com",
       "password": "SecurePassword123!",
       "role": "user"
     }'

# Login
curl -X POST "http://localhost:8000/login" \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "password": "SecurePassword123!"
     }'

# Usar token retornado em rotas protegidas
curl -X GET "http://localhost:8000/me" \
     -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Rota protegida
curl -X GET "http://localhost:8000/protected" \
     -H "Authorization: Bearer YOUR_TOKEN_HERE"
"""
