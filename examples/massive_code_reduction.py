"""Exemplos práticos demonstrando redução massiva de código com flext-auth.

Compara implementação tradicional vs flext-auth para mostrar a redução real.
"""

import asyncio
import contextlib

# =============================================================================
# SETUP COMPLETO: Tradicional vs FLEXT
# =============================================================================

def traditional_setup() -> None:
    """Setup tradicional - ~150 linhas de código."""
    # Implementação tradicional seria algo como:


def flext_auth_setup() -> None:
    """Setup FLEXT - 3 linhas de código."""
    from flext_auth import flext_auth_quick_start

    # FLEXT: Setup completo em 1 linha!
    return flext_auth_quick_start()

    # Pronto! Todas as funcionalidades disponíveis:
    # - Registro com validação
    # - Login com tokens JWT
    # - Validação de senha forte
    # - Validação de email
    # - Hashing bcrypt seguro
    # - Sessões seguras
    # - Middleware para frameworks
    # - API keys
    # - Operações em lote



# =============================================================================
# OPERAÇÕES BÁSICAS: Tradicional vs FLEXT
# =============================================================================

def traditional_operations() -> None:
    """Operações tradicionais - ~50 linhas por operação."""
    # Para cada operação básica, código tradicional:

    # 1. VALIDAÇÃO DE EMAIL (~15 linhas)
    # import re
    # def validate_email(email):
    #     if not email or '@' not in email:
    #         return False
    #     pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    #     return bool(re.match(pattern, email))

    # 2. HASH DE SENHA (~20 linhas)
    # import bcrypt
    # import secrets
    # def hash_password(password, rounds=12):
    #     try:
    #         salt = bcrypt.gensalt(rounds=rounds)
    #         hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    #         return hashed.decode('utf-8')
    #     except Exception as e:
    #         raise ValueError(f"Password hashing failed: {e}")

    # 3. VERIFICAÇÃO DE SENHA (~15 linhas)
    # def verify_password(password, hashed):
    #     try:
    #         return bcrypt.checkpw(
    #             password.encode('utf-8'),
    #             hashed.encode('utf-8')
    #         )
    #     except Exception:
    #         return False

    # 4. ANÁLISE DE FORÇA DA SENHA (~50 linhas)
    # def check_password_strength(password):
    #     score = 0
    #     feedback = []
    #
    #     # Verificações múltiplas...
    #     if len(password) >= 8: score += 1
    #     else: feedback.append("At least 8 characters")
    #
    #     if re.search(r'[A-Z]', password): score += 1
    #     else: feedback.append("Add uppercase")
    #
    #     # ... mais 30+ linhas de validações
    #
    #     return {'score': score, 'valid': score >= 4, 'feedback': feedback}

    # 5. JWT OPERATIONS (~30 linhas)
    # import jwt
    # from datetime import datetime, timedelta
    # def generate_jwt(payload, secret, expires_minutes=30):
    #     payload.update({
    #         'iat': datetime.utcnow(),
    #         'exp': datetime.utcnow() + timedelta(minutes=expires_minutes)
    #     })
    #     return jwt.encode(payload, secret, algorithm='HS256')
    #
    # def decode_jwt(token, secret):
    #     try:
    #         claims = jwt.decode(token, secret, algorithms=['HS256'])
    #         return claims
    #     except jwt.InvalidTokenError:
    #         return None

    # TOTAL POR OPERAÇÃO: 50+ linhas
    # TOTAL PARA TODAS: 200+ linhas


def flext_auth_operations() -> None:
    """Operações FLEXT - 1 linha cada."""
    from flext_auth import (
        flext_auth_create_secure_session,
        flext_auth_decode_jwt,
        flext_auth_generate_jwt,
        flext_auth_hash_password,
        flext_auth_validate_email,
        flext_auth_validate_password_strength,
        flext_auth_verify_password,
    )

    # FLEXT: Cada operação em 1 linha!

    # 1. VALIDAÇÃO DE EMAIL (1 linha vs 15 linhas)
    email_valid = flext_auth_validate_email("user@example.com")

    # 2. HASH DE SENHA (1 linha vs 20 linhas)
    password_hash = flext_auth_hash_password("SecurePass123!", rounds=4)

    # 3. VERIFICAÇÃO DE SENHA (1 linha vs 15 linhas)
    password_valid = flext_auth_verify_password("SecurePass123!", password_hash)

    # 4. ANÁLISE DE FORÇA (1 linha vs 50 linhas)
    strength = flext_auth_validate_password_strength("SecurePass123!")

    # 5. JWT GENERATION (1 linha vs 15 linhas)
    token = flext_auth_generate_jwt(
        {"user_id": "123"},
        secret="secret-key-12345678901234567890",
    )

    # 6. JWT DECODING (1 linha vs 15 linhas)
    decoded = flext_auth_decode_jwt(token, "secret-key-12345678901234567890")

    # 7. SESSÃO SEGURA (1 linha vs 30 linhas)
    session = flext_auth_create_secure_session("user123", "john", "REDACTED_LDAP_BIND_PASSWORD", 24)

    # TOTAL FLEXT: 7 linhas
    # TOTAL TRADICIONAL: 200+ linhas
    # REDUÇÃO: 96.5%

    return {
        "email_valid": email_valid,
        "password_hash": password_hash,
        "password_valid": password_valid,
        "strength": strength,
        "token": token,
        "decoded": decoded,
        "session": session,
    }


# =============================================================================
# EXEMPLO PRÁTICO: FastAPI
# =============================================================================

def traditional_fastapi() -> None:
    """FastAPI tradicional - ~100 linhas."""
    # Implementação tradicional FastAPI:
    #
    # from fastapi import FastAPI, HTTPException, Depends, status
    # from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    # from pydantic import BaseModel, EmailStr
    # import bcrypt
    # import jwt
    # from datetime import datetime, timedelta
    # import re
    #
    # app = FastAPI()
    # security = HTTPBearer()
    # users_db = {}
    # SECRET_KEY = "your-secret-key"
    #
    # class UserCreate(BaseModel):
    #     username: str
    #     email: EmailStr
    #     password: str
    #
    # class UserLogin(BaseModel):
    #     username: str
    #     password: str
    #
    # def hash_password(password: str) -> str:
    #     salt = bcrypt.gensalt()
    #     return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    #
    # def verify_password(password: str, hashed: str) -> bool:
    #     return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    #
    # def validate_password_strength(password: str) -> dict:
    #     score = 0
    #     feedback = []
    #
    #     if len(password) >= 8: score += 1
    #     else: feedback.append("At least 8 characters")
    #
    #     if re.search(r'[A-Z]', password): score += 1
    #     else: feedback.append("Add uppercase")
    #
    #     if re.search(r'[a-z]', password): score += 1
    #     else: feedback.append("Add lowercase")
    #
    #     if re.search(r'[0-9]', password): score += 1
    #     else: feedback.append("Add numbers")
    #
    #     if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 1
    #     else: feedback.append("Add special characters")
    #
    #     return {'valid': score >= 4, 'feedback': feedback}
    #
    # def create_jwt_token(data: dict) -> str:
    #     to_encode = data.copy()
    #     expire = datetime.utcnow() + timedelta(minutes=30)
    #     to_encode.update({"exp": expire})
    #     return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    #
    # def verify_jwt_token(token: str) -> dict:
    #     try:
    #         payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    #         return payload
    #     except jwt.PyJWTError:
    #         return None
    #
    # async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    #     token = credentials.credentials
    #     payload = verify_jwt_token(token)
    #     if not payload:
    #         raise HTTPException(status_code=401, detail="Invalid token")
    #     return payload
    #
    # @app.post("/register")
    # async def register(user: UserCreate):
    #     if user.username in users_db:
    #         raise HTTPException(status_code=400, detail="User already exists")
    #
    #     strength = validate_password_strength(user.password)
    #     if not strength['valid']:
    #         raise HTTPException(status_code=400, detail=f"Weak password: {strength['feedback']}")
    #
    #     hashed_password = hash_password(user.password)
    #     users_db[user.username] = {
    #         "email": user.email,
    #         "password": hashed_password,
    #         "created_at": datetime.utcnow()
    #     }
    #
    #     return {"message": "User created successfully"}
    #
    # @app.post("/login")
    # async def login(user: UserLogin):
    #     if user.username not in users_db:
    #         raise HTTPException(status_code=401, detail="Invalid credentials")
    #
    #     stored_user = users_db[user.username]
    #     if not verify_password(user.password, stored_user["password"]):
    #         raise HTTPException(status_code=401, detail="Invalid credentials")
    #
    #     token = create_jwt_token({"sub": user.username})
    #     return {"access_token": token, "token_type": "bearer"}
    #
    # @app.get("/protected")
    # async def protected_route(current_user: dict = Depends(get_current_user)):
    #     return {"message": f"Hello {current_user['sub']}"}
    #
    # # TOTAL: ~100 linhas de código complexo


def flext_auth_fastapi() -> None:
    """FastAPI com FLEXT - 10 linhas."""
    # from fastapi import FastAPI, HTTPException, Depends
    # from flext_auth import flext_auth_quick_start, flext_auth_middleware_factory
    # from pydantic import BaseModel
    #
    # # 1. Setup completo em 1 linha
    # auth = flext_auth_quick_start()
    #
    # # 2. App FastAPI
    # app = FastAPI()
    #
    # # 3. Modelos simples
    # class UserCreate(BaseModel):
    #     username: str
    #     email: str
    #     password: str
    #
    # class UserLogin(BaseModel):
    #     username: str
    #     password: str
    #
    # # 4. Endpoints com validação automática
    # @app.post("/register")
    # async def register(user: UserCreate):
    #     result = await auth.register_validated(user.username, user.email, user.password)
    #     if not result.is_success:
    #         raise HTTPException(status_code=400, detail=result.error)
    #     return {"message": "User created", "user": result.data}
    #
    # @app.post("/login")
    # async def login(user: UserLogin):
    #     result = await auth.login_and_validate(user.username, user.password)
    #     if not result.is_success:
    #         raise HTTPException(status_code=401, detail=result.error)
    #     return {"access_token": result.data["token"], "token_type": "bearer"}
    #
    # @app.get("/protected")
    # async def protected_route(request):
    #     # Middleware automático do FLEXT cuida da autenticação
    #     return {"message": f"Hello {request.auth_context['username']}"}
    #
    # # TOTAL FLEXT: 10 linhas funcionais
    # # TOTAL TRADICIONAL: 100+ linhas
    # # REDUÇÃO: 90%

    return "FastAPI completo com auth em 10 linhas!"


# =============================================================================
# DEMONSTRAÇÃO PRÁTICA
# =============================================================================

async def practical_demo() -> None:
    """Demonstração prática da redução de código."""
    # Importar apenas o que precisamos
    from flext_auth import (
        flext_auth_create_secure_session,
        flext_auth_decode_jwt,
        flext_auth_generate_jwt,
        flext_auth_hash_password,
        flext_auth_quick_start,
        flext_auth_validate_email,
        flext_auth_verify_password,
    )

    auth = flext_auth_quick_start()

    password = "DemoPassword123!"
    hashed = flext_auth_hash_password(password)
    flext_auth_verify_password(password, hashed)

    flext_auth_validate_email("demo@example.com")

    payload = {"user_id": "demo123", "username": "demo"}
    secret = "demo-secret-key-12345678901234567890"
    token = flext_auth_generate_jwt(payload, secret=secret)
    flext_auth_decode_jwt(token, secret)

    flext_auth_create_secure_session("demo123", "demouser", "REDACTED_LDAP_BIND_PASSWORD")

    with contextlib.suppress(Exception):
        await auth.register("demo", "demo@example.com", "DemoPassword123!")



def comparison_summary() -> None:
    """Resumo detalhado das comparações."""
    comparisons = [
        ("Setup Completo", "150+ linhas", "1 linha", "99.3%",
         "Configuração de auth, JWT, bcrypt, validações"),
        ("Hash de Senha", "20+ linhas", "1 linha", "95%",
         "Salt generation, bcrypt, error handling"),
        ("Validação Email", "15+ linhas", "1 linha", "93%",
         "Regex pattern, validation logic, error handling"),
        ("Password Strength", "50+ linhas", "1 linha", "98%",
         "Multiple checks, scoring, feedback generation"),
        ("JWT Operations", "30+ linhas", "2 linhas", "93%",
         "Token generation, validation, claims handling"),
        ("FastAPI Auth", "100+ linhas", "10 linhas", "90%",
         "Models, routes, middleware, dependencies"),
        ("Flask Auth", "80+ linhas", "8 linhas", "90%",
         "Routes, decorators, session handling"),
        ("Sessão Segura", "30+ linhas", "1 linha", "97%",
         "Session creation, permissions, expiration"),
        ("Middleware", "40+ linhas", "3 linhas", "92%",
         "Request processing, auth validation, context"),
        ("API Keys", "25+ linhas", "2 linhas", "92%",
         "Long-lived tokens, scope validation"),
        ("Batch Operations", "60+ linhas", "5 linhas", "91%",
         "Multiple user processing, error aggregation"),
    ]


    total_tradicional = 0
    total_flext = 0

    for _op, trad, flext, _reducao, _desc in comparisons:
        trad_num = int(trad.replace("+ linhas", "").replace(" linhas", ""))
        flext_num = int(flext.replace(" linha", "").replace(" linhas", ""))

        total_tradicional += trad_num
        total_flext += flext_num


    round((1 - total_flext/total_tradicional) * 100, 1)







# =============================================================================
# EXECUÇÃO PRINCIPAL
# =============================================================================

def main() -> None:
    """Executa todas as demonstrações."""
    traditional_setup()
    flext_auth_setup()

    traditional_operations()
    flext_auth_operations()

    traditional_fastapi()
    flext_auth_fastapi()

    # Demonstração prática
    asyncio.run(practical_demo())

    # Resumo final
    comparison_summary()


if __name__ == "__main__":
    main()
