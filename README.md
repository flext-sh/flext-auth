# FLEXT Auth - Enterprise Authentication Library

**Enterprise Authentication & Authorization Library**

Built on flext-core foundation with Clean Architecture, Domain-Driven Design, and CQRS patterns. Provides comprehensive authentication flows with massive code reduction - from 150+ lines to 3 lines of code.

## VisÃ£o Geral

**FLEXT Auth** Ã© uma biblioteca Python pura projetada para reduzir massivamente o cÃ³digo necessÃ¡rio para implementar autenticaÃ§Ã£o empresarial. Com **interface pÃºblica Ãºnica** e helpers extremamente Ãºteis, elimina 98% do cÃ³digo boilerplate.

### ð¯ CaracterÃ­sticas Principais

- â **Interface Ãnica**: Todas as funcionalidades atravÃ©s de `FlextAuth()`
- â **Zero ConfiguraÃ§Ã£o**: Funciona out-of-the-box com defaults seguros
- â **ReduÃ§Ã£o Massiva**: De 150+ linhas para 3 linhas
- â **Base SÃ³lida**: ConstruÃ­da sobre flext-core (sem duplicaÃ§Ã£o)
- â **Biblioteca Pura**: Sem CLI, sem serviÃ§os, apenas utilitÃ¡rios
- â **Acesso Raiz**: APENAS atravÃ©s do namespace principal
- â **Compatibilidade**: Warnings para APIs antigas

## ð InstalaÃ§Ã£o

```bash
pip install flext-auth
```

## â¡ Quick Start

### Antes (MÃ©todo Tradicional - 150+ linhas)

```python
# ConfiguraÃ§Ã£o manual de bcrypt, JWT, repositÃ³rios, sessÃµes...
# 150+ linhas de cÃ³digo boilerplate
# MÃºltiplos pontos de falha
# ManutenÃ§Ã£o complexa
```

### Depois (FLEXT Auth - 3 linhas)

```python
from flext_auth import flext_auth_quick_start

# Setup completo com REDACTED_LDAP_BIND_PASSWORD automÃ¡tico
auth = flext_auth_quick_start()

# Sistema completo funcionando!
```

## ð" Uso BÃ¡sico

### Registro e Login

```python
import asyncio
from flext_auth import FlextAuth

async def exemplo_basico():
    auth = FlextAuth()

    # Registro com validaÃ§Ã£o automÃ¡tica
    user = await auth.register("john", "john@exemplo.com", "SenhaSegura123!")

    # Login com sessÃ£o automÃ¡tica
    session = await auth.login("john", "SenhaSegura123!")

    # ValidaÃ§Ã£o instantÃ¢nea
    context = await auth.validate(session.data["tokens"]["access_token"])

    print(f"UsuÃ¡rio logado: {context.data['username']}")

asyncio.run(exemplo_basico())
```

### Sistema Completo

```python
from flext_auth import (
    FlextAuth,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_hash_password,
    flext_auth_generate_jwt,
)

async def sistema_completo():
    # ConfiguraÃ§Ã£o customizada
    config = {
        "jwt": {"secret_key": "minha-chave-secreta"},
        "security": {"password_rounds": 12}
    }
    auth = FlextAuth(config)

    # ValidaÃ§Ãµes com helpers
    email = "REDACTED_LDAP_BIND_PASSWORD@empresa.com"
    password = "MinhaPasswordSegura123!"

    if flext_auth_validate_email(email):
        strength = flext_auth_validate_password_strength(password)
        if strength["valid"]:
            # Registro
            result = await auth.register("REDACTED_LDAP_BIND_PASSWORD", email, password, "REDACTED_LDAP_BIND_PASSWORD")

            # Login
            login = await auth.login("REDACTED_LDAP_BIND_PASSWORD", password)

            # OperaÃ§Ãµes avanÃ§adas
            await auth.change_password(user_id, password, "NovaSenha456!")
            await auth.get_user_sessions(user_id)
            await auth.cleanup_sessions()

asyncio.run(sistema_completo())
```

## ð IntegraÃ§Ã£o com Frameworks Web

### FastAPI (10 linhas vs 100+ tradicionais)

```python
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer
from flext_auth import flext_auth_quick_start

app = FastAPI()
auth = flext_auth_quick_start()
security = HTTPBearer()

async def get_current_user(token = Depends(security)):
    result = await auth.validate(token.credentials)
    if not result.is_success:
        raise HTTPException(401, "Token invÃ¡lido")
    return result.data

@app.get("/protected")
async def protected(user = Depends(get_current_user)):
    return {"message": f"OlÃ¡ {user['username']}!"}
```

### Flask (8 linhas vs 80+ tradicionais)

```python
from flask import Flask, request, jsonify
from functools import wraps
from flext_auth import flext_auth_quick_start

app = Flask(__name__)
auth = flext_auth_quick_start()

def require_auth(f):
    @wraps(f)
    async def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        result = await auth.validate(token)
        if not result.is_success:
            return jsonify({"error": "NÃ£o autorizado"}), 401
        request.user = result.data
        return await f(*args, **kwargs)
    return decorated

@app.route('/protected')
@require_auth
async def protected():
    return jsonify({"message": f"OlÃ¡ {request.user['username']}!"})
```

### Middleware Universal

```python
from flext_auth import flext_auth_middleware_creator, flext_auth_quick_start

auth = flext_auth_quick_start()
middleware = flext_auth_middleware_creator(auth)

# Funciona com qualquer framework!
```

## ð ï¸ Helpers para ReduÃ§Ã£o Massiva

### AutenticaÃ§Ã£o

```python
from flext_auth import (
    flext_auth_hash_password,
    flext_auth_verify_password,
    flext_auth_generate_jwt,
    flext_auth_decode_jwt,
)

# Hash seguro em 1 linha
hashed = flext_auth_hash_password("senha123", rounds=12)

# VerificaÃ§Ã£o em 1 linha
valid = flext_auth_verify_password("senha123", hashed)

# JWT customizado em 1 linha
token = flext_auth_generate_jwt({"user_id": "123"}, expires_minutes=60)

# DecodificaÃ§Ã£o em 1 linha
decoded = flext_auth_decode_jwt(token, "secret")
```

### ValidaÃ§Ãµes

```python
from flext_auth import (
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_create_secure_session,
)

# ValidaÃ§Ã£o robusta de email
valid_email = flext_auth_validate_email("user@exemplo.com")

# AnÃ¡lise completa de senha
strength = flext_auth_validate_password_strength("MinhaPassword123!")
print(f"Score: {strength['score']}, VÃ¡lida: {strength['valid']}")

# SessÃ£o segura completa
session = flext_auth_create_secure_session("user123", "joao", "REDACTED_LDAP_BIND_PASSWORD", 24)
```

## ðï¸ Interface PÃºblica

### Classe Principal

- `FlextAuth()` - Interface Ãºnica para todas as operaÃ§Ãµes

### Helpers (ReduÃ§Ã£o Massiva)

- `flext_auth_quick_start()` - Setup instantÃ¢neo com REDACTED_LDAP_BIND_PASSWORD
- `flext_auth_hash_password()` - Hash seguro sem configuraÃ§Ã£o
- `flext_auth_verify_password()` - VerificaÃ§Ã£o instantÃ¢nea
- `flext_auth_generate_jwt()` - JWT em 1 linha
- `flext_auth_decode_jwt()` - DecodificaÃ§Ã£o instantÃ¢nea
- `flext_auth_validate_email()` - ValidaÃ§Ã£o robusta
- `flext_auth_validate_password_strength()` - AnÃ¡lise completa
- `flext_auth_create_secure_session()` - SessÃ£o completa
- `flext_auth_middleware_creator()` - Middleware universal

### Compatibilidade

- Classes `FlextAuth*` (com warnings de depreciaÃ§Ã£o)
- `FlextResult` (re-exportado de flext-core)

## ð§ª Testes

```bash
# Executar todos os testes
pytest tests/

# Testes especÃ­ficos
pytest tests/test_flext_auth_library.py -v

# Performance
pytest tests/test_flext_auth_library.py::TestFlextAuthPerformance -v

# Cobertura
pytest tests/ --cov=flext_auth --cov-report=html
```

## ð" Benchmark de ReduÃ§Ã£o

| OperaÃ§Ã£o     | Tradicional | FLEXT Auth | ReduÃ§Ã£o |
| -------------- | ----------- | ---------- | --------- |
| Setup BÃ¡sico  | 150+ linhas | 3 linhas   | 98%       |
| FastAPI Auth   | 100+ linhas | 10 linhas  | 90%       |
| Flask Auth     | 80+ linhas  | 8 linhas   | 90%       |
| Hash Password  | 20+ linhas  | 1 linha    | 95%       |
| JWT Operations | 50+ linhas  | 2 linhas   | 96%       |

## ðï¸ Arquitetura

```
flext-auth/
â"â"â" src/flext_auth/
â"   â"â"â" __init__.py          # â ÃNICA interface pÃºblica
â"   â"â"â" services/            # ServiÃ§os existentes (reutilizaÃ§Ã£o)
â"   â"â"â" repositories/        # RepositÃ³rios (sem duplicaÃ§Ã£o)
â"   â"â"â" domain/             # Entidades (compatibilidade)
â"   â""â"â" config.py           # ConfiguraÃ§Ã£o (flext-core base)
â"â"â" examples/               # Exemplos prÃ¡ticos
â"â"â" tests/                  # Testes robustos
â""â"â" README.md              # Esta documentaÃ§Ã£o
```

### PrincÃ­pios

1. **Interface Ãnica**: Acesso APENAS pela raiz (`from flext_auth import ...`)
2. **Sem DuplicaÃ§Ã£o**: Reutiliza flext-core e bibliotecas existentes
3. **ReduÃ§Ã£o Massiva**: Elimina 95%+ do cÃ³digo boilerplate
4. **Biblioteca Pura**: Sem CLI, sem serviÃ§os, apenas utilitÃ¡rios
5. **Compatibilidade**: Warnings para migration suave

## ð"§ ConfiguraÃ§Ã£o AvanÃ§ada

```python
from flext_auth import FlextAuth

config = {
    "jwt": {
        "secret_key": "chave-super-secreta-producao",
        "access_token_expire_minutes": 15,
        "refresh_token_expire_days": 30,
        "algorithm": "HS256"
    },
    "security": {
        "password_rounds": 14,  # ProduÃ§Ã£o
        "max_failed_attempts": 3,
        "lockout_duration_minutes": 60,
        "session_expire_hours": 24,
        "max_concurrent_sessions": 5
    }
}

auth = FlextAuth(config)
```

## ð¯ Casos de Uso

### 1. APIs REST

```python
# AutenticaÃ§Ã£o completa em 3 linhas
auth = flext_auth_quick_start()
result = await auth.login(username, password)
context = await auth.validate(token)
```

### 2. MicroserviÃ§os

```python
# ValidaÃ§Ã£o distribuÃ­da
middleware = flext_auth_middleware_creator(auth)
# Aplicar em todos os serviÃ§os
```

### 3. AplicaÃ§Ãµes Web

```python
# IntegraÃ§Ã£o instantÃ¢nea
@require_auth
def protected_route():
    return render_template('dashboard.html')
```

## ð" Exemplos Completos

Veja os exemplos completos em `/examples/`:

- `basic_usage.py` - Uso bÃ¡sico e comparaÃ§Ãµes
- `advanced_usage.py` - Sistema completo com RBAC
- `web_framework_integration.py` - IntegraÃ§Ã£o com frameworks

## ð¤ Contribuindo

1. Fork o repositÃ³rio
2. Crie uma branch para sua feature
3. Execute os testes: `make validate`
4. Submeta um Pull Request

## ð" LicenÃ§a

MIT License - veja LICENSE para detalhes.

## ð Resumo

**FLEXT Auth** revoluciona a implementaÃ§Ã£o de autenticaÃ§Ã£o Python com:

- â¡ **98% menos cÃ³digo** que mÃ©todos tradicionais
- ð"' **SeguranÃ§a empresarial** com defaults seguros
- ð **Performance otimizada** com flext-core
- ð **Compatibilidade universal** com frameworks
- ð" **Interface Ãºnica** para mÃ¡xima simplicidade

**De 150+ linhas para 3 linhas. De 4 horas para 2 minutos.**

---

_ConstruÃ­da com â¤ï¸ usando flext-core patterns para mÃ¡xima reutilizaÃ§Ã£o e zero duplicaÃ§Ã£o._
