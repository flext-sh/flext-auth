# FLEXT Auth - Enterprise Authentication Library

**Enterprise Authentication & Authorization Library**

Built on flext-core foundation with Clean Architecture, Domain-Driven Design, and CQRS patterns. Provides comprehensive authentication flows with massive code reduction - from 150+ lines to 3 lines of code.

## Visão Geral

**FLEXT Auth** é uma biblioteca Python pura projetada para reduzir massivamente o código necessário para implementar autenticação empresarial. Com **interface pública única** e helpers extremamente úteis, elimina 98% do código boilerplate.

### 🎯 Características Principais

- ✅ **Interface Única**: Todas as funcionalidades através de `FlextAuth()`
- ✅ **Zero Configuração**: Funciona out-of-the-box com defaults seguros
- ✅ **Redução Massiva**: De 150+ linhas para 3 linhas 
- ✅ **Base Sólida**: Construída sobre flext-core (sem duplicação)
- ✅ **Biblioteca Pura**: Sem CLI, sem serviços, apenas utilitários
- ✅ **Acesso Raiz**: APENAS através do namespace principal
- ✅ **Compatibilidade**: Warnings para APIs antigas

## 🚀 Instalação

```bash
pip install flext-auth
```

## ⚡ Quick Start

### Antes (Método Tradicional - 150+ linhas)
```python
# Configuração manual de bcrypt, JWT, repositórios, sessões...
# 150+ linhas de código boilerplate
# Múltiplos pontos de falha
# Manutenção complexa
```

### Depois (FLEXT Auth - 3 linhas)
```python
from flext_auth import flext_auth_quick_start

# Setup completo com REDACTED_LDAP_BIND_PASSWORD automático
auth = flext_auth_quick_start()

# Sistema completo funcionando!
```

## 📖 Uso Básico

### Registro e Login
```python
import asyncio
from flext_auth import FlextAuth

async def exemplo_basico():
    auth = FlextAuth()
    
    # Registro com validação automática
    user = await auth.register("john", "john@exemplo.com", "SenhaSegura123!")
    
    # Login com sessão automática
    session = await auth.login("john", "SenhaSegura123!")
    
    # Validação instantânea
    context = await auth.validate(session.data["tokens"]["access_token"])
    
    print(f"Usuário logado: {context.data['username']}")

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
    # Configuração customizada
    config = {
        "jwt": {"secret_key": "minha-chave-secreta"},
        "security": {"password_rounds": 12}
    }
    auth = FlextAuth(config)
    
    # Validações com helpers
    email = "REDACTED_LDAP_BIND_PASSWORD@empresa.com"
    password = "MinhaPasswordSegura123!"
    
    if flext_auth_validate_email(email):
        strength = flext_auth_validate_password_strength(password)
        if strength["valid"]:
            # Registro
            result = await auth.register("REDACTED_LDAP_BIND_PASSWORD", email, password, "REDACTED_LDAP_BIND_PASSWORD")
            
            # Login
            login = await auth.login("REDACTED_LDAP_BIND_PASSWORD", password)
            
            # Operações avançadas
            await auth.change_password(user_id, password, "NovaSenha456!")
            await auth.get_user_sessions(user_id)
            await auth.cleanup_sessions()

asyncio.run(sistema_completo())
```

## 🌐 Integração com Frameworks Web

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
        raise HTTPException(401, "Token inválido")
    return result.data

@app.get("/protected")
async def protected(user = Depends(get_current_user)):
    return {"message": f"Olá {user['username']}!"}
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
            return jsonify({"error": "Não autorizado"}), 401
        request.user = result.data
        return await f(*args, **kwargs)
    return decorated

@app.route('/protected')
@require_auth
async def protected():
    return jsonify({"message": f"Olá {request.user['username']}!"})
```

### Middleware Universal
```python
from flext_auth import flext_auth_middleware_creator, flext_auth_quick_start

auth = flext_auth_quick_start()
middleware = flext_auth_middleware_creator(auth)

# Funciona com qualquer framework!
```

## 🛠️ Helpers para Redução Massiva

### Autenticação
```python
from flext_auth import (
    flext_auth_hash_password,
    flext_auth_verify_password,
    flext_auth_generate_jwt,
    flext_auth_decode_jwt,
)

# Hash seguro em 1 linha
hashed = flext_auth_hash_password("senha123", rounds=12)

# Verificação em 1 linha
valid = flext_auth_verify_password("senha123", hashed)

# JWT customizado em 1 linha
token = flext_auth_generate_jwt({"user_id": "123"}, expires_minutes=60)

# Decodificação em 1 linha
decoded = flext_auth_decode_jwt(token, "secret")
```

### Validações
```python
from flext_auth import (
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_create_secure_session,
)

# Validação robusta de email
valid_email = flext_auth_validate_email("user@exemplo.com")

# Análise completa de senha
strength = flext_auth_validate_password_strength("MinhaPassword123!")
print(f"Score: {strength['score']}, Válida: {strength['valid']}")

# Sessão segura completa
session = flext_auth_create_secure_session("user123", "joao", "REDACTED_LDAP_BIND_PASSWORD", 24)
```

## 🏗️ Interface Pública

### Classe Principal
- `FlextAuth()` - Interface única para todas as operações

### Helpers (Redução Massiva)
- `flext_auth_quick_start()` - Setup instantâneo com REDACTED_LDAP_BIND_PASSWORD
- `flext_auth_hash_password()` - Hash seguro sem configuração
- `flext_auth_verify_password()` - Verificação instantânea
- `flext_auth_generate_jwt()` - JWT em 1 linha
- `flext_auth_decode_jwt()` - Decodificação instantânea
- `flext_auth_validate_email()` - Validação robusta
- `flext_auth_validate_password_strength()` - Análise completa
- `flext_auth_create_secure_session()` - Sessão completa
- `flext_auth_middleware_creator()` - Middleware universal

### Compatibilidade
- Classes `FlextAuth*` (com warnings de depreciação)
- `FlextResult` (re-exportado de flext-core)

## 🧪 Testes

```bash
# Executar todos os testes
pytest tests/

# Testes específicos
pytest tests/test_flext_auth_library.py -v

# Performance
pytest tests/test_flext_auth_library.py::TestFlextAuthPerformance -v

# Cobertura
pytest tests/ --cov=flext_auth --cov-report=html
```

## 📊 Benchmark de Redução

| Operação | Tradicional | FLEXT Auth | Redução |
|----------|-------------|------------|---------|
| Setup Básico | 150+ linhas | 3 linhas | 98% |
| FastAPI Auth | 100+ linhas | 10 linhas | 90% |
| Flask Auth | 80+ linhas | 8 linhas | 90% |
| Hash Password | 20+ linhas | 1 linha | 95% |
| JWT Operations | 50+ linhas | 2 linhas | 96% |

## 🏛️ Arquitetura

```
flext-auth/
├── src/flext_auth/
│   ├── __init__.py          # ← ÚNICA interface pública
│   ├── services/            # Serviços existentes (reutilização)
│   ├── repositories/        # Repositórios (sem duplicação)
│   ├── domain/             # Entidades (compatibilidade)
│   └── config.py           # Configuração (flext-core base)
├── examples/               # Exemplos práticos
├── tests/                  # Testes robustos
└── README.md              # Esta documentação
```

### Princípios

1. **Interface Única**: Acesso APENAS pela raiz (`from flext_auth import ...`)
2. **Sem Duplicação**: Reutiliza flext-core e bibliotecas existentes
3. **Redução Massiva**: Elimina 95%+ do código boilerplate
4. **Biblioteca Pura**: Sem CLI, sem serviços, apenas utilitários
5. **Compatibilidade**: Warnings para migration suave

## 🔧 Configuração Avançada

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
        "password_rounds": 14,  # Produção
        "max_failed_attempts": 3,
        "lockout_duration_minutes": 60,
        "session_expire_hours": 24,
        "max_concurrent_sessions": 5
    }
}

auth = FlextAuth(config)
```

## 🎯 Casos de Uso

### 1. APIs REST
```python
# Autenticação completa em 3 linhas
auth = flext_auth_quick_start()
result = await auth.login(username, password)
context = await auth.validate(token)
```

### 2. Microserviços
```python
# Validação distribuída
middleware = flext_auth_middleware_creator(auth)
# Aplicar em todos os serviços
```

### 3. Aplicações Web
```python
# Integração instantânea
@require_auth
def protected_route():
    return render_template('dashboard.html')
```

## 📚 Exemplos Completos

Veja os exemplos completos em `/examples/`:

- `basic_usage.py` - Uso básico e comparações
- `advanced_usage.py` - Sistema completo com RBAC
- `web_framework_integration.py` - Integração com frameworks

## 🤝 Contribuindo

1. Fork o repositório
2. Crie uma branch para sua feature
3. Execute os testes: `make validate`
4. Submeta um Pull Request

## 📄 Licença

MIT License - veja LICENSE para detalhes.

## 🏆 Resumo

**FLEXT Auth** revoluciona a implementação de autenticação Python com:

- ⚡ **98% menos código** que métodos tradicionais
- 🔒 **Segurança empresarial** com defaults seguros
- 🚀 **Performance otimizada** com flext-core
- 🌐 **Compatibilidade universal** com frameworks
- 📚 **Interface única** para máxima simplicidade

**De 150+ linhas para 3 linhas. De 4 horas para 2 minutos.**

---

*Construída com ❤️ usando flext-core patterns para máxima reutilização e zero duplicação.*