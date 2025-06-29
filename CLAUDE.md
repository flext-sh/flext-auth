# CLAUDE.md - FLX-AUTH MODULE

**Hierarchy**: PROJECT-SPECIFIC
**Project**: FLX Auth - Enterprise Authentication Service
**Status**: DEVELOPMENT (75% Complete)
**Last Updated**: 2025-06-28

**Reference**: `/home/marlonsc/CLAUDE.md` → Universal principles
**Reference**: `/home/marlonsc/internal.invalid.md` → Cross-workspace issues
**Reference**: `../CLAUDE.md` → PyAuto workspace patterns

---

## 🎯 PROJECT-SPECIFIC CONFIGURATION

### Virtual Environment Usage

```bash
# MANDATORY: Use workspace venv
source /home/marlonsc/pyauto/.venv/bin/activate
# NOT project-specific venv
```

### Agent Coordination

```bash
# Read workspace coordination first
cat /home/marlonsc/pyauto/.token | tail -5
# Log auth-specific work
echo "FLX_AUTH_WORK_$(date)" >> .token
```

## 📊 REAL IMPLEMENTATION STATUS

Based on actual code analysis from `flx-meltano-enterprise/src/flx_core/auth/`:

| File                | Size         | Status          | NotImplementedError Count |
| ------------------- | ------------ | --------------- | ------------------------- |
| **user_service.py** | 32,244 bytes | ✅ Complete     | 0                         |
| **jwt_service.py**  | 28,098 bytes | ✅ Complete     | 0                         |
| **models.py**       | ~5KB         | ✅ Complete     | 0                         |
| **tokens.py**       | ~40KB        | 🟡 95% Complete | 6                         |
| **types.py**        | ~3KB         | ✅ Complete     | 0                         |

**Total NotImplementedError**: 6 (not hundreds as might be assumed)

## 🔧 EXTRACTION STRATEGY

### What to Extract As-Is

```bash
# These files are complete and working
cp flx-meltano-enterprise/src/flx_core/auth/user_service.py src/flx_auth/
cp flx-meltano-enterprise/src/flx_core/auth/jwt_service.py src/flx_auth/
cp flx-meltano-enterprise/src/flx_core/auth/models.py src/flx_auth/
cp flx-meltano-enterprise/src/flx_core/auth/types.py src/flx_auth/
```

### What Needs Completion

**tokens.py - Only 6 methods need implementation:**

```python
# Line 216 - TokenStorage.store()
async def store(self, key: str, value: T, ttl: timedelta | None = None) -> None:
    raise NotImplementedError  # TODO: Implement Redis/DB backend

# Line 239 - TokenStorage.get()
async def get(self, key: str) -> T | None:
    raise NotImplementedError  # TODO: Implement Redis/DB backend

# Line 262 - TokenStorage.delete()
async def delete(self, key: str) -> bool:
    raise NotImplementedError  # TODO: Implement Redis/DB backend

# Line 285 - TokenStorage.exists()
async def exists(self, key: str) -> bool:
    raise NotImplementedError  # TODO: Implement Redis/DB backend

# Line 308 - TokenStorage.keys()
async def keys(self, pattern: str) -> list[str]:
    raise NotImplementedError  # TODO: Implement Redis/DB backend

# Line 331 - TokenStorage.cleanup_expired()
async def cleanup_expired(self) -> int:
    raise NotImplementedError  # TODO: Implement Redis/DB backend
```

## 🚨 PROJECT-SPECIFIC ISSUES

### **Import Dependencies**

The auth module depends on:

- `flx_core.domain` - User, Role entities
- `flx_core.config.domain_config` - Configuration management
- `flx_core.auth.types` - Shared type definitions

These need to be resolved during extraction.

### **Database Models**

The models.py uses SQLAlchemy and expects:

- User table with specific schema
- Role and Permission tables
- Many-to-many relationships

Migration scripts will be needed.

### **Configuration Integration**

Auth module expects configuration from domain_config:

- JWT settings (algorithm, expiry)
- Security settings (password requirements)
- Redis connection for token storage

## 📁 PROJECT STRUCTURE

```
flx-auth/
├── src/
│   └── flx_auth/
│       ├── __init__.py
│       ├── user_service.py      # Extract as-is (32KB)
│       ├── jwt_service.py       # Extract as-is (28KB)
│       ├── models.py           # Extract as-is
│       ├── tokens.py           # Complete 6 methods
│       ├── types.py            # Extract as-is
│       ├── security.py         # Additional security utilities
│       └── api/
│           ├── __init__.py
│           ├── endpoints.py    # FastAPI endpoints
│           └── dependencies.py # DI setup
├── tests/
│   ├── unit/
│   │   ├── test_user_service.py
│   │   ├── test_jwt_service.py
│   │   └── test_tokens.py
│   └── integration/
│       └── test_auth_flow.py
├── migrations/
│   └── alembic/
├── pyproject.toml
├── README.md
├── CLAUDE.md                   # This file
└── .env.example
```

## 🎯 IMPLEMENTATION PRIORITIES

### **Week 1: Core Extraction**

1. **Day 1-2**: Extract working files with import resolution
2. **Day 3**: Implement 6 token storage methods
3. **Day 4-5**: Create FastAPI endpoints
4. **Day 6-7**: Integration testing

### **Week 2: Production Hardening**

1. Database migrations
2. Redis connection pooling
3. Performance optimization
4. Security audit

## 📊 SUCCESS METRICS

- ✅ All 6 NotImplementedError resolved
- ✅ 100% test coverage maintained
- ✅ Authentication < 100ms response time
- ✅ Token operations < 10ms
- ✅ Zero security vulnerabilities

## 🔒 PROJECT .ENV SECURITY REQUIREMENTS

### MANDATORY .env Variables

```bash
# WORKSPACE (required for all PyAuto projects)
WORKSPACE_ROOT=/home/marlonsc/pyauto
PYTHON_VENV=/home/marlonsc/pyauto/.venv
DEBUG_MODE=true

# FLX-AUTH SPECIFIC
JWT_SECRET_KEY=your_jwt_secret_key_minimum_32_chars
JWT_PUBLIC_KEY_PATH=/path/to/public.pem
JWT_PRIVATE_KEY_PATH=/path/to/private.pem
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Database
DATABASE_URL=postgresql://user:pass@localhost/flx_auth
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=50

# Security
BCRYPT_ROUNDS=12
PASSWORD_MIN_LENGTH=8
REQUIRE_EMAIL_VERIFICATION=true
```

### MANDATORY CLI Usage

```bash
# ALWAYS source workspace venv + project .env + debug CLI
source /home/marlonsc/pyauto/.venv/bin/activate
source .env
python -m flx_auth.cli command --debug --verbose
```

## 📝 LESSONS APPLIED

### **From Investigation Failure**

1. **File Size Check**: user_service.py is 32KB (not empty!)
2. **Real Count**: Only 6 NotImplementedError (not hundreds)
3. **Implementation Status**: 75% complete (not 0%)
4. **Quality**: Enterprise-grade with bcrypt, RS256, proper patterns

### **Documentation Accuracy**

- ✅ Exact line numbers for NotImplementedError
- ✅ Actual file sizes documented
- ✅ Real implementation percentages
- ✅ Specific gaps identified

## 🎯 NEXT ACTIONS

1. Set up project structure
2. Extract working components from flx-meltano-enterprise
3. Implement 6 token storage methods
4. Create FastAPI endpoints wrapping services
5. Add comprehensive tests
6. Create migration scripts

---

**MANTRA FOR THIS PROJECT**: **EXTRACT THE EXCELLENCE, COMPLETE THE GAPS**

**Remember**: This is 75% complete enterprise-grade code, not a skeleton. Focus on the 6 missing methods and integration.
