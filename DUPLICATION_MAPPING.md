# FLEXT-AUTH CODE DUPLICATION MAPPING

**Status**: SYSTEMATIC ANALYSIS FOR ELIMINATION · 1.0.0 Release Preparation
**Goal**: Migrate all duplicated code to use centralized flext-core patterns

## CRITICAL DUPLICATION VIOLATIONS IDENTIFIED

### 1. EXCEPTION HIERARCHIES (HIGH PRIORITY)

**❌ CURRENT STATE**: Custom exception hierarchy in `src/flext_auth/exceptions.py`

- `FlextAuthError` (base class with error codes)
- 15+ specialized authentication exceptions
- Custom error handling and formatting

**✅ FLEXT-CORE ALTERNATIVE**: `FlextExceptions.Base.create_exception_type()`

- Dynamic exception generation with built-in error codes
- Hierarchical exception system with metrics tracking
- Standardized error handling patterns

**MIGRATION PLAN**:

```python
# OLD: Custom base exception (27 lines of duplicate code)
class FlextAuthError(Exception):
    def __init__(self, message: str, error_code: str = "AUTH_ERROR"):
        super().__init__(message)
        self.message = message
        self.error_code = error_code

# NEW: Use flext-core factory pattern (1 line)
FlextAuthError = FlextExceptions.Base.create_exception_type(
    "FlextAuthError",
    base_class=RuntimeError,
    error_code=FlextConstants.Errors.AUTH_ERROR
)
```

**IMPACT**: Eliminate ~200 lines of duplicate exception handling code

---

### 2. SERVICE BASE CLASSES (HIGH PRIORITY)

**❌ CURRENT STATE**: Manual service implementations

- `FlextPasswordService` (425+ lines) - password hashing/validation
- `FlextJWTService` (432+ lines) - JWT token operations
- `FlextAuthenticationService` (163+ lines) - auth orchestration
- `FlextAuthorizationService` (200+ lines) - authorization logic

**✅ FLEXT-CORE ALTERNATIVE**: `FlextDomainService[TDomainResult]`

- Abstract base class with validation and serialization
- Standard error handling with FlextResult patterns
- Built-in business rule validation framework
- Service composition and dependency injection support

**MIGRATION EXAMPLE**:

```python
# OLD: Manual service implementation (425+ lines)
class FlextPasswordService:
    def __init__(self):
        self.rounds = 12

    def hash_password(self, password: str) -> str:
        # Custom implementation...

# NEW: Domain service pattern (much cleaner)
class FlextPasswordService(FlextDomainService[str]):
    def execute(self) -> FlextResult[str]:
        return self.hash_password_operation()

    def validate_business_rules(self) -> FlextResult[None]:
        # Use built-in validation framework
```

**IMPACT**: Reduce service code by ~40% while adding standard patterns

---

### 3. REPOSITORY IMPLEMENTATIONS (MEDIUM PRIORITY)

**❌ CURRENT STATE**: Custom repository classes

- `InMemoryUserRepository` - manual CRUD implementation
- `InMemorySessionRepository` - manual session management
- No standardized repository interface

**✅ FLEXT-CORE ALTERNATIVE**: `FlextProtocols.Domain.Repository[T]`

- Standardized repository protocol with CRUD operations
- Type-safe repository pattern with FlextResult returns
- Consistent interface across all FLEXT projects

**MIGRATION PLAN**:

```python
# OLD: Manual repository (no standard interface)
class InMemoryUserRepository:
    def get_by_username(self, username: str) -> Optional[FlextUser]:
        # Custom implementation

# NEW: Protocol-based repository
class InMemoryUserRepository(FlextProtocols.Domain.Repository[FlextUser]):
    def get_by_id(self, entity_id: str) -> FlextResult[FlextUser | None]:
        # Standard interface implementation

    def save(self, entity: FlextUser) -> FlextResult[FlextUser]:
        # Standard interface implementation
```

**IMPACT**: Standardize all repository operations and enable repository swapping

---

### 4. VALIDATION SYSTEMS (MEDIUM PRIORITY)

**❌ CURRENT STATE**: Custom validation in multiple files

- `src/flext_auth/validation.py` - FlextAuthValidators class
- Custom email/password validation logic
- Duplicated validation patterns across services

**✅ FLEXT-CORE ALTERNATIVE**: `FlextExceptions.ValidationError` and validation protocols

- Centralized validation with standard error handling
- Built-in validation predicates and composable patterns
- Type-safe validation with FlextResult integration

**MIGRATION PLAN**:

```python
# OLD: Custom validator class (duplicate validation logic)
class FlextAuthValidators:
    @staticmethod
    def validate_email(email: str) -> bool:
        # Custom email validation

# NEW: Use flext-core validation patterns
from flext_core import FlextExceptions.ValidationError

def validate_email(email: str) -> FlextResult[None]:
    # Use centralized validation with FlextResult
```

**IMPACT**: Eliminate ~150 lines of duplicate validation code

---

### 5. TYPE DEFINITIONS (LOW PRIORITY)

**❌ CURRENT STATE**: Local type definitions

- `src/flext_auth/typings.py` - FlextAuthValidationResultType
- Custom type aliases scattered across modules
- Repository type definitions (UserRepositoryType, SessionRepositoryType)

**✅ FLEXT-CORE ALTERNATIVE**: Centralized type system

- `FlextCoreTypes` namespace with standard type patterns
- Protocol-based type definitions for repositories and services
- Consistent typing across all FLEXT ecosystem projects

**MIGRATION PLAN**:

```python
# OLD: Local type definitions (scattered across files)
FlextAuthValidationResultType = Union[str, None]
UserRepositoryType = Union[InMemoryUserRepository, PostgreSQLUserRepository]

# NEW: Use centralized type system
from flext_core import FlextCoreTypes
from flext_core.protocols import FlextProtocols

ValidationResult = FlextResult[None]  # Standard result pattern
UserRepositoryType = FlextProtocols.Domain.Repository[FlextUser]
```

---

## MIGRATION STRATEGY

### Phase 1: Exception Migration (IMMEDIATE - HIGH IMPACT)

1. ✅ Read flext-core exception patterns completely
2. 🔄 Replace FlextAuthError with FlextExceptions.Base factory
3. 🔄 Migrate all specialized exceptions to use centralized patterns
4. 🔄 Update all imports across flext-auth project
5. 🔄 Validate all exception handling works with new patterns

### Phase 2: Service Migration (WEEK 2 - HIGH IMPACT)

1. 🔄 Migrate FlextPasswordService to FlextDomainService base
2. 🔄 Migrate FlextJWTService to FlextDomainService base
3. 🔄 Migrate FlextAuthenticationService to FlextDomainService base
4. 🔄 Update container registration to use new service patterns
5. 🔄 Validate all authentication workflows still work

### Phase 3: Repository Standardization (WEEK 3 - MEDIUM IMPACT)

1. Implement FlextProtocols.Domain.Repository[T] for user repository
2. Implement FlextProtocols.Domain.Repository[T] for session repository
3. Update all repository usage to use standard interface
4. Enable repository swapping through dependency injection

### Phase 4: Validation Consolidation (WEEK 4 - MEDIUM IMPACT)

1. Replace custom validation with flext-core patterns
2. Migrate all validation logic to use FlextResult consistently
3. Remove duplicate validation code across services

## SUCCESS METRICS

**Lines of Code Reduction**:

- Exceptions: ~200 lines eliminated
- Services: ~40% reduction in service implementation code
- Repositories: ~30% reduction through standard interfaces
- Validation: ~150 lines of duplicate validation eliminated

**Quality Improvements**:

- Consistent error handling across all FLEXT projects
- Type-safe repository patterns enable easier testing/mocking
- Standard service patterns improve maintainability
- Centralized validation reduces bugs and improves consistency

**Architecture Benefits**:

- Single source of truth for all base patterns
- Easier onboarding for new developers (standard patterns)
- Simplified testing through standardized interfaces
- Future-proof architecture following Clean Architecture + DDD

## VALIDATION COMMANDS

After each phase:

```bash
make validate                    # Complete validation pipeline
pytest tests/ -v                 # Verify all tests still pass
make type-check                  # Ensure type safety maintained
grep -r "FlextAuth.*Error" src/  # Verify exception migration
grep -r "class.*Service" src/    # Verify service migration
```

## COMPLETION CRITERIA

Phase complete when:

- ✅ All quality gates pass (`make validate`)
- ✅ All tests pass with no regressions
- ✅ Zero duplicate base classes found via grep analysis
- ✅ All imports use root-level flext-core patterns only
- ✅ Code review confirms proper usage of centralized patterns

---

**PRIORITY**: CRITICAL - This refactoring eliminates architectural violations and establishes proper FLEXT ecosystem patterns.

**TIMELINE**: 4 weeks for complete migration with validation at each phase.
