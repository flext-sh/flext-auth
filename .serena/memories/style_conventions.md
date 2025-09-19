# FLEXT Auth Style and Conventions

## Code Style

- **Python 3.13+**: Use latest Python features
- **Type Hints**: Strict typing, no object types allowed
- **PEP8**: Follow PEP8 style guidelines
- **Black**: Auto-formatting with Black
- **Ruff**: Linting with Ruff

## Import Standards

- **Direct Imports**: Use direct imports from flext-core
- **No Internal Imports**: Never import from internal flext-core modules
- **Domain Separation**: All third-party libraries through flext-core patterns

### Correct Import Pattern

```python
from flext_core import (
    FlextResult, FlextLogger, FlextContainer,
    FlextModels, FlextConfig, FlextConstants,
    FlextUtilities, FlextTypes
)
```

### Forbidden Import Pattern

```python
# ❌ FORBIDDEN
from flext_core.result import FlextResult
from flext_core.models import FlextModels
import jwt  # Use through flext-core patterns
import bcrypt  # Use through flext-core patterns
```

## Docstring Standards (PEP8)

```python
def method_name(self, param1: str, param2: int | None = None) -> FlextResult[ReturnType]:
    """Brief description of the method.

    Longer description if needed, explaining the purpose and behavior
    of the method in more detail.

    Args:
        param1: Description of param1
        param2: Description of param2, defaults to None

    Returns:
        FlextResult containing ReturnType or error information

    Raises:
        ValueError: When param1 is invalid
        RuntimeError: When operation fails

    Example:
        >>> result = instance.method_name("test", 42)
        >>> assert result.is_success
    """
```

## Class Structure

- **Unified Class Pattern**: Single class per module
- **Nested Helpers**: Use nested classes for helper functionality
- **No Loose Functions**: All functions must be inside classes

## Error Handling

- **FlextResult Pattern**: All operations return FlextResult[T]
- **No try/except Fallbacks**: Use explicit error checking
- **No type: ignore**: Fix underlying issues instead

## Naming Conventions

- **Classes**: PascalCase (e.g., FlextAuth, FlextAuthConfig)
- **Methods**: snake_case (e.g., authenticate_user, register_user)
- **Constants**: UPPER_SNAKE_CASE (e.g., JWT_DEFAULT_ALGORITHM)
- **Private Methods**: Leading underscore (e.g., \_authenticate_user_internal)
