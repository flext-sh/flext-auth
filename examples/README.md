# FLEXT Auth Examples

**Practical usage examples for authentication library with common patterns and integrations.**

## Overview

This directory contains usage examples demonstrating FLEXT Auth functionality, from basic authentication to framework integration patterns. Examples show practical authentication implementation patterns for common use cases.

## Simplified Setup

### Traditional Manual Setup

```python
# Manual authentication implementation
import bcrypt
import jwt
from datetime import datetime, timedelta

# Requires implementing:
# - User repository with database schema
# - Password hashing service with bcrypt
# - JWT service with token validation
# - Authentication service with business logic
# - Session management and security policies
# ... (detailed implementation required)
```

### FLEXT Auth Setup

```python
from flext_auth import flext_auth_quick_start

# Ready-to-use authentication service
auth_result = flext_auth_quick_start()
if auth_result.success:
    auth = auth_result.value
    result = auth.authenticate_user("username", "password")
```

**Benefit**: Simplified setup with integrated components and consistent error handling.

## Example Files

### 1. Basic Usage (`01_basic_usage.py`)

**Purpose**: Demonstrate simple authentication setup and common workflows
**Complexity**: Minimal
**Use Case**: Getting started with FLEXT Auth

```python
from flext_auth import flext_auth_quick_start

# Zero-config authentication setup
auth_result = flext_auth_quick_start()
if auth_result.success:
    auth = auth_result.value

    # Register a user
    register_result = auth.register_user("john", "john@example.com", "SecurePass123!")

    # Authenticate user
    login_result = auth.authenticate_user("john", "SecurePass123!")

    print(f"Authentication successful: {login_result.success}")
```

**Key Features Demonstrated**:

- Quick start setup
- User registration
- User authentication
- Error handling with FlextResult

### 2. Advanced Features (`02_advanced_features.py`)

**Purpose**: Show advanced authentication patterns and configurations
**Complexity**: Intermediate
**Use Case**: Production applications with custom requirements

**Key Features Demonstrated**:

- Custom configuration options
- Role-based access control
- Session management
- JWT token customization
- Password strength validation

### 3. Comprehensive Demo (`03_comprehensive_demo.py`)

**Purpose**: Complete feature showcase with all authentication capabilities
**Complexity**: Advanced
**Use Case**: Understanding full FLEXT Auth feature SET

**Key Features Demonstrated**:

- Complete authentication workflows
- All authentication methods
- Security features
- Performance optimizations
- Integration patterns

### 4. Refactored System Showcase (`04_refactored_system_showcase.py`)

**Purpose**: Enterprise integration patterns and system architecture
**Complexity**: Enterprise
**Use Case**: Large-scale applications and microservices

**Key Features Demonstrated**:

- Microservice integration
- Database persistence
- Caching strategies
- Monitoring and observability
- Deployment configurations

### 5. Basic Auth Example (`05_basic_auth.py`)

**Purpose**: Minimal authentication example for quick reference
**Complexity**: Minimal
**Use Case**: Copy-paste ready authentication

### 6. Debug Auth Issues (`09_debug_auth_issues.py`)

**Purpose**: Debugging and troubleshooting patterns
**Complexity**: Intermediate
**Use Case**: Development and debugging scenarios

**Key Features Demonstrated**:

- Error diagnosis
- Logging configuration
- Debug mode settings
- Common issue resolution

## Usage Patterns

### Quick Start Pattern

```python
# Fastest way to get authentication working
from flext_auth import flext_auth_complete_workflow

result = flext_auth_complete_workflow("user", "user@example.com", "password")
if result.success:
    print("Authentication system ready!")
```

### Production Pattern

```python
# Production-ready configuration
from flext_auth import flext_auth_prod

auth_service = flext_auth_prod()
# Production-optimized with security hardening
```

### Development Pattern

```python
# Development-optimized configuration
from flext_auth import flext_auth_dev

auth_service = flext_auth_dev()
# Fast setup for development with relaxed security
```

### API-Optimized Pattern

```python
# API service configuration
from flext_auth import flext_auth_api

auth_service = flext_auth_api()
# Optimized for REST API authentication
```

## Integration Examples

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from flext_auth import flext_auth_quick_start, flext_auth_required

app = FastAPI()
auth_result = flext_auth_quick_start()
auth = auth_result.value

@app.post("/login")
async def login(username: str, password: str):
    result = await auth.authenticate_user(username, password)
    return {"success": result.success}

@app.get("/protected")
@flext_auth_required(auth_service=auth)
async def protected_endpoint(current_user: dict = Depends()):
    return {"user": current_user}
```

### Flask Integration

```python
from flask import Flask, request, jsonify
from flext_auth import flext_auth_quick_start, flext_auth_required

app = Flask(__name__)
auth_result = flext_auth_quick_start()
auth = auth_result.value

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    result = auth.authenticate_user(data['username'], data['password'])
    return jsonify({"success": result.success})

@app.route('/protected')
@flext_auth_required(auth_service=auth)
def protected():
    return jsonify({"message": "Protected resource"})
```

### Django Integration

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from flext_auth import flext_auth_quick_start, flext_auth_required

auth_result = flext_auth_quick_start()
auth = auth_result.value

@csrf_exempt
def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        result = auth.authenticate_user(username, password)
        return JsonResponse({"success": result.success})

@flext_auth_required(auth_service=auth)
def protected_view(request):
    return JsonResponse({"message": "Protected resource"})
```

## Performance Examples

### High-Performance Configuration

```python
from flext_auth import FlextAuthConfig, FlextAuthService

# Optimized for high-throughput scenarios
config = FlextAuthConfig(
    bcrypt_rounds=4,  # Faster hashing for development
    access_token_expire_minutes=60,
    max_concurrent_sessions=10
)

auth_service = FlextAuthService(config)
```

### Security-Hardened Configuration

```python
from flext_auth import FlextAuthConfig, FlextAuthService

# Maximum security configuration
config = FlextAuthConfig(
    bcrypt_rounds=12,  # Strong password hashing
    access_token_expire_minutes=15,  # Short token lifetime
    max_failed_attempts=3,  # Strict lockout policy
    lockout_duration_minutes=60
)

auth_service = FlextAuthService(config)
```

## Running Examples

### Prerequisites

```bash
# Ensure FLEXT Auth is installed
pip install -e .

# Or install dependencies
poetry install
```

### Execute Examples

```bash
# Run basic usage example
python examples/01_basic_usage.py

# Run advanced features
python examples/02_advanced_features.py

# Run comprehensive demo
python examples/03_comprehensive_demo.py

# Run enterprise showcase
python examples/04_refactored_system_showcase.py
```

### Interactive Examples

```bash
# Run with interactive mode
python -i examples/05_basic_auth.py

# Debug mode
python examples/09_debug_auth_issues.py --debug
```

## Example Development

### Adding New Examples

1. **Identify Use Case**: Determine what authentication scenario to demonstrate
2. **Choose Complexity**: Select appropriate complexity level for target audience
3. **Follow Patterns**: Use established example patterns and structure
4. **Document Purpose**: Clear explanation of what the example demonstrates
5. **Test Thoroughly**: Ensure example works correctly and handles errors

### Example Structure Template

```python
#!/usr/bin/env python3
"""Example: [Purpose] - [Brief description].

This example demonstrates [specific features] and shows how to [use case].
It includes [key features] and handles [error scenarios].

Complexity: [Minimal/Intermediate/Advanced/Enterprise]
Use Case: [Target scenario]:
"""

from flext_auth import [required imports]

def main():
    """Main example execution."""
    print("FLEXT Auth Example: [Name]")
    print("=" * 50)

    try:
        # Example implementation
        result = demonstrate_feature()

        if result.success:
            print("✅ Example completed successfully")
        else:
            print(f"❌ Example failed: {result.error}")

    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def demonstrate_feature():
    """Demonstrate specific authentication feature."""
    # Implementation here
    pass

if __name__ == "__main__":
    main()
```

## Best Practices Demonstrated

### Security Best Practices

- Secure password handling
- JWT token security
- Session management
- Input validation
- Error handling without information leakage

### Performance Best Practices

- Efficient configuration choices
- Caching strategies
- Connection pooling
- Async/await patterns
- Resource management

### Integration Best Practices

- Framework-agnostic patterns
- Dependency injection
- Configuration management
- Error propagation
- Logging and monitoring

## Troubleshooting Examples

### Common Issues and Solutions

1. **Import Errors**: Verify FLEXT Auth installation
2. **Configuration Issues**: Check environment variables
3. **Database Issues**: Ensure database connectivity
4. **Performance Issues**: Review configuration settings

### Debug Utilities

```python
# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Use debug authentication service
from flext_auth import flext_auth_dev
auth = flext_auth_dev()  # Debug-friendly configuration
```

## Current Status

**Example Documentation**: ✅ Comprehensive documentation completed  
**Usage Patterns**: ✅ All major patterns documented  
**Integration Examples**: 🔄 Framework integration examples being enhanced  
**Performance Examples**: 🔄 Optimization examples being developed

---

_These examples serve as the primary learning resources for FLEXT Auth. They should be kept current with the latest features and best practices._
