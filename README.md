# FLEXT-Auth

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**FLEXT-Auth** is a generic, extensible authentication and authorization library for the FLEXT ecosystem. It utilizes a multi-provider architecture to support various authentication methods—from standard JWTs to enterprise SSO solutions like SAML and OAuth2—all while maintaining a unified, type-safe API.

Part of the [FLEXT](https://github.com/flext/flext) ecosystem.

## 🚀 Key Features

- **Multi-Provider Support**: A plugin-based architecture for diverse authentication strategies (JWT, OAuth2, OIDC, SAML, API Keys).
- **Provider Registry**: Dynamic registration and discovery of authentication providers at runtime.
- **FLEXT Integration**: Seamlessly works with `flext-core` for result handling and dependency injection.
- **Secure by Default**: Implements industry-standard security practices, including secure credential storage (bcrypt) and token lifecycle management.
- **Transport Agnostic**: Designed to work across HTTP, gRPC, and WebSocket transports.
- **Railway-Oriented**: Authentication flows return `FlextResult[T]`, ensuring predictable error handling.

## 📦 Installation

To install `flext-auth`:

```bash
pip install flext-auth
```

Or with Poetry:

```bash
poetry add flext-auth
```

## 🛠️ Usage

### Quick Start with JWT

Set up a standard JWT authentication flow.

```python
from flext_auth import FlextAuth

# 1. Configure Auth with JWT Provider
auth = FlextAuth.with_jwt(
    secret_key="sys-secret",
    algorithm="HS256",
    access_token_expiry_minutes=60
)

# 2. Authenticate User
result = auth.authenticate({
    "username": "alice", 
    "password": "secure-password"
})

if result.is_success:
    token = result.unwrap()
    print(f"Token: {token.access_token}")
else:
    print(f"Auth Failed: {result.error}")
```

### Custom Provider Registration

Register your own authentication logic using the provider registry.

```python
from flext_auth import FlextAuth, FlextAuthRegistry, FlextAuthJwtProvider

# 1. Initialize Registry
registry = FlextAuthRegistry()

# 2. Register a Provider
jwt_provider = FlextAuthJwtProvider({"secret_key": "my-secret"})
registry.register("jwt", jwt_provider)

# 3. Initialize Auth with Registry
auth = FlextAuth.with_registry(registry=registry, default_provider="jwt")

# 4. Authenticate
auth.authenticate(credentials).map(lambda t: print(f"Logged in: {t}"))
```

## 🏗️ Architecture

FLEXT-Auth separates the _mechanism_ of authentication from the _policy_:

- **Orchestrator (`FlextAuth`)**: The main entry point that delegates to configured providers.
- **Registry (`FlextAuthRegistry`)**: Manages the lifecycle and retrieval of authentication providers.
- **Providers**: Implement specific protocols (e.g., `FlextAuthJwtProvider`, `OAuth2Provider`).
- **Models**: Standardized User, Session, and Token models ensure consistency across providers.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/development.md) for details on setting up your environment and creating new authentication providers.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
