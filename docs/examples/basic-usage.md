# Basic Usage Examples

**Version**: 0.9.0 | **Updated**: September 17, 2025

Working code examples for flext-auth authentication service.

---

## Quick Start Example

Complete authentication workflow:

```python
from flext_auth import flext_auth_quick_start, FlextAuthModels

# Initialize authentication service
auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

# Create user request
user_request = FlextAuthModels.UserCreationRequest(
    username="alice",
    email="alice@example.com",
    password="SecurePassword123!"
)

# Register user
result = auth.register_user(
    username=user_request.username,
    email=user_request.email,
    password=user_request.password
)

if result.is_success:
    user = result.unwrap()
    print(f"User created: {user.username} ({user.email})")

    # Authenticate user
    auth_result = auth.authenticate_user("alice", "SecurePassword123!")

    if auth_result.is_success:
        session_data = auth_result.unwrap()
        print("Authentication successful!")
        print(f"Token: {session_data['token'][:20]}...")
        print(f"Session ID: {session_data['session']['id']}")

        # Validate token
        token_result = auth.validate_token(session_data['token'])
        if token_result.is_success:
            token_data = token_result.unwrap()
            print(f"Token valid for user: {token_data['username']}")
        else:
            print(f"Token validation failed: {token_result.error}")
    else:
        print(f"Authentication failed: {auth_result.error}")
else:
    print(f"User registration failed: {result.error}")
```

---

## FlextResult Pattern Examples

### Error Handling

```python
from flext_auth import FlextAuth, FlextAuthConfig
from flext_core import FlextResult

def safe_authentication(username: str, password: str) -> FlextResult[str]:
    """Safe authentication with proper error handling."""
    auth = FlextAuth()

    # Chain operations with FlextResult
    return (
        auth.authenticate_user(username, password)
        .flat_map(lambda auth_data: auth.validate_token(auth_data['token']))
        .map(lambda token_data: f"Welcome {token_data['username']}")
    )

# Usage
result = safe_authentication("alice", "SecurePassword123!")
if result.is_success:
    welcome_message = result.unwrap()
    print(welcome_message)
else:
    print(f"Authentication failed: {result.error}")
```

### Chaining Operations

```python
def complete_user_workflow(user_data: dict) -> FlextResult[dict]:
    """Complete user creation and authentication workflow."""
    auth = FlextAuth()

    def register_user(data):
        return auth.register_user(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )

    def authenticate_user(user):
        return auth.authenticate_user(user.username, user_data['password'])

    def format_result(auth_data):
        return {
            "user": auth_data['user'],
            "token": auth_data['token'],
            "status": "complete"
        }

    return (
        FlextResult.ok(user_data)
        .flat_map(register_user)
        .flat_map(authenticate_user)
        .map(format_result)
    )

# Usage
user_data = {
    "username": "bob",
    "email": "bob@example.com",
    "password": "BobSecure456!"
}

workflow_result = complete_user_workflow(user_data)
if workflow_result.is_success:
    result_data = workflow_result.unwrap()
    print(f"Workflow complete for: {result_data['user']['username']}")
else:
    print(f"Workflow failed: {workflow_result.error}")
```

---

## Configuration Examples

### Environment-Specific Configuration

```python
from flext_auth import FlextAuth, FlextAuthConfig
import os

def create_configured_auth() -> FlextAuth:
    """Create authentication service with environment-specific config."""
    env = os.getenv('FLEXT_ENV', 'development')

    config_result = FlextAuthConfig.create_for_environment(env)
    if config_result.is_failure:
        raise RuntimeError(f"Configuration failed: {config_result.error}")

    config = config_result.unwrap()
    return FlextAuth(config=config)

# Usage
try:
    auth = create_configured_auth()
    print("Authentication service configured successfully")
except RuntimeError as e:
    print(f"Configuration error: {e}")
```

### Custom Configuration

```python
from flext_auth import FlextAuth, FlextAuthConfig

def create_high_security_auth() -> FlextAuth:
    """Create authentication with high security settings."""
    config = FlextAuthConfig(
        jwt_expiry_minutes=15,          # Short-lived tokens
        bcrypt_rounds=14,               # High security
        max_failed_attempts=3,          # Strict lockout
        session_timeout_minutes=30      # Short sessions
    )

    return FlextAuth(config=config)

# Usage
secure_auth = create_high_security_auth()
print(f"High security auth configured with {secure_auth.config.bcrypt_rounds} bcrypt rounds")
```

---

## Domain Model Examples

### Working with User Entities

```python
from flext_auth.models import FlextAuthModels
from datetime import datetime

# Create user directly (for testing)
user = FlextAuthModels.User(
    username="charlie",
    email="charlie@example.com",
    roles=["user", "REDACTED_LDAP_BIND_PASSWORD"],
    created_at=datetime.utcnow()
)

# Set password
password_result = user.set_password("CharlieSecure789!")
if password_result.is_success:
    print("Password set successfully")

    # Verify password
    verify_result = user.verify_password("CharlieSecure789!")
    if verify_result.is_success and verify_result.unwrap():
        print("Password verification successful")
    else:
        print("Password verification failed")
else:
    print(f"Password setting failed: {password_result.error}")

# Check user properties
print(f"User: {user.username}")
print(f"Email: {user.email}")
print(f"Roles: {user.roles}")
print(f"Active: {user.is_active}")
```

### Session Management

```python
from flext_auth.models import FlextAuthModels
from datetime import datetime, timedelta
import uuid

# Create session
session = FlextAuthModels.Session(
    user_id=str(uuid.uuid4()),
    session_token=f"session_{uuid.uuid4().hex}",
    expires_at=datetime.utcnow() + timedelta(hours=2),
    is_active=True
)

# Check session validity
def is_session_valid(session: FlextAuthModels.Session) -> bool:
    """Check if session is valid and not expired."""
    return (
        session.is_active and
        datetime.utcnow() < session.expires_at
    )

if is_session_valid(session):
    print(f"Session {session.session_token[:8]}... is valid")
    print(f"Expires at: {session.expires_at}")
else:
    print("Session is invalid or expired")
```

---

## Integration Examples

### Flask Web Application

```python
from flask import Flask, request, jsonify, session
from flext_auth import FlextAuth

app = Flask(__name__)
app.secret_key = 'your-flask-secret-key'
auth = FlextAuth()

@app.route('/api/register', methods=['POST'])
def register():
    """User registration endpoint."""
    data = request.get_json()

    result = auth.register_user(
        username=data['username'],
        email=data['email'],
        password=data['password']
    )

    if result.is_success:
        user = result.unwrap()
        return jsonify({
            'success': True,
            'user': {
                'username': user.username,
                'email': user.email
            }
        })
    else:
        return jsonify({
            'success': False,
            'error': result.error
        }), 400

@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint."""
    data = request.get_json()

    auth_result = auth.authenticate_user(
        username=data['username'],
        password=data['password']
    )

    if auth_result.is_success:
        auth_data = auth_result.unwrap()
        session['token'] = auth_data['token']
        session['username'] = auth_data['user']['username']

        return jsonify({
            'success': True,
            'token': auth_data['token']
        })
    else:
        return jsonify({
            'success': False,
            'error': auth_result.error
        }), 401

@app.route('/api/protected')
def protected():
    """Protected endpoint requiring authentication."""
    token = session.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token:
        return jsonify({'error': 'Token required'}), 401

    validation_result = auth.validate_token(token)
    if validation_result.is_failure:
        return jsonify({'error': validation_result.error}), 401

    token_data = validation_result.unwrap()
    return jsonify({
        'message': f'Hello {token_data["username"]}',
        'authenticated': True
    })

if __name__ == '__main__':
    app.run(debug=True)
```

### CLI Application

```python
import click
from flext_auth import FlextAuth

auth = FlextAuth()

@click.group()
def cli():
    """Authentication CLI example."""
    pass

@cli.command()
@click.option('--username', prompt=True, help='Username')
@click.option('--email', prompt=True, help='Email address')
@click.option('--password', prompt=True, hide_input=True, help='Password')
def register(username, email, password):
    """Register new user."""
    result = auth.register_user(username, email, password)

    if result.is_success:
        user = result.unwrap()
        click.echo(f"✅ User {user.username} registered successfully")
    else:
        click.echo(f"❌ Registration failed: {result.error}")

@cli.command()
@click.option('--username', prompt=True, help='Username')
@click.option('--password', prompt=True, hide_input=True, help='Password')
def login(username, password):
    """Login user."""
    auth_result = auth.authenticate_user(username, password)

    if auth_result.is_success:
        auth_data = auth_result.unwrap()
        click.echo("✅ Authentication successful")
        click.echo(f"Token: {auth_data['token'][:20]}...")
    else:
        click.echo(f"❌ Authentication failed: {auth_result.error}")

if __name__ == '__main__':
    cli()
```

---

## Testing Examples

### Unit Test Example

```python
import pytest
from flext_auth import FlextAuth, FlextAuthModels

class TestAuthentication:
    def setup_method(self):
        """Setup for each test."""
        self.auth = FlextAuth()
        self.test_user_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'TestPassword123!'
        }

    def test_user_registration(self):
        """Test user registration."""
        result = self.auth.register_user(**self.test_user_data)

        assert result.is_success
        user = result.unwrap()
        assert user.username == self.test_user_data['username']
        assert user.email == self.test_user_data['email']

    def test_authentication_flow(self):
        """Test complete authentication flow."""
        # Register user
        reg_result = self.auth.register_user(**self.test_user_data)
        assert reg_result.is_success

        # Authenticate user
        auth_result = self.auth.authenticate_user(
            self.test_user_data['username'],
            self.test_user_data['password']
        )
        assert auth_result.is_success

        auth_data = auth_result.unwrap()
        assert 'token' in auth_data
        assert 'session' in auth_data

        # Validate token
        token_result = self.auth.validate_token(auth_data['token'])
        assert token_result.is_success

        token_data = token_result.unwrap()
        assert token_data['username'] == self.test_user_data['username']

    def test_invalid_credentials(self):
        """Test authentication with invalid credentials."""
        # Register user first
        self.auth.register_user(**self.test_user_data)

        # Try with wrong password
        auth_result = self.auth.authenticate_user(
            self.test_user_data['username'],
            'WrongPassword'
        )
        assert auth_result.is_failure
```

---

These examples demonstrate the actual working functionality of flext-auth as of September 17, 2025. For more advanced usage, see the [API Reference](../api-reference.md).