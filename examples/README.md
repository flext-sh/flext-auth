# flext-auth Examples (YAGNI)

This folder contains runnable examples for the current `FlextAuth` API only.

## Canonical API Surface

Use only:

- `FlextAuth()`
- `FlextAuth.quick_start(create_admin_user=...)`
- `register_user(...)`
- `authenticate_user(...)`
- `create_token(...)`
- `identity_service.identity_manager.get_user(...)`
- `identity_service.identity_manager.get_user_by_username(...)`
- `token_service.validate_token(...)`
- `session_service.session_manager.get_active_sessions(...)`
- `session_service.session_manager.end_session_by_id(...)`
- `session_service.cleanup_expired_sessions(...)`

No legacy helper functions or wrapper factories are part of the supported examples contract.

## Minimal Flow

```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_admin_user=False)

registered = auth.register_user(
    username="demo_user", email="demo@example.com", password="DemoPass123!"
)

if registered.success:
    user = registered.value
    token = auth.create_token(identity_id=user.unique_id)
    if token.success:
        _ = auth.token_service.validate_token(token.value)
```

## Run Examples

```bash
python examples/basic_auth_05.py
python examples/basic_refactored_usage_06.py
python examples/comprehensive_demo_03.py
python examples/refactored_system_showcase_04.py
```
