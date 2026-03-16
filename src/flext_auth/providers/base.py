"""Base authentication provider protocol for FLEXT Auth.

This module defines the abstract base class that all authentication providers
must inherit from, providing a consistent interface for authentication operations
such as login, token refresh, validation, and revocation.

The protocol ensures railway-oriented programming patterns with r returns
and supports various authentication methods (JWT, API keys, OAuth, etc.).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations
