"""Compatibility facade: re-export auth_models via models.py.

Standardizes imports to use flext_auth.models across the codebase.
"""

from __future__ import annotations

from .auth_models import *  # noqa: F403
