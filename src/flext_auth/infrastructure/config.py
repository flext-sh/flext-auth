"""Configuration redirects to unified configuration.

DEPRECATED: This file has been consolidated into flext_auth.config using
unified composition mixins from flext-core. All functionality moved there.

For backward compatibility, re-export the unified configuration.
"""

from __future__ import annotations

# Import the unified configuration
from flext_auth.config import AuthConfig, get_auth_settings

# Re-export for backward compatibility
__all__ = ["AuthConfig", "get_auth_settings"]
