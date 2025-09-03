"""FLEXT Auth Constants - Direct use of flext-core patterns without wrappers.

Uses FlextConstants directly from flext-core for authentication domain constants.
"""

from __future__ import annotations

# Import FlextConstants directly - no wrapper needed
from flext_core import FlextConstants

# Re-export FlextConstants for authentication domain use
__all__ = [
    "FlextConstants",
]
