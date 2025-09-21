#!/usr/bin/env python3
"""Health check script for Docker container.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

# Constants
HTTP_OK = 200


def main() -> int:
    """Perform health check.

    Returns:
        int: Exit code (0 for success, 1 for failure)

    """
    try:
        with urllib.request.urlopen(
            "http://localhost:8000/auth/health",
            timeout=10,
        ) as response:
            if response.status == HTTP_OK:
                return 0
            return 1
    except urllib.error.URLError:
        return 1
    except (RuntimeError, ValueError, TypeError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
