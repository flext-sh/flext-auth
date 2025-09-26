#!/usr/bin/env python3
"""Health check script for Docker container.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

from flext_auth.constants import FlextAuthConstants


def main() -> int:
    """Perform health check.

    Returns:
        int: Exit code (0 for success, 1 for failure)

    """
    try:
        health_url = f"http://{FlextAuthConstants.Platform.DEFAULT_HOST}:{FlextAuthConstants.Platform.FLEXT_API_PORT}/auth/health"
        with urllib.request.urlopen(
            health_url,
            timeout=FlextAuthConstants.Network.DEFAULT_TIMEOUT,
        ) as response:
            if response.status == FlextAuthConstants.Platform.HTTP_STATUS_OK:
                return 0
            return 1
    except urllib.error.URLError:
        return 1
    except (RuntimeError, ValueError, TypeError):
        return 1


if __name__ == "__main__":
    sys.exit(main())
