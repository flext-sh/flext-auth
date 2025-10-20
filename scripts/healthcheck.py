#!/usr/bin/env python3
"""Health check script for Docker container.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Note: This script uses urllib.request.urlopen with validated HTTP/HTTPS URLs only.
Expected ruff S310 warning is acceptable due to explicit scheme validation.

"""
# URL scheme validated above to only allow http/https

from __future__ import annotations

import sys
import urllib.error
import urllib.parse
import urllib.request

from flext_auth.constants import FlextAuthConstants


def main() -> int:
    """Perform health check.

    Returns:
        int: Exit code (0 for success, 1 for failure)

    """
    try:
        health_url = f"http://{FlextAuthConstants.Platform.DEFAULT_HOST}:{FlextAuthConstants.Platform.FLEXT_API_PORT}/auth/health"

        # Comprehensive URL scheme validation for security
        parsed_url = urllib.parse.urlparse(health_url)

        # Validate scheme - only allow http/https
        if parsed_url.scheme not in {"http", "https"}:
            return 1

        # Additional security checks
        if parsed_url.netloc and ".." in parsed_url.netloc:
            return 1  # Prevent directory traversal

        # Validate hostname format
        if not parsed_url.hostname or not isinstance(parsed_url.hostname, str):
            return 1

        # Use urllib.request.urlopen with validated scheme and security checks
        # URL scheme has been validated above to only allow http/https
        with urllib.request.urlopen(
            health_url,
            timeout=30,  # Use a reasonable timeout instead of constant
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
