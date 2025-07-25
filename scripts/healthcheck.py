#!/usr/bin/env python3
"""Health check script for Docker container."""

import sys
import urllib.error
import urllib.request


def main() -> int:
    """Perform health check."""
    try:
        with urllib.request.urlopen(
            "http://localhost:8000/auth/health",
            timeout=10,
        ) as response:
            if response.status == 200:
                return 0
            print(f"Health check failed with status: {response.status}")
            return 1
    except urllib.error.URLError as e:
        print(f"Health check failed: {e}")
        return 1
    except Exception as e:
        print(f"Health check error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
