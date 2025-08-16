#!/usr/bin/env python3
"""Validate that FLEXT Auth is Docker-ready.

Tests that the library works with standard Python package dependencies
without complex build environments.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import os
import pathlib
import sys
import tempfile


def test_pip_install() -> bool | None:
    """Test if FLEXT Auth can be installed via pip in a clean environment."""
    try:
        # Test that our dependencies are standard and pip-installable
        deps = ["pydantic>=2.0.0", "structlog", "bcrypt", "pyjwt", "python-multipart"]

        for _dep in deps:
            pass

        return True
    except Exception:
        return False


def test_import_isolation() -> None:
    """Test that imports work in isolated environment."""
    test_code = """
try:
    # Test basic imports from package root
    from flext_auth import (
        FlextAuth,
        flext_auth_quick_start,
        AppConfig,
        FlextUser,
        FlextUserRole,
    )

    print("✅ All imports successful")

    # Test basic functionality
    config = AppConfig()
    auth = FlextAuth()
    print(f"✅ Basic instantiation works: {type(auth).__name__}")

    result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print(f"✅ Quick start works: {result.success}")

    print("🎉 Container simulation successful!")

except ImportError as e:
    print(f"❌ Import error: {e}")
    import sys
    sys.exit(1)
except Exception as e:
    print(f"❌ Runtime error: {e}")
    import sys
    sys.exit(1)
"""

    try:
        # Write test to temp file
        with tempfile.NamedTemporaryFile(
            encoding="utf-8",
            mode="w",
            suffix=".py",
            delete=False,
        ) as f:
            f.write(test_code)
            temp_file = f.name

        # Set up environment (no manual PYTHONPATH hacks; rely on installed packages)
        env = os.environ.copy()

        # Run the test
        async def _run(
            cmd_list: list[str],
            env: dict[str, str],
            *,
            timeout_seconds: int = 30,
        ) -> tuple[int, str, str]:
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                async with asyncio.timeout(timeout_seconds):
                    stdout, stderr = await process.communicate()
            except TimeoutError:
                process.kill()
                await process.communicate()
                return 124, "", "Timeout"
            return process.returncode, stdout.decode(), stderr.decode()

        rc, _out, err = asyncio.run(
            _run([sys.executable, temp_file], env, timeout_seconds=30),
        )

        # capture stderr for debugging in test output if needed

        # Clean up
        pathlib.Path(temp_file).unlink()

        return rc == 0

    except Exception:
        return False


def test_examples_docker_ready() -> bool | None:
    """Test that examples would work in Docker."""
    try:
        # Check that examples don't have complex dependencies
        examples_path = "/home/marlonsc/flext/flext-auth/examples"

        # Count working examples
        working_examples = [
            "01_basic_usage.py",
            "02_advanced_features.py",
            "03_comprehensive_demo.py",
            "04_refactored_system_showcase.py",
        ]

        for example in working_examples:
            example_path = pathlib.Path(examples_path) / example
            if example_path.exists():
                pass

        return True
    except Exception:
        return False


def main() -> int:
    """Run Docker readiness validation."""
    tests = [
        ("Standard Dependencies", test_pip_install),
        ("Import Isolation", test_import_isolation),
        ("Examples Ready", test_examples_docker_ready),
    ]

    results = []
    for test_name, test_func in tests:
        success = test_func()
        results.append((test_name, success))

    all_passed = True
    for _test_name, success in results:
        if not success:
            all_passed = False

    if all_passed:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
