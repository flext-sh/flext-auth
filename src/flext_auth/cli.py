"""CLI facade for flext-auth.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)


def main() -> int:
    """Run the flext-auth console entry point.

    Commands are not implemented yet.

    Returns:
        The process exit code, always zero.

    """
    return 0


__all__: list[str] = ["main"]
