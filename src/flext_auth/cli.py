"""CLI facade for flext-auth.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import t


def main(args: t.StrSequence | None = None) -> int:
    """Run the flext-auth console entry point.

    Commands are not implemented yet; the entry point accepts and ignores
    its arguments.

    Args:
        args: Optional command-line arguments, currently unused.

    Returns:
        The process exit code, always zero.

    """
    _ = args
    return 0


__all__: list[str] = ["main"]
