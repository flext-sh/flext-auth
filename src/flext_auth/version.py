"""Project metadata for flext auth."""

from __future__ import annotations

from importlib.metadata import metadata
from typing import Final

_metadata = metadata("flext-auth")

__version__ = _metadata["Version"]
__version_info__ = tuple(
    int(part) if part.isdigit() else part for part in __version__.split(".")
)
__title__ = _metadata["Name"]
__description__ = _metadata["Summary"]
__author__ = _metadata.get("Author")
__author_email__ = _metadata.get("Author-Email")
__license__ = _metadata.get("License")
__url__ = _metadata.get("Home-Page")


from dataclasses import dataclass


@dataclass
class FlextAuthVersion:
    """Simple version container for flext-auth."""

    version: str
    version_info: tuple[int | str, ...]


VERSION: Final[FlextAuthVersion] = FlextAuthVersion(__version__, __version_info__)

__all__ = [
    "VERSION",
    "FlextAuthVersion",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
]
