"""
PHAROS CDR - Package Reconstruction Utilities
----------------------------------------------
Helper routines for rebuilding document packages from in-memory stream fragments.
"""

from __future__ import annotations

import io
import zipfile
from typing import Mapping

from src.cdr.sanitizer import sanitize_ooxml_bytes


def rebuild_package(parts: Mapping[str, bytes]) -> bytes:
    """Rebuild a compressed ZIP/OOXML package from an in-memory dictionary of parts."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in parts.items():
            zf.writestr(name, data)
    return buf.getvalue()


__all__ = ["rebuild_package", "sanitize_ooxml_bytes"]
