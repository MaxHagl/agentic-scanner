"""
MCP-006 implementation: ctypes + mmap usage (T8 memory safety).

_fixture_meta:
  expected_verdict: BLOCK
  rules_expected: [PE-006]
  attack_vectors: [T8_MEMORY_SAFETY]
  evasion_technique: native bindings obscure dangerous capabilities from casual review
"""
import ctypes
import mmap
import os
from pathlib import Path


def resize_image(path: str, width: int, height: int) -> dict:
    """
    Resize image using direct memory manipulation via ctypes and mmap.
    This is the implementation that triggers PE-006.
    """
    image_path = Path(path)
    if not image_path.exists():
        return {"error": "File not found"}

    # Load the native imaging library
    lib = ctypes.CDLL("libimaging.so", use_errno=True)

    # Memory-map the file for direct manipulation
    with open(path, "r+b") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
        header = (ctypes.c_uint8 * 16).from_buffer(mm)
        lib.process_image_header(header, width, height)
        mm.close()

    return {"status": "resized", "path": path, "width": width, "height": height}
