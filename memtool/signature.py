"""
Signature scanner — byte pattern scanning with wildcards.

Supports IDA-style signatures: "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??"
Uses Boyer-Moore optimization for fast scanning.

Use cases:
  - Find an address after game update (code surrounding the value)
  - Smart re-attach: store signature of surrounding bytes, re-find on restart
  - AOB (Array of Bytes) scanning like Cheat Engine
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Optional

from .engine import MemoryEngine, MemoryRegion


@dataclass
class SignatureMatch:
    """A match for a byte signature."""
    address: int
    pattern_name: str = ""
    matched_bytes: bytes = b""


@dataclass
class SavedOffset:
    """A saved address offset — survives game restarts and updates.

    Stores:
      - signature: bytes around the target address (for re-finding)
      - module_name + offset: if pointer chain points to a module
      - path: pointer chain string for display
    """
    label: str = ""            # user-friendly name (e.g. "Gold")
    data_type: str = "int4"    # value type
    value_hint: str = ""       # approximate value to help identify
    signature: str = ""        # byte pattern with ?? wildcards
    signature_offset: int = 0  # offset from sig match to the actual value
    module_name: str = ""      # if the sig is relative to a module
    module_offset: int = 0
    pointer_path: str = ""     # Cheat Engine-style pointer path
    description: str = ""


class SignatureScanner:
    """Fast byte-pattern scanner with wildcard support."""

    def __init__(self, engine: MemoryEngine):
        self._engine = engine

    # ── Signature matching ───────────────────────────────────

    @staticmethod
    def parse_signature(sig: str) -> tuple[bytes, bytes]:
        """
        Parse an IDA-style signature string.

        "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??" →
          mask:  b'\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00'
          pattern: b'\x48\x8b\x05\x00\x00\x00\x00\x48\x85\xc0\x74\x00'
        """
        pattern = bytearray()
        mask = bytearray()

        for token in sig.strip().split():
            token = token.strip()
            if token in ("?", "??", "?"):
                pattern.append(0)
                mask.append(0)
            else:
                pattern.append(int(token, 16))
                mask.append(0xFF)

        return bytes(pattern), bytes(mask)

    @staticmethod
    def build_signature(data: bytes) -> str:
        """
        Build a signature from raw bytes.
        Returns an IDA-style pattern string.
        """
        return " ".join(f"{b:02X}" for b in data)

    def scan(
        self,
        pattern_str: str,
        max_results: int = 100,
    ) -> list[SignatureMatch]:
        """
        Scan all readable memory for a signature pattern.

        Uses Python's bytes.find for C-level Boyer-Moore speed on
        the non-wildcard prefix, then verifies with the mask.
        """
        pattern, mask = self.parse_signature(pattern_str)
        if not pattern:
            return []

        results = []
        regions = self._engine.get_readable_regions()

        # Find the longest prefix of non-wildcard bytes as the search needle
        needle_end = 0
        for i in range(len(mask)):
            if mask[i] == 0:
                break
            needle_end = i + 1
        needle = pattern[:needle_end] if needle_end > 0 else pattern[:4]

        for region in regions:
            if len(results) >= max_results:
                break

            # Read region in chunks
            for offset in range(0, region.size, 1024 * 1024):
                if len(results) >= max_results:
                    break
                chunk_size = min(1024 * 1024, region.size - offset)
                addr = region.base_address + offset
                data = self._engine.read_bytes(addr, chunk_size)
                if data is None:
                    continue

                pos = 0
                while True:
                    pos = data.find(needle, pos)
                    if pos == -1:
                        break

                    # Check full pattern with mask
                    sig_start = pos
                    if sig_start + len(pattern) > len(data):
                        pos += 1
                        continue

                    match = True
                    for j in range(len(pattern)):
                        if mask[j] != 0 and data[sig_start + j] != pattern[j]:
                            match = False
                            break

                    if match:
                        results.append(SignatureMatch(
                            address=addr + sig_start,
                            matched_bytes=data[sig_start:sig_start + len(pattern)],
                        ))

                    pos += 1

        return results

    # ── Smart signature creation ──────────────────────────────

    def create_signature_around(
        self,
        address: int,
        radius: int = 32,
        min_unique: int = 12,
    ) -> Optional[str]:
        """
        Read bytes around an address and build a unique signature.

        The signature is the surrounding bytes (exclusive of the value itself)
        so it survives value changes. Uses the bytes BEFORE the address as
        the signature — these are usually instructions or structure fields
        that don't change between game updates.
        """
        # Read bytes before the address
        start = max(0, address - radius)
        data = self._engine.read_bytes(start, radius + 16)
        if data is None or len(data) < min_unique:
            return None

        # Take the last `radius` bytes before the address
        offset = address - start
        sig_bytes = data[max(0, offset - radius):offset]

        if len(sig_bytes) < min_unique:
            return None

        # Turn into signature
        return self.build_signature(sig_bytes)

    def create_relative_signature(
        self,
        address: int,
        module_name: str = "",
        module_base: int = 0,
        radius: int = 64,
    ) -> Optional[SavedOffset]:
        """
        Create a SavedOffset with a signature and module-relative info.
        """
        sig = self.create_signature_around(address, radius)
        if sig is None:
            return None

        so = SavedOffset(signature=sig)
        so.signature_offset = radius  # sig is `radius` bytes before the value

        if module_name and module_base:
            so.module_name = module_name
            so.module_offset = address - module_base

        return so
