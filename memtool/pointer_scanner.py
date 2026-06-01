"""
Pointer scanner — finds pointer chains that lead to a target address.

How Cheat Engine pointer scanning works:
  1. Given a target address (e.g. 0x1A2B3C4D — where gold lives)
  2. Scan ALL memory for integers whose value is IN RANGE of the target
     (e.g. any int4 from 0x1A2B0000 to 0x1A2BFFFF)
  3. For each match, record the offset = target - pointer_value
  4. Recurse: now scan for pointers TO each pointer, building chains
  5. Result: [[base + 0x10] + 0x8] + 0x4 = gold

This finds "static" pointers rooted in the game executable or DLLs,
which survive game restarts.

Also handles:
  - Module-aware offsets (pointer relative to .exe/.dll base)
  - Pointer depth limits (max 5 levels)
  - Offset range (how far a pointer can be from the target)
  - Caching per executable for smart re-attach
"""

from __future__ import annotations

import struct
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np

from .engine import MemoryEngine, MemoryRegion, ModuleInfo
from .scanner import ValueType


# ── Types ─────────────────────────────────────────────────────────

@dataclass
class PointerNode:
    """One level in a pointer chain."""
    address: int           # absolute address of this pointer
    module_name: str = ""  # module this address is in (if known)
    module_offset: int = 0 # offset from module base
    value: int = 0         # the pointer value at this address


@dataclass
class PointerChain:
    """A complete pointer chain from root to target."""
    chain: list[PointerNode]      # [root_ptr, mid_ptr, ..., final_ptr]
    target_address: int           # the destination address
    final_offset: int             # last pointer value + final_offset = target
    depth: int = 0

    def __post_init__(self):
        self.depth = len(self.chain)

    @property
    def display_string(self) -> str:
        """Build a Cheat Engine-style display string."""
        parts = []
        for node in self.chain:
            if node.module_name:
                parts.append(f"[{node.module_name}+0x{node.module_offset:X}]")
            else:
                parts.append(f"[0x{node.address:016X}]")
        parts.append(f"+0x{self.final_offset:X}")
        return " -> ".join(parts)

    def resolve(self, engine: MemoryEngine) -> Optional[int]:
        """Follow this chain and return the final address, or None if broken."""
        addr = 0
        for i, node in enumerate(self.chain):
            if node.module_name:
                # Resolve module base (it changes per launch)
                modules = engine.get_modules()
                mod = next((m for m in modules if m.name == node.module_name), None)
                if mod is None:
                    return None
                addr = mod.base_address + node.module_offset
            else:
                addr = node.address

            if i < len(self.chain) - 1:
                data = engine.read_bytes(addr, 8)
                if data is None:
                    return None
                addr = struct.unpack("<Q", data[:8])[0]
            else:
                data = engine.read_bytes(addr, 8)
                if data is None:
                    return None
                addr = struct.unpack("<Q", data[:8])[0] + self.final_offset

        return addr


@dataclass
class PointerScanResult:
    """Results of a pointer scan."""
    target_address: int
    chains: list[PointerChain] = field(default_factory=list)
    total_pointers_scanned: int = 0
    elapsed_ms: float = 0.0


# ── PointerScanner ────────────────────────────────────────────────

class PointerScanner:
    """
    Finds pointer chains that lead to a target memory address.

    Algorithm:
      1. Scan all memory for 8-byte values that point NEAR the target
      2. Each hit is a potential "last pointer" before the target
      3. Recurse deeper: find pointers that point TO those pointers
      4. Stop when we hit a module (.exe/.dll) address, or max depth
    """

    DEFAULT_MAX_DEPTH = 5
    DEFAULT_MAX_OFFSET = 0x2000   # 8 KB — how far a pointer can be from target
    DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB per read (fewer RPM calls)

    def __init__(self, engine: MemoryEngine):
        self._engine = engine
        self._modules: list[ModuleInfo] = []
        self._module_ranges: list[tuple[int, int, str]] = []  # (start, end, name)
        self._cancelled = False
        self._progress_callback: Optional[Callable[[str, float], None]] = None

    def set_progress_callback(self, cb: Optional[Callable[[str, float], None]]):
        self._progress_callback = cb

    def cancel(self):
        self._cancelled = True

    def _report(self, msg: str, fraction: float = 0.0):
        if self._progress_callback:
            self._progress_callback(msg, fraction)

    # ── Module detection ─────────────────────────────────────

    def _refresh_modules(self):
        """Discover loaded modules to resolve pointers relative to them."""
        self._modules = self._engine.get_modules()
        self._module_ranges = []
        for m in self._modules:
            self._module_ranges.append((m.base_address, m.base_address + m.size, m.name))

    def _find_module(self, address: int) -> tuple[str, int]:
        """Find which module an address belongs to. Returns (name, offset) or ('', 0)."""
        for start, end, name in self._module_ranges:
            if start <= address < end:
                return (name, address - start)
        return ("", 0)

    # ── Pointer scan ─────────────────────────────────────────

    def scan_pointers(
        self,
        target_address: int,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_offset: int = DEFAULT_MAX_OFFSET,
        max_results: int = 500,
    ) -> PointerScanResult:
        """
        Find pointer chains that lead to target_address.

        Returns chains sorted by depth (shorter = better, usually).
        """
        self._cancelled = False
        self._refresh_modules()

        t0 = time.perf_counter()
        result = PointerScanResult(target_address=target_address)

        # Level 0: scan for direct pointers to the target
        level_chains = self._scan_level(
            target_address, level=0, max_offset=max_offset,
        )

        # Recurse deeper levels
        for depth in range(1, max_depth):
            if self._cancelled or not level_chains:
                break

            self._report(
                f"Pointer depth {depth + 1} — scanning {len(level_chains)} candidates...",
                depth / max_depth,
            )

            # Collect all unique pointer addresses from current chains
            ptr_addrs = set()
            for chain in level_chains:
                if chain.chain:
                    ptr_addrs.add(chain.chain[0].address)

            # Scan for pointers to each of these
            deeper: list[PointerChain] = []
            scanned = 0
            for ptr_addr in ptr_addrs:
                if self._cancelled:
                    break
                scanned += 1
                sub_chains = self._scan_level(
                    ptr_addr, level=depth, max_offset=max_offset,
                )
                for sub in sub_chains:
                    for existing in level_chains:
                        if existing.chain and existing.chain[0].address == ptr_addr:
                            # Prepend the deeper pointer
                            new_chain = PointerChain(
                                chain=sub.chain + existing.chain,
                                target_address=target_address,
                                final_offset=existing.final_offset,
                            )
                            deeper.append(new_chain)

                if scanned % 100 == 0:
                    self._report(
                        f"Depth {depth + 1}: {scanned}/{len(ptr_addrs)} scanned, "
                        f"{len(deeper)} chains found",
                        depth / max_depth,
                    )

            level_chains = deeper
            result.chains.extend(deeper)

            if len(result.chains) >= max_results:
                break

        # Sort: prefer chains rooted in modules
        def chain_score(c: PointerChain) -> tuple:
            has_module = any(n.module_name for n in c.chain)
            return (0 if has_module else 1, c.depth)

        result.chains.sort(key=chain_score)

        # Trim
        if len(result.chains) > max_results:
            result.chains = result.chains[:max_results]

        result.elapsed_ms = (time.perf_counter() - t0) * 1000
        self._report(
            f"Pointer scan done — {len(result.chains)} chains in {result.elapsed_ms:.0f}ms",
            1.0,
        )
        return result

    # ── Single-level scan ────────────────────────────────────

    def _scan_level(
        self,
        target_addr: int,
        level: int,
        max_offset: int,
    ) -> list[PointerChain]:
        """
        Scan all memory for 8-byte values that point to [target_addr - max_offset,
        target_addr + max_offset]. Each hit is a potential pointer.
        """
        results: list[PointerChain] = []
        lo = target_addr - max_offset
        hi = target_addr + max_offset

        regions = self._engine.get_readable_regions()
        regions = [r for r in regions if r.size >= 8]

        for region in regions:
            if self._cancelled:
                break

            for chunk_start in range(0, region.size, self.DEFAULT_CHUNK_SIZE):
                if self._cancelled:
                    break
                chunk_size = min(self.DEFAULT_CHUNK_SIZE, region.size - chunk_start)
                addr = region.base_address + chunk_start
                data = self._engine.read_bytes(addr, chunk_size)
                if data is None or len(data) < 8:
                    continue

                # numpy scan for 8-byte values in range
                usable = len(data) - (len(data) % 8)
                if usable < 8:
                    continue

                # Scan every byte alignment for 8-byte pointers
                for alignment in range(8):
                    if self._cancelled:
                        break
                    if alignment >= len(data):
                        break
                    view = data[alignment:]
                    u = len(view) - (len(view) % 8)
                    if u < 8:
                        continue

                    try:
                        arr = np.frombuffer(view[:u], dtype=np.uint64)
                    except (ValueError, TypeError):
                        continue

                    # Between lo and hi
                    mask = (arr >= lo) & (arr <= hi)
                    matches = np.nonzero(mask)[0]

                    for idx in matches:
                        ptr_addr = addr + alignment + (int(idx) * 8)
                        ptr_val = int(arr[idx])
                        final_offset = target_addr - ptr_val

                        mod_name, mod_off = self._find_module(ptr_addr)

                        node = PointerNode(
                            address=ptr_addr,
                            module_name=mod_name,
                            module_offset=mod_off,
                            value=ptr_val,
                        )

                        results.append(PointerChain(
                            chain=[node],
                            target_address=target_addr,
                            final_offset=final_offset,
                        ))

        return results
