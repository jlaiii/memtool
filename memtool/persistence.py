"""
Persistence — save and load address lists, pointer caches, and signatures.

Stores data as JSON in ~/MemTool/ directory:
  - address_lists/   — user-saved address lists
  - pointer_cache/   — per-executable pointer chain caches
  - signatures/      — per-value signatures for smart re-attach
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Data structures ───────────────────────────────────────────────

@dataclass
class AddressEntry:
    """One saved address entry."""
    address: int = 0
    display_address: str = ""
    value_type: str = "int4"
    current_value: str = ""
    frozen_value: str = ""
    freeze: bool = False
    description: str = ""


@dataclass
class AddressList:
    """A saved address list."""
    name: str = "Untitled"
    created: str = ""           # ISO timestamp
    process_name: str = ""      # e.g. "game.exe"
    entries: list[AddressEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "created": self.created,
            "process_name": self.process_name,
            "entries": [asdict(e) for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AddressList":
        entries = [AddressEntry(**e) for e in d.get("entries", [])]
        return cls(
            name=d.get("name", "Untitled"),
            created=d.get("created", ""),
            process_name=d.get("process_name", ""),
            entries=entries,
        )


@dataclass
class PointerCache:
    """Cached pointer chains for a specific executable."""
    exe_name: str = ""
    last_updated: str = ""
    target_label: str = ""       # e.g. "Gold"
    value_type: str = "int4"
    pointer_path: str = ""       # Cheat Engine-style display
    signature: str = ""          # byte pattern for re-finding
    signature_offset: int = 0
    module_name: str = ""
    module_offset: int = 0
    verified: bool = False


@dataclass
class ExecutableCache:
    """All cached info for one executable."""
    exe_name: str = ""
    pointers: list[PointerCache] = field(default_factory=list)
    signatures: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "exe_name": self.exe_name,
            "pointers": [asdict(p) for p in self.pointers],
            "signatures": self.signatures,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ExecutableCache":
        pointers = [PointerCache(**p) for p in d.get("pointers", [])]
        return cls(
            exe_name=d.get("exe_name", ""),
            pointers=pointers,
            signatures=d.get("signatures", []),
        )


# ── Persistence Manager ───────────────────────────────────────────

class PersistenceManager:
    """Manages saving and loading all MemTool data."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            base_dir = os.path.join(os.path.expanduser("~"), "MemTool")
        self._base_dir = base_dir
        self._lists_dir = os.path.join(base_dir, "address_lists")
        self._cache_dir = os.path.join(base_dir, "pointer_cache")
        self._ensure_dirs()

    def _ensure_dirs(self):
        os.makedirs(self._lists_dir, exist_ok=True)
        os.makedirs(self._cache_dir, exist_ok=True)

    @property
    def lists_dir(self) -> str:
        return self._lists_dir

    @property
    def cache_dir(self) -> str:
        return self._cache_dir

    # ── Address Lists ─────────────────────────────────────────

    def save_list(self, addr_list: AddressList) -> str:
        """Save an address list. Returns the file path."""
        safe_name = "".join(c if c.isalnum() or c in "._- " else "_"
                            for c in addr_list.name)
        filename = f"{safe_name}.json"
        filepath = os.path.join(self._lists_dir, filename)

        d = addr_list.to_dict()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2, ensure_ascii=False)

        return filepath

    def load_list(self, filepath: str) -> Optional[AddressList]:
        """Load an address list from a file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                d = json.load(f)
            return AddressList.from_dict(d)
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None

    def list_saved_lists(self) -> list[str]:
        """List all saved address list file paths."""
        try:
            files = [f for f in os.listdir(self._lists_dir) if f.endswith(".json")]
            return sorted(
                [os.path.join(self._lists_dir, f) for f in files],
                key=os.path.getmtime, reverse=True,
            )
        except FileNotFoundError:
            return []

    def delete_list(self, filepath: str) -> bool:
        """Delete a saved address list."""
        try:
            os.remove(filepath)
            return True
        except OSError:
            return False

    # ── Pointer Cache ─────────────────────────────────────────

    def save_pointer_cache(self, cache: ExecutableCache):
        """Save pointer cache for an executable."""
        safe_name = "".join(c if c.isalnum() or c in "._- " else "_"
                            for c in cache.exe_name)
        filepath = os.path.join(self._cache_dir, f"{safe_name}.json")

        # Merge with existing cache if present
        existing = self.load_pointer_cache(cache.exe_name)
        if existing:
            # Merge pointers by label
            existing_labels = {p.target_label for p in existing.pointers}
            for p in cache.pointers:
                if p.target_label not in existing_labels:
                    existing.pointers.append(p)
                else:
                    # Update existing
                    for i, ep in enumerate(existing.pointers):
                        if ep.target_label == p.target_label:
                            existing.pointers[i] = p
                            break
            cache = existing

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(cache.to_dict(), f, indent=2, ensure_ascii=False)

    def load_pointer_cache(self, exe_name: str) -> Optional[ExecutableCache]:
        """Load pointer cache for an executable."""
        safe_name = "".join(c if c.isalnum() or c in "._- " else "_"
                            for c in exe_name)
        filepath = os.path.join(self._cache_dir, f"{safe_name}.json")
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                d = json.load(f)
            return ExecutableCache.from_dict(d)
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return None

    def list_cached_executables(self) -> list[str]:
        """List all executables with cached pointer data."""
        try:
            return sorted(
                [f.replace(".json", "") for f in os.listdir(self._cache_dir)
                 if f.endswith(".json")],
            )
        except FileNotFoundError:
            return []
