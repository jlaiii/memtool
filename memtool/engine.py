"""
Core memory engine — Windows process memory operations via ctypes.

Provides:
  - Process enumeration (name, PID, architecture)
  - Opening/closing process handles
  - Reading/writing memory
  - Enumerating readable memory regions
  - Freezing values (periodic write)
"""

import ctypes
import ctypes.wintypes as wintypes
from ctypes import (
    c_void_p, c_size_t, c_ulonglong, c_char,
    byref, sizeof, POINTER, cast, memmove, string_at,
    WinError, get_last_error,
)
from dataclasses import dataclass, field
from typing import Optional, Iterator, Callable
import struct
import threading
import time

# ── Win32 constants ──────────────────────────────────────────────

# Process access rights
PROCESS_VM_READ           = 0x0010
PROCESS_VM_WRITE          = 0x0020
PROCESS_VM_OPERATION      = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFO = 0x1000
PROCESS_ALL_ACCESS        = 0x1F0FFF

# Toolhelp snapshot
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE  = 0x00000008

# Memory constants
MEM_COMMIT  = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED  = 0x40000
MEM_IMAGE   = 0x1000000

# Page protection (readable if not PAGE_NOACCESS or PAGE_EXECUTE)
PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100
PAGE_NOCACHE           = 0x200

READABLE_PROTECTIONS = {
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
}

# ── Win32 structures ──────────────────────────────────────────────

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   POINTER(c_ulonglong)),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           wintypes.WCHAR * 260),
    ]

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",        wintypes.DWORD),
        ("th32ModuleID",  wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage",  wintypes.DWORD),
        ("ProccntUsage",  wintypes.DWORD),
        ("modBaseAddr",   POINTER(ctypes.c_byte)),
        ("modBaseSize",   wintypes.DWORD),
        ("hModule",       wintypes.HMODULE),
        ("szModule",      wintypes.WCHAR * 256),
        ("szExePath",     wintypes.WCHAR * 260),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       c_void_p),
        ("AllocationBase",    c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId",       wintypes.WORD),
        ("RegionSize",        c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD),
        ("wReserved",              wintypes.WORD),
        ("dwPageSize",             wintypes.DWORD),
        ("lpMinimumApplicationAddress", c_void_p),
        ("lpMaximumApplicationAddress", c_void_p),
        ("dwActiveProcessorMask",  POINTER(c_ulonglong)),
        ("dwNumberOfProcessors",   wintypes.DWORD),
        ("dwProcessorType",        wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD),
        ("wProcessorLevel",        wintypes.WORD),
        ("wProcessorRevision",     wintypes.WORD),
    ]

# ── Win32 function bindings ──────────────────────────────────────

_kernel32 = ctypes.windll.kernel32

# Required for GetLastError diagnostics
_kernel32.SetLastError.argtypes = [wintypes.DWORD]
_kernel32.SetLastError.restype = None

# Process enumeration
_CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
_CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_CreateToolhelp32Snapshot.restype = wintypes.HANDLE

_Process32FirstW = _kernel32.Process32FirstW
_Process32FirstW.argtypes = [wintypes.HANDLE, POINTER(PROCESSENTRY32W)]
_Process32FirstW.restype = wintypes.BOOL

_Process32NextW = _kernel32.Process32NextW
_Process32NextW.argtypes = [wintypes.HANDLE, POINTER(PROCESSENTRY32W)]
_Process32NextW.restype = wintypes.BOOL

# Module enumeration
_Module32FirstW = _kernel32.Module32FirstW
_Module32FirstW.argtypes = [wintypes.HANDLE, POINTER(MODULEENTRY32W)]
_Module32FirstW.restype = wintypes.BOOL

_Module32NextW = _kernel32.Module32NextW
_Module32NextW.argtypes = [wintypes.HANDLE, POINTER(MODULEENTRY32W)]
_Module32NextW.restype = wintypes.BOOL

# Process handle
_OpenProcess = _kernel32.OpenProcess
_OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_OpenProcess.restype = wintypes.HANDLE

_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL

# Memory operations
_ReadProcessMemory = _kernel32.ReadProcessMemory
_ReadProcessMemory.argtypes = [
    wintypes.HANDLE, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)
]
_ReadProcessMemory.restype = wintypes.BOOL

_WriteProcessMemory = _kernel32.WriteProcessMemory
_WriteProcessMemory.argtypes = [
    wintypes.HANDLE, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)
]
_WriteProcessMemory.restype = wintypes.BOOL

_VirtualProtectEx = _kernel32.VirtualProtectEx
_VirtualProtectEx.argtypes = [
    wintypes.HANDLE, c_void_p, c_size_t, wintypes.DWORD, POINTER(wintypes.DWORD)
]
_VirtualProtectEx.restype = wintypes.BOOL

_VirtualQueryEx = _kernel32.VirtualQueryEx
_VirtualQueryEx.argtypes = [
    wintypes.HANDLE, c_void_p, POINTER(MEMORY_BASIC_INFORMATION), c_size_t
]
_VirtualQueryEx.restype = c_size_t

_GetSystemInfo = _kernel32.GetSystemInfo
_GetSystemInfo.argtypes = [POINTER(SYSTEM_INFO)]
_GetSystemInfo.restype = None

_IsWow64Process = _kernel32.IsWow64Process
_IsWow64Process.argtypes = [wintypes.HANDLE, POINTER(wintypes.BOOL)]
_IsWow64Process.restype = wintypes.BOOL


# ── Public types ──────────────────────────────────────────────────

@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    name: str
    architecture: str = "unknown"  # "x86" or "x64"

@dataclass
class ModuleInfo:
    """Information about a loaded module in a process."""
    name: str
    base_address: int
    size: int

@dataclass
class MemoryRegion:
    """A readable, committed memory region."""
    base_address: int
    size: int
    protection: int
    type: int
    state: int

    @property
    def end_address(self) -> int:
        return self.base_address + self.size

@dataclass
class ScanResult:
    """A single scan hit."""
    address: int
    value: object  # the value found
    display_value: str  # formatted for display
    data_type: str

@dataclass
class FrozenValue:
    """A value being frozen (periodically rewritten)."""
    address: int
    value: bytes
    data_type: str
    interval: float = 0.1  # seconds between writes


# ── Engine class ──────────────────────────────────────────────────

class MemoryEngine:
    """Manages process memory operations on Windows."""

    def __init__(self):
        self._process_handle: Optional[int] = None
        self._pid: Optional[int] = None
        self._process_name: Optional[str] = None
        self._is_wow64: bool = False
        self._has_write: bool = False
        self._frozen_values: dict[int, FrozenValue] = {}
        self._freeze_thread: Optional[threading.Thread] = None
        self._freeze_running: bool = False
        # Diagnostics
        self._freeze_tick_count: int = 0
        self._freeze_fail_count: int = 0
        self._last_write_ok: bool = True
        self._log_callback: Optional[Callable[[str], None]] = None

    # ── Process enumeration ───────────────────────────────────

    @staticmethod
    def list_processes() -> list[ProcessInfo]:
        """Enumerate all running processes."""
        processes = []
        snapshot = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == wintypes.HANDLE(-1).value:
            return processes

        entry = PROCESSENTRY32W()
        entry.dwSize = sizeof(PROCESSENTRY32W)

        if _Process32FirstW(snapshot, byref(entry)):
            while True:
                name = entry.szExeFile
                # Handle null-terminated WCHAR string
                if isinstance(name, bytes):
                    name = name.decode("utf-16-le", errors="replace").rstrip("\x00")
                processes.append(ProcessInfo(
                    pid=entry.th32ProcessID,
                    name=name,
                ))
                if not _Process32NextW(snapshot, byref(entry)):
                    break

        _CloseHandle(snapshot)
        return sorted(processes, key=lambda p: p.name.lower())

    # ── Module enumeration ────────────────────────────────────────

    def get_modules(self) -> list[ModuleInfo]:
        """Enumerate loaded modules of the ATTACHED process."""
        modules = []
        if not self._pid:
            return modules

        snapshot = _CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS, self._pid
        )
        if snapshot == wintypes.HANDLE(-1).value:
            return modules

        entry = MODULEENTRY32W()
        entry.dwSize = sizeof(MODULEENTRY32W)

        if _Module32FirstW(snapshot, byref(entry)):
            while True:
                name = entry.szModule
                if not isinstance(name, str):
                    name = name.decode("utf-16-le", errors="replace").rstrip("\x00")
                base = ctypes.cast(entry.modBaseAddr, c_void_p).value or 0
                modules.append(ModuleInfo(
                    name=name,
                    base_address=base,
                    size=entry.modBaseSize,
                ))
                if not _Module32NextW(snapshot, byref(entry)):
                    break

        _CloseHandle(snapshot)
        return modules

    # ── Process attachment ────────────────────────────────────

    def open_process(self, pid: int) -> bool:
        """Open a process for memory access. Returns True on success.

        Tries three access levels:
          1. Full read+write+operation (normal, needs admin for system procs)
          2. PROCESS_ALL_ACCESS (most permissive)
          3. Read-only fallback (writes will fail)
        Sets self._has_write accordingly — check has_write_access before writing.
        """
        self.close_process()

        # Tier 1: Normal full access
        desired = (PROCESS_VM_READ | PROCESS_VM_WRITE |
                   PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)
        handle = _OpenProcess(desired, False, pid)
        has_write = bool(handle)

        # Tier 2: Try ALL_ACCESS (sometimes works when tier 1 doesn't)
        if not handle:
            handle = _OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            has_write = bool(handle)

        # Tier 3: Read-only fallback
        if not handle:
            desired = (PROCESS_VM_READ | PROCESS_VM_OPERATION |
                       PROCESS_QUERY_LIMITED_INFO)
            handle = _OpenProcess(desired, False, pid)
            has_write = False

        if not handle:
            return False

        self._process_handle = handle
        self._pid = pid
        self._has_write = has_write

        # Detect if this is a 32-bit process on 64-bit OS
        is_wow = wintypes.BOOL(False)
        _IsWow64Process(handle, byref(is_wow))
        self._is_wow64 = bool(is_wow.value)

        return True

    def close_process(self):
        """Close the current process handle."""
        self.stop_freezing()
        if self._process_handle:
            _CloseHandle(self._process_handle)
        self._process_handle = None
        self._pid = None
        self._is_wow64 = False
        self._has_write = False

    @property
    def is_attached(self) -> bool:
        return self._process_handle is not None and self._pid is not None

    @property
    def has_write_access(self) -> bool:
        """True if the process handle was opened with write permissions."""
        return self._has_write

    @property
    def current_pid(self) -> Optional[int]:
        return self._pid

    @property
    def freeze_stats(self) -> dict:
        """Diagnostics for the freeze loop."""
        return {
            "ticks": self._freeze_tick_count,
            "failures": self._freeze_fail_count,
            "frozen_count": len(self._frozen_values),
            "running": self._freeze_running,
            "last_write_ok": self._last_write_ok,
        }

    def set_log_callback(self, cb: Optional[Callable[[str], None]]):
        """Set a callback for diagnostic log messages."""
        self._log_callback = cb

    def _log(self, msg: str):
        """Emit a log message if a callback is set."""
        if self._log_callback:
            self._log_callback(msg)

    # ── Memory reading / writing ──────────────────────────────

    def read_bytes(self, address: int, size: int) -> Optional[bytes]:
        """Read raw bytes from process memory."""
        if not self._process_handle:
            return None
        buf = ctypes.create_string_buffer(size)
        bytes_read = c_size_t(0)
        success = _ReadProcessMemory(
            self._process_handle, c_void_p(address), buf, size, byref(bytes_read)
        )
        if not success or bytes_read.value == 0:
            return None
        return buf.raw[:bytes_read.value]

    def write_bytes(self, address: int, data: bytes) -> bool:
        """Write raw bytes to process memory.

        Aggressively ensures the page is writable via VirtualProtectEx.
        Does NOT restore original protection — leaves the page writable
        so subsequent writes and freeze ticks succeed without re-unprotecting.
        """
        if not self._process_handle:
            return False

        size = len(data)

        # Query current page protection
        mbi = MEMORY_BASIC_INFORMATION()
        result = _VirtualQueryEx(
            self._process_handle, c_void_p(address),
            byref(mbi), sizeof(mbi)
        )
        current_protect = mbi.Protect if result else 0

        # Anything without WRITE in the name needs to be made writable
        WRITABLE = {PAGE_READWRITE, PAGE_EXECUTE_READWRITE,
                    PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY}

        if current_protect not in WRITABLE:
            new_prot = PAGE_EXECUTE_READWRITE
            old_tmp = wintypes.DWORD(0)
            _VirtualProtectEx(
                self._process_handle, c_void_p(address),
                c_size_t(max(size, 1)), new_prot, byref(old_tmp)
            )
            # Deliberately do NOT restore — leave writable

        # Write
        _kernel32.SetLastError(0)
        buf = ctypes.create_string_buffer(data, size)
        bytes_written = c_size_t(0)
        success = _WriteProcessMemory(
            self._process_handle, c_void_p(address), buf, size, byref(bytes_written)
        )
        ok = bool(success) and bytes_written.value == size

        if not ok:
            err = get_last_error()
            self._log(f"WriteProcessMemory failed at 0x{address:X}: err={err}, "
                      f"prot=0x{current_protect:04X}, size={size}")

            # Retry: force VirtualProtectEx then write again
            old_tmp = wintypes.DWORD(0)
            _VirtualProtectEx(
                self._process_handle, c_void_p(address),
                c_size_t(max(size, 1)), PAGE_EXECUTE_READWRITE, byref(old_tmp)
            )
            _kernel32.SetLastError(0)
            bytes_written2 = c_size_t(0)
            success2 = _WriteProcessMemory(
                self._process_handle, c_void_p(address), buf, size, byref(bytes_written2)
            )
            ok = bool(success2) and bytes_written2.value == size

            if ok:
                self._log(f"Write retry succeeded at 0x{address:X} (was prot=0x{current_protect:04X})")
            else:
                err2 = get_last_error()
                self._log(f"Write retry ALSO FAILED at 0x{address:X}: err={err2} "
                          f"→ likely anti-cheat or inaccessible page")

        return ok

    def read_value(self, address: int, data_type: str) -> Optional[object]:
        """Read a typed value from memory."""
        sizes = {
            "int1": 1, "int2": 2, "int4": 4, "int8": 8,
            "uint1": 1, "uint2": 2, "uint4": 4, "uint8": 8,
            "float": 4, "double": 8,
        }
        size = sizes.get(data_type)
        if size is None:
            return None
        data = self.read_bytes(address, size)
        if data is None:
            return None
        return self._unpack_value(data, data_type)

    def write_value(self, address: int, data_type: str, value) -> bool:
        """Write a typed value to memory."""
        fmt_map = {
            "int1": ("b", 1),   "int2": ("h", 2),   "int4": ("i", 4),   "int8": ("q", 8),
            "uint1": ("B", 1),  "uint2": ("H", 2),  "uint4": ("I", 4),  "uint8": ("Q", 8),
            "float": ("f", 4),  "double": ("d", 8),
        }
        entry = fmt_map.get(data_type)
        if entry is None:
            # String types
            if data_type == "string":
                if isinstance(value, str):
                    data = value.encode("utf-16-le")
                else:
                    data = bytes(value)
                return self.write_bytes(address, data)
            return False

        fmt, size = entry
        try:
            data = struct.pack(f"<{fmt}", value)
        except struct.error:
            return False
        return self.write_bytes(address, data)

    @staticmethod
    def _unpack_value(data: bytes, data_type: str) -> Optional[object]:
        """Unpack raw bytes into a typed value."""
        fmt_map = {
            "int1": ("<b", 1),   "int2": ("<h", 2),   "int4": ("<i", 4),   "int8": ("<q", 8),
            "uint1": ("<B", 1),  "uint2": ("<H", 2),  "uint4": ("<I", 4),  "uint8": ("<Q", 8),
            "float": ("<f", 4),  "double": ("<d", 8),
        }
        entry = fmt_map.get(data_type)
        if entry is None:
            if data_type == "string":
                try:
                    return data.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    return repr(data)
            return None
        fmt, size = entry
        try:
            return struct.unpack(fmt, data[:size])[0]
        except struct.error:
            return None

    @staticmethod
    def pack_value(value, data_type: str) -> Optional[bytes]:
        """Pack a typed value into bytes."""
        fmt_map = {
            "int1": ("<b", 1),   "int2": ("<h", 2),   "int4": ("<i", 4),   "int8": ("<q", 8),
            "uint1": ("<B", 1),  "uint2": ("<H", 2),  "uint4": ("<I", 4),  "uint8": ("<Q", 8),
            "float": ("<f", 4),  "double": ("<d", 8),
        }
        entry = fmt_map.get(data_type)
        if entry is not None:
            fmt, size = entry
            try:
                return struct.pack(fmt, value)
            except struct.error:
                return None
        if data_type == "string":
            if isinstance(value, str):
                return value.encode("utf-16-le")
            return bytes(value)
        return None

    # ── Memory region enumeration ──────────────────────────────

    def enumerate_regions(self) -> Iterator[MemoryRegion]:
        """Yield ALL committed memory regions of the attached process.

        Unlike the old version, this does NOT filter by protection.
        It yields every committed page — matching Cheat Engine's behavior.
        Some pages may fail to read (we handle that in the scanner).
        """
        if not self._process_handle:
            return

        # Get system address range
        sys_info = SYSTEM_INFO()
        _GetSystemInfo(byref(sys_info))
        min_addr = cast(sys_info.lpMinimumApplicationAddress, c_void_p).value
        max_addr = cast(sys_info.lpMaximumApplicationAddress, c_void_p).value

        # For 64-bit processes, scan up to the highest user-mode address
        if not max_addr or max_addr < 0x10000:
            # Detect 64-bit: max address for 64-bit user mode is ~0x7FFFFFFFFFFF
            # For 32-bit: 0x7FFFFFFF
            is_64bit = not self._is_wow64
            max_addr = 0x7FFFFFFFFFFF if is_64bit else 0x7FFFFFFF

        address = min_addr or 0x10000
        mbi = MEMORY_BASIC_INFORMATION()

        while address < max_addr:
            result = _VirtualQueryEx(
                self._process_handle, c_void_p(address), byref(mbi), sizeof(mbi)
            )
            if result == 0:
                # VirtualQueryEx failed — skip ahead by allocation granularity
                address += 0x10000
                continue

            if mbi.State == MEM_COMMIT:
                # Cheat Engine scans ALL committed pages regardless of protection.
                # Skip only PAGE_NOACCESS (genuinely unreadable) and guard pages.
                if mbi.Protect != PAGE_NOACCESS:
                    yield MemoryRegion(
                        base_address=mbi.BaseAddress or 0,
                        size=mbi.RegionSize,
                        protection=mbi.Protect,
                        type=mbi.Type,
                        state=mbi.State,
                    )

            next_addr = (mbi.BaseAddress or 0) + mbi.RegionSize
            if next_addr <= address:
                address += 0x10000  # prevent infinite loop
            else:
                address = next_addr

    def get_readable_regions(self) -> list[MemoryRegion]:
        """Return all readable, committed memory regions as a list."""
        return list(self.enumerate_regions())

    # ── Bulk region reading ───────────────────────────────────

    def read_region(self, region: MemoryRegion) -> Optional[bytes]:
        """Read an entire memory region. Returns None on failure."""
        return self.read_bytes(region.base_address, region.size)

    # ── Value freezing ────────────────────────────────────────

    def freeze_value(self, address: int, data_type: str, value) -> Optional[FrozenValue]:
        """Start freezing a value at the given address."""
        data = self.pack_value(value, data_type)
        if data is None:
            return None

        fv = FrozenValue(
            address=address,
            value=data,
            data_type=data_type,
            interval=0.05,  # 50ms refresh rate
        )
        self._frozen_values[address] = fv
        self._ensure_freeze_thread()
        return fv

    def unfreeze_value(self, address: int):
        """Stop freezing a value."""
        self._frozen_values.pop(address, None)

    def unfreeze_all(self):
        """Stop freezing all values."""
        self._frozen_values.clear()

    def _ensure_freeze_thread(self):
        """Start the freeze thread if not already running."""
        if self._freeze_thread and self._freeze_thread.is_alive():
            return
        self._freeze_running = True
        self._freeze_fail_count = 0
        self._freeze_tick_count = 0
        self._freeze_thread = threading.Thread(target=self._freeze_loop, daemon=True)
        self._freeze_thread.start()

    def _freeze_loop(self):
        """Continuously rewrite frozen values at ~250Hz (4ms interval).

        Matches/exceeds typical game tick rates (60fps = 16ms).
        Writes all frozen values in a tight batch per tick, then sleeps.
        """
        import time as _time
        while self._freeze_running and self._frozen_values:
            self._freeze_tick_count += 1
            fail_this_tick = 0
            total_this_tick = 0

            for addr, fv in list(self._frozen_values.items()):
                total_this_tick += 1
                ok = self.write_bytes(addr, fv.value)
                if not ok:
                    fail_this_tick += 1
                    self._freeze_fail_count += 1

            self._last_write_ok = (fail_this_tick == 0)

            if fail_this_tick > 0 and self._freeze_tick_count % 60 == 1:
                # Log every ~60 ticks (~240ms) to avoid spam
                self._log(
                    f"[freeze #{self._freeze_tick_count}] "
                    f"{fail_this_tick}/{total_this_tick} writes FAILED"
                )

            _time.sleep(0.004)  # 4ms → ~250 writes/sec per value

    def stop_freezing(self):
        """Stop the freeze loop."""
        self._freeze_running = False
        if self._freeze_thread:
            self._freeze_thread.join(timeout=1.0)
            self._freeze_thread = None
        self._freeze_tick_count = 0
        self._freeze_fail_count = 0
        self._last_write_ok = True
        self._frozen_values.clear()

    def get_frozen_count(self) -> int:
        return len(self._frozen_values)

    # ── Cleanup ───────────────────────────────────────────────

    def __del__(self):
        self.close_process()
