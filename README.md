# MemTool

A high-performance Windows memory scanner and editor with a PyQt6 GUI, inspired by Cheat Engine. Features SIMD-accelerated scanning, pointer chain discovery, byte signature matching, and CLI integration for AI-assisted memory analysis.

[https://jlaiii.github.io/memtool](https://jlaiii.github.io/memtool)

## Features

### Memory Scanning
- **SIMD-accelerated scans** using NumPy -- 800+ MB/sec throughput on typical processes
- **11 value types**: 1/2/4/8-byte signed and unsigned integers, float, double, UTF-16 strings
- **8 scan kinds**: exact, bigger than, smaller than, changed, unchanged, increased, decreased, between
- **Unaligned scanning** -- finds values at every byte offset, matching Cheat Engine's behavior
- **Background threaded** scans keep the GUI responsive

### Memory Editing
- **Value freezing** at 250 Hz with automatic `VirtualProtectEx` page unprotection
- **Read-back verification** -- confirms writes succeeded and detects game overwrites
- **Batch editing** -- edit multiple addresses at once via context menu

### Pointer Scanning
- Find multi-level pointer chains rooted in static module addresses
- Module-aware offsets (`game.exe+0x2B4F10` style)
- Save best pointer chains to the cache for game restarts

### Signatures
- IDA-style byte pattern scanning with wildcards (`48 8B 05 ?? ?? ??`)
- Create unique signatures around values that survive game updates
- Signature-based smart cache -- auto-rediscover values on next launch

### Persistence
- Save/load address lists as JSON to `~/MemTool/address_lists/`
- Per-executable pointer caches in `~/MemTool/pointer_cache/`
- Smart re-attach: when you connect to a known process, cached signatures and pointers are offered automatically

### CLI for AI Integration
- 14 CLI commands with `--json` output for Claude Code or any external tool
- Full workflow: `scan` -> `next` -> `write` -> `freeze` via terminal
- Designed for autonomous AI-driven memory analysis

## Installation

### Requirements
- Windows 10 or later (64-bit)
- Python 3.10+
- Administrator privileges (required for memory access)

### Setup

```bash
git clone https://github.com/jlaiii/memtool.git
cd memtool
pip install -r requirements.txt
python run.py
```

MemTool will request Administrator elevation on startup via UAC. This is required to read and write other process memory.

## Usage

### GUI Mode

```bash
python run.py
```

1. Click **Select Process** and choose a target process
2. Enter a value, select the type, and click **First Scan**
3. Change the value in the target application and click **Next Scan** to filter
4. Double-click results to add them to the Address List
5. Toggle the freeze checkbox to lock values
6. Right-click any address for pointer scanning, signature creation, and hex viewing

### CLI Mode (for AI tools)

```bash
# List processes
python -m memtool.cli processes --json

# Attach to a process
python -m memtool.cli attach --pid 1234

# Scan for a value
python -m memtool.cli scan --type int4 --value 100

# Filter results
python -m memtool.cli next --kind increased

# Write a value
python -m memtool.cli write --address 0x7FF12345 --type int4 --value 999

# Freeze a value
python -m memtool.cli freeze --address 0x7FF12345 --type int4 --value 999

# Get results as JSON
python -m memtool.cli results --json
```

### Pointer Workflow

```
Session 1:
  1. Find the target value via scanning
  2. Right-click -> Find Pointer Chains
  3. Save the best chain to the cache

Session 2 (after game restart):
  1. Attach -> Smart Cache popup -> resolve automatically
  2. Or: Load a saved address list and re-scan with signatures
```

## Architecture

```
memtool/
  engine.py          -- Windows process memory I/O (ReadProcessMemory, WriteProcessMemory, VirtualQueryEx, VirtualProtectEx)
  scanner.py         -- SIMD-accelerated value scanner with NumPy
  pointer_scanner.py -- Multi-level pointer chain discovery
  signature.py       -- Byte pattern scanning with wildcard support
  persistence.py     -- JSON save/load for address lists and pointer caches
  gui/
    main_window.py   -- Full Cheat Engine-style PyQt6 interface
    process_dialog.py-- Searchable process picker
    scan_worker.py   -- Background scan thread
  cli/
    interface.py     -- 14 CLI commands with JSON output for AI tool integration
```

## Security

MemTool requires Administrator privileges to interact with other process memory. The Windows UAC prompt is triggered automatically on launch.

This tool is intended for:
- Single-player game modding
- Reverse engineering education
- Memory forensics research

Do not use this tool with multiplayer games or software that prohibits memory modification in its terms of service.

## License

MIT License
