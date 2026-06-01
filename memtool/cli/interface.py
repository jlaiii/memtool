"""
CLI interface for MemTool — designed for AI-assisted memory hacking.

Usage:
  python -m memtool.cli processes [--filter NAME] [--json]
  python -m memtool.cli attach --pid PID
  python -m memtool.cli detach
  python -m memtool.cli scan --type int4 --value 100 [--kind exact] [--json]
  python -m memtool.cli next --kind increased [--json]
  python -m memtool.cli results [--json] [--limit N]
  python -m memtool.cli read --address ADDR --type TYPE
  python -m memtool.cli write --address ADDR --type TYPE --value VALUE
  python -m memtool.cli freeze --address ADDR --type TYPE --value VALUE
  python -m memtool.cli unfreeze --address ADDR
  python -m memtool.cli unfreeze-all
  python -m memtool.cli regions [--json]
  python -m memtool.cli dump --address ADDR --size SIZE
  python -m memtool.cli status [--json]

All commands support --json for machine-readable output.
"""

from __future__ import annotations

import sys
import json
import argparse

from ..engine import MemoryEngine
from ..scanner import MemoryScanner, ValueType, ScanKind

# Global state — persists across CLI calls within a single `python -m memtool.cli` session
_engine: MemoryEngine | None = None
_scanner: MemoryScanner | None = None


def _get_engine() -> MemoryEngine:
    global _engine
    if _engine is None:
        _engine = MemoryEngine()
    return _engine


def _get_scanner() -> MemoryScanner:
    global _scanner
    if _scanner is None:
        _scanner = MemoryScanner(_get_engine())
    return _scanner


def _json_out(data: dict | list):
    """Print data as JSON to stdout."""
    print(json.dumps(data, indent=2, default=str))


def cmd_processes(args):
    """List running processes."""
    engine = _get_engine()
    procs = engine.list_processes()

    if args.filter:
        filter_lower = args.filter.lower()
        procs = [p for p in procs if filter_lower in p.name.lower() or str(p.pid) == args.filter]

    if args.json:
        _json_out([{"pid": p.pid, "name": p.name} for p in procs])
    else:
        print(f"{'PID':>8s}  {'Name':<40s}")
        print("-" * 52)
        for p in procs:
            print(f"{p.pid:8d}  {p.name:<40s}")
        print(f"\n{len(procs)} processes")


def cmd_attach(args):
    """Attach to a process by PID."""
    engine = _get_engine()
    pid = args.pid

    # Heuristic: if PID is small, try to find by name
    if pid < 100:
        procs = engine.list_processes()
        matches = [p for p in procs if args.pid_search.lower() in p.name.lower()] if hasattr(args, 'pid_search') else []
        if not matches:
            if not args.json:
                print(f"Error: PID {pid} not found. Use 'processes' to list PIDs.")
            return
        pid = matches[0].pid

    success = engine.open_process(pid)
    if args.json:
        _json_out({"success": success, "pid": pid})
    else:
        if success:
            print(f"Attached to PID {pid}")
        else:
            print(f"Error: Could not open process {pid}. Try running as Administrator.")


def cmd_detach(args):
    """Detach from the current process."""
    engine = _get_engine()
    scanner = _get_scanner()
    scanner.clear_session()
    engine.close_process()
    if not args.json:
        print("Detached from process")


def cmd_scan(args):
    """Perform a first scan."""
    engine = _get_engine()
    scanner = _get_scanner()

    if not engine.is_attached:
        if args.json:
            _json_out({"error": "No process attached"})
        else:
            print("Error: No process attached. Use 'attach --pid PID' first.")
        return

    value_type = ValueType.from_key(args.type)
    scan_kind = ScanKind.from_key(args.kind)

    # Parse value
    valueless = scan_kind in (ScanKind.CHANGED, ScanKind.UNCHANGED,
                               ScanKind.INCREASED, ScanKind.DECREASED)
    search_value = None
    if not valueless:
        search_value = _parse_value(args.value, value_type)

    scanner.first_scan(value_type, scan_kind, search_value)
    session = scanner.session
    count = session.result_count if session else 0

    if args.json:
        results = scanner.get_results()[:args.limit or 100]
        _json_out({
            "count": count,
            "pass": session.pass_number if session else 0,
            "elapsed_ms": session.elapsed_ms if session else 0,
            "results": [
                {"address": f"0x{r.address:016X}", "value": r.value, "type": r.data_type}
                for r in results
            ],
        })
    else:
        print(f"First scan complete: {count:,} results")
        _print_results(scanner, args.limit or 50)


def cmd_next(args):
    """Perform a next scan (filter previous results)."""
    engine = _get_engine()
    scanner = _get_scanner()

    if not engine.is_attached:
        if args.json:
            _json_out({"error": "No process attached"})
        else:
            print("Error: No process attached.")
        return

    session = scanner.session
    if session is None or not session.entries:
        if args.json:
            _json_out({"error": "No scan session — run 'scan' first"})
        else:
            print("Error: No scan session in progress. Run 'scan' first.")
        return

    scan_kind = ScanKind.from_key(args.kind)
    search_value = None
    valueless = scan_kind in (ScanKind.CHANGED, ScanKind.UNCHANGED,
                               ScanKind.INCREASED, ScanKind.DECREASED)
    if not valueless and args.value:
        search_value = _parse_value(args.value, session.value_type)

    count = scanner.next_scan(scan_kind, search_value)

    if args.json:
        results = scanner.get_results()[:args.limit or 100]
        _json_out({
            "count": count,
            "pass": scanner.session.pass_number if scanner.session else 0,
            "elapsed_ms": scanner.session.elapsed_ms if scanner.session else 0,
            "results": [
                {"address": f"0x{r.address:016X}", "value": r.value, "type": r.data_type}
                for r in results
            ],
        })
    else:
        print(f"Next scan complete: {count:,} results remaining")
        _print_results(scanner, args.limit or 50)


def cmd_results(args):
    """Print current scan results."""
    scanner = _get_scanner()
    if args.json:
        results = scanner.get_results()[:args.limit or None]
        session = scanner.session
        _json_out({
            "count": len(results),
            "pass": session.pass_number if session else 0,
            "results": [
                {"address": f"0x{r.address:016X}", "value": r.value,
                 "previous": r.previous_value, "type": r.data_type}
                for r in results
            ],
        })
    else:
        _print_results(scanner, args.limit or 50)


def cmd_read(args):
    """Read a value from a specific address."""
    engine = _get_engine()
    if not engine.is_attached:
        print("Error: No process attached.")
        return

    addr = _parse_address(args.address)
    value_type = ValueType.from_key(args.type)
    value = engine.read_value(addr, value_type.key)

    if args.json:
        _json_out({"address": f"0x{addr:016X}", "type": value_type.key, "value": value})
    else:
        print(f"0x{addr:016X} ({value_type.key}): {value}")


def cmd_write(args):
    """Write a value to a specific address."""
    engine = _get_engine()
    if not engine.is_attached:
        print("Error: No process attached.")
        return

    addr = _parse_address(args.address)
    value_type = ValueType.from_key(args.type)
    parsed = _parse_value(args.value, value_type)
    if parsed is None:
        print(f"Error: Could not parse '{args.value}' as {value_type.key}")
        return

    success = engine.write_value(addr, value_type.key, parsed)
    if args.json:
        _json_out({"address": f"0x{addr:016X}", "type": value_type.key,
                    "value": parsed, "success": success})
    else:
        if success:
            print(f"Wrote {parsed} to 0x{addr:016X}")
        else:
            print(f"Error: Write failed at 0x{addr:016X}")


def cmd_freeze(args):
    """Freeze a value at an address."""
    engine = _get_engine()
    if not engine.is_attached:
        print("Error: No process attached.")
        return

    addr = _parse_address(args.address)
    value_type = ValueType.from_key(args.type)
    parsed = _parse_value(args.value, value_type)
    if parsed is None:
        print(f"Error: Could not parse '{args.value}' as {value_type.key}")
        return

    fv = engine.freeze_value(addr, value_type.key, parsed)
    if args.json:
        _json_out({"address": f"0x{addr:016X}", "type": value_type.key,
                    "value": parsed, "frozen": fv is not None})
    else:
        if fv:
            print(f"Freezing 0x{addr:016X} = {parsed} ({value_type.key})")
        else:
            print(f"Error: Could not freeze 0x{addr:016X}")


def cmd_unfreeze(args):
    """Stop freezing a specific address."""
    engine = _get_engine()
    addr = _parse_address(args.address)
    engine.unfreeze_value(addr)
    if not args.json:
        print(f"Unfroze 0x{addr:016X}")


def cmd_unfreeze_all(args):
    """Stop freezing all addresses."""
    engine = _get_engine()
    engine.unfreeze_all()
    if not args.json:
        print("All values unfrozen")


def cmd_regions(args):
    """List readable memory regions."""
    engine = _get_engine()
    if not engine.is_attached:
        print("Error: No process attached.")
        return

    regions = engine.get_readable_regions()
    if args.json:
        _json_out([
            {"base": f"0x{r.base_address:016X}", "size": r.size,
             "end": f"0x{r.end_address:016X}", "protection": r.protection}
            for r in regions
        ])
    else:
        print(f"{'Base Address':>20s}  {'Size':>12s}  {'End Address':>20s}  Prot")
        print("-" * 72)
        for r in regions:
            print(f"0x{r.base_address:018X}  {r.size:12,d}  0x{r.end_address:018X}  0x{r.protection:04X}")
        print(f"\n{len(regions)} regions, total: {sum(r.size for r in regions) / (1<<20):.1f} MB")


def cmd_dump(args):
    """Hex dump at a specific address."""
    engine = _get_engine()
    if not engine.is_attached:
        print("Error: No process attached.")
        return

    addr = _parse_address(args.address)
    size = args.size or 256
    data = engine.read_bytes(addr, size)
    if data is None:
        print(f"Error: Could not read at 0x{addr:016X}")
        return

    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"0x{addr + offset:016X}  {hex_part:<48s}  |{ascii_part}|")


def cmd_status(args):
    """Show current session status."""
    engine = _get_engine()
    scanner = _get_scanner()
    session = scanner.session

    info = {
        "attached": engine.is_attached,
        "pid": engine.current_pid,
        "frozen_count": engine.get_frozen_count(),
        "scan_active": session is not None,
        "scan_pass": session.pass_number if session else 0,
        "scan_results": session.result_count if session else 0,
    }

    if args.json:
        _json_out(info)
    else:
        print(f"Attached:     {info['attached']}")
        print(f"PID:          {info['pid'] or '-'}")
        print(f"Frozen vals:  {info['frozen_count']}")
        print(f"Scan active:  {info['scan_active']}")
        print(f"Scan pass:    {info['scan_pass']}")
        print(f"Results:      {info['scan_results']:,}")


# ── Helpers ──────────────────────────────────────────────────────

def _parse_address(addr_str: str) -> int:
    """Parse an address string (supports hex: 0x..., or plain int)."""
    return int(addr_str, 0)


def _parse_value(text: str, value_type: ValueType):
    """Parse a string into a typed value."""
    try:
        if value_type.key.startswith("int") or value_type.key.startswith("uint"):
            return int(text, 0)
        if value_type.key in ("float", "double"):
            return float(text)
        if value_type.key == "string":
            return text
    except (ValueError, TypeError):
        return None
    return None


def _print_results(scanner: MemoryScanner, limit: int = 50):
    """Pretty-print scan results."""
    results = scanner.get_results()[:limit]
    session = scanner.session
    if not results:
        print("  (no results)")
        return
    print(f"\n{'Address':>20s}  {'Value':>20s}  {'Previous':>20s}  Type")
    print("-" * 78)
    for r in results:
        print(f"0x{r.address:018X}  {str(r.value):>20s}  {str(r.previous_value or '-'):>20s}  {r.data_type}")
    if session and session.result_count > limit:
        print(f"  ... and {session.result_count - limit:,} more (use --limit to show)")


# ── CLI Entry Point ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memtool",
        description="MemTool CLI — process memory scanner and editor for AI-assisted hacking.",
    )
    sub = parser.add_subparsers(dest="command", help="Command to run")

    # processes
    p = sub.add_parser("processes", help="List running processes")
    p.add_argument("--filter", "-f", type=str, help="Filter by name or PID")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # attach
    p = sub.add_parser("attach", help="Attach to a process")
    p.add_argument("--pid", "-p", type=int, required=True, help="Process ID")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # detach
    p = sub.add_parser("detach", help="Detach from current process")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # scan
    p = sub.add_parser("scan", help="First memory scan")
    p.add_argument("--type", "-t", type=str, default="int4", help="Value type (default: int4)")
    p.add_argument("--value", "-v", type=str, required=True, help="Search value")
    p.add_argument("--kind", "-k", type=str, default="exact", help="Scan kind (default: exact)")
    p.add_argument("--limit", "-l", type=int, default=100, help="Max results to show")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # next
    p = sub.add_parser("next", help="Next scan (filter previous results)")
    p.add_argument("--kind", "-k", type=str, default="exact", help="Scan kind")
    p.add_argument("--value", "-v", type=str, help="Search value (for exact/bigger/smaller)")
    p.add_argument("--limit", "-l", type=int, default=100, help="Max results to show")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # results
    p = sub.add_parser("results", help="Show current scan results")
    p.add_argument("--limit", "-l", type=int, default=100, help="Max results to show")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # read
    p = sub.add_parser("read", help="Read a value from an address")
    p.add_argument("--address", "-a", type=str, required=True, help="Memory address")
    p.add_argument("--type", "-t", type=str, required=True, help="Value type (e.g. int4, float)")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # write
    p = sub.add_parser("write", help="Write a value to an address")
    p.add_argument("--address", "-a", type=str, required=True, help="Memory address")
    p.add_argument("--type", "-t", type=str, required=True, help="Value type")
    p.add_argument("--value", "-v", type=str, required=True, help="Value to write")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # freeze
    p = sub.add_parser("freeze", help="Freeze a value at an address")
    p.add_argument("--address", "-a", type=str, required=True, help="Memory address")
    p.add_argument("--type", "-t", type=str, required=True, help="Value type")
    p.add_argument("--value", "-v", type=str, required=True, help="Value to freeze")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # unfreeze
    p = sub.add_parser("unfreeze", help="Stop freezing an address")
    p.add_argument("--address", "-a", type=str, required=True, help="Memory address")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # unfreeze-all
    p = sub.add_parser("unfreeze-all", help="Stop freezing all addresses")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # regions
    p = sub.add_parser("regions", help="List memory regions")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    # dump
    p = sub.add_parser("dump", help="Hex dump at an address")
    p.add_argument("--address", "-a", type=str, required=True, help="Memory address")
    p.add_argument("--size", "-s", type=int, default=256, help="Bytes to dump (default: 256)")

    # status
    p = sub.add_parser("status", help="Show session status")
    p.add_argument("--json", "-j", action="store_true", help="JSON output")

    return parser


def main(args: list[str] | None = None):
    """Entry point for `python -m memtool.cli ...`."""
    if args is None:
        args = sys.argv[1:]

    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return

    # Dispatch to command handler
    handlers = {
        "processes":    cmd_processes,
        "attach":       cmd_attach,
        "detach":       cmd_detach,
        "scan":         cmd_scan,
        "next":         cmd_next,
        "results":      cmd_results,
        "read":         cmd_read,
        "write":        cmd_write,
        "freeze":       cmd_freeze,
        "unfreeze":     cmd_unfreeze,
        "unfreeze-all": cmd_unfreeze_all,
        "regions":      cmd_regions,
        "dump":         cmd_dump,
        "status":       cmd_status,
    }

    handler = handlers.get(parsed.command)
    if handler:
        handler(parsed)


if __name__ == "__main__":
    main()
