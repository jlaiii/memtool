"""
Background scan worker — runs memory scans in a QThread to keep the GUI responsive.
"""

from PyQt6.QtCore import QThread, pyqtSignal

from ..engine import MemoryEngine
from ..scanner import MemoryScanner, ValueType, ScanKind


class ScanWorker(QThread):
    """Runs a scan in a background thread, emitting progress and results."""

    # Signals
    progress = pyqtSignal(str, float)   # message, fraction
    finished = pyqtSignal(int)           # result count
    error = pyqtSignal(str)              # error message

    def __init__(
        self,
        engine: MemoryEngine,
        scanner: MemoryScanner,
        scan_type: str,  # "first" or "next"
        value_type: ValueType,
        scan_kind: ScanKind,
        search_value=None,
        search_value2=None,
        parent=None,
    ):
        super().__init__(parent)
        self._engine = engine
        self._scanner = scanner
        self._scan_type = scan_type
        self._value_type = value_type
        self._scan_kind = scan_kind
        self._search_value = search_value
        self._search_value2 = search_value2

    def run(self):
        """Execute the scan."""
        try:
            self._scanner.set_progress_callback(
                lambda msg, frac: self.progress.emit(msg, frac)
            )

            if self._scan_type == "first":
                count = self._scanner.first_scan(
                    self._value_type, self._scan_kind,
                    self._search_value, self._search_value2,
                )
            else:
                count = self._scanner.next_scan(
                    self._scan_kind, self._search_value, self._search_value2,
                )

            self.finished.emit(count)
        except Exception as e:
            self.error.emit(str(e))

    def cancel_scan(self):
        """Request cancellation of the scan."""
        self._scanner.cancel()
