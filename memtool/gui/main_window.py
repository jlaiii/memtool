"""
Main application window — the Cheat Engine-like UI.

Layout:
  ┌──────────────────────────────────────────────────────────┐
  │  [Select Process]  PID: 1234 — game.exe                  │
  ├──────────────────────────────────────────────────────────┤
  │  Value: [____]  Type: [4-Byte ▼]  Scan: [Exact ▼]       │
  │  [First Scan]  [Next Scan]  [New Scan]  [✕ Cancel]      │
  │  ████████████░░░░░░  65%  Scanning 0x1A2B3C...          │
  ├──────────────────────────────────────────────────────────┤
  │  Address       │ Value   │ Previous  │ Type    │ Info   │
  │  0x7FF12345... │ 100     │ 75        │ int4    │        │
  │  0x7FF23456... │ 100     │ -         │ int4    │        │
  ├──────────────────────────────────────────────────────────┤
  │  [Address List] [CLI / AI]                               │
  │  ☑ Freeze │ Address      │ Type  │ Value  │ Description │
  │  ────────────────────────────────────────────────────────│
  │  Status: 1,234 results | Scan pass #2 | 342ms           │
  └──────────────────────────────────────────────────────────┘
"""

import re
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QProgressBar,
    QHeaderView, QAbstractItemView, QMenu, QMessageBox,
    QTabWidget, QInputDialog, QCheckBox, QSplitter,
    QFrame, QApplication, QPlainTextEdit, QDialog,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QAction, QClipboard

from ..engine import MemoryEngine
from ..scanner import MemoryScanner, ValueType, ScanKind, ScanEntry
from ..pointer_scanner import PointerScanner, PointerChain
from ..signature import SignatureScanner, SavedOffset
from ..persistence import (
    PersistenceManager, AddressList, AddressEntry, PointerCache, ExecutableCache,
)
from .scan_worker import ScanWorker
from .process_dialog import ProcessDialog


class MainWindow(QMainWindow):
    """MemTool main application window."""

    STATUS_REFRESH_MS = 2000  # refresh frozen values display interval

    def __init__(self):
        super().__init__()

        self._engine = MemoryEngine()
        self._scanner = MemoryScanner(self._engine)
        self._ptr_scanner = PointerScanner(self._engine)
        self._sig_scanner = SignatureScanner(self._engine)
        self._persistence = PersistenceManager()
        self._scan_worker: ScanWorker | None = None
        self._frozen_items: dict[int, dict] = {}  # address -> {type, value, desc}
        self._process_name: str = ""

        self.setWindowTitle("MemTool — Memory Scanner & Editor")
        self.setMinimumSize(900, 650)
        self.resize(1100, 750)

        self._build_ui()
        self._update_process_label()

        # Status refresh timer (updates frozen value display)
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._refresh_frozen_display)
        self._status_timer.start(self.STATUS_REFRESH_MS)

    def _append_log(self, msg: str):
        """Append a timestamped line to the debug log."""
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._log_text.appendPlainText(f"[{ts}] {msg}")

    # ── UI Construction ──────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(6)

        # ── Admin warning banner ────────────────────────────
        import ctypes as _ctypes
        self._is_admin = False
        try:
            self._is_admin = bool(_ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass

        self._admin_banner = QLabel()
        self._admin_banner.setVisible(not self._is_admin)
        self._admin_banner.setTextFormat(Qt.TextFormat.RichText)
        self._admin_banner.setStyleSheet(
            "QLabel { background-color: #f38ba8; color: #1e1e2e; padding: 8px 12px; "
            "border-radius: 4px; font-weight: bold; font-size: 13px; }"
        )
        self._admin_banner.setText(
            "⚠ NOT RUNNING AS ADMINISTRATOR — memory writes will FAIL. "
            "Close and re-launch with admin rights (right-click → Run as Administrator)."
        )
        main_layout.addWidget(self._admin_banner)

        # ── Top bar: Process selector ──────────────────────
        top = QHBoxLayout()
        self._process_btn = QPushButton("🎯 Select Process")
        self._process_btn.setMinimumHeight(34)
        self._process_btn.clicked.connect(self._show_process_dialog)
        top.addWidget(self._process_btn)

        self._process_label = QLabel("No process attached")
        self._process_label.setStyleSheet("color: #888; font-weight: bold;")
        top.addWidget(self._process_label, 1)

        self._detach_btn = QPushButton("✕ Detach")
        self._detach_btn.setEnabled(False)
        self._detach_btn.clicked.connect(self._detach_process)
        top.addWidget(self._detach_btn)
        main_layout.addLayout(top)

        # Separator
        main_layout.addWidget(self._make_separator())

        # ── Scan panel ─────────────────────────────────────
        scan_layout = QHBoxLayout()
        scan_layout.setSpacing(8)

        scan_layout.addWidget(QLabel("Value:"))
        self._value_input = QLineEdit()
        self._value_input.setPlaceholderText("Enter value to scan...")
        self._value_input.setMinimumWidth(140)
        self._value_input.returnPressed.connect(self._on_first_scan)
        scan_layout.addWidget(self._value_input)

        scan_layout.addWidget(QLabel("Type:"))
        self._type_combo = QComboBox()
        for vt in ValueType:
            self._type_combo.addItem(vt.label, vt.key)
        self._type_combo.setCurrentIndex(2)  # Default: 4-byte signed (INT4)
        scan_layout.addWidget(self._type_combo)

        scan_layout.addWidget(QLabel("Scan:"))
        self._scan_kind_combo = QComboBox()
        for sk in ScanKind:
            self._scan_kind_combo.addItem(sk.label, sk.key)
        scan_layout.addWidget(self._scan_kind_combo)

        # Second value input (for "between" scans)
        self._value2_label = QLabel("and:")
        self._value2_label.setVisible(False)
        self._value2_input = QLineEdit()
        self._value2_input.setPlaceholderText("Max value")
        self._value2_input.setMaximumWidth(100)
        self._value2_input.setVisible(False)
        scan_layout.addWidget(self._value2_label)
        scan_layout.addWidget(self._value2_input)

        # Show/hide second value for "between"
        self._scan_kind_combo.currentIndexChanged.connect(self._on_scan_kind_changed)

        scan_layout.addStretch()
        main_layout.addLayout(scan_layout)

        # ── Scan buttons ───────────────────────────────────
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(6)

        self._first_scan_btn = QPushButton("🔍 First Scan")
        self._first_scan_btn.setMinimumHeight(32)
        self._first_scan_btn.clicked.connect(self._on_first_scan)
        self._first_scan_btn.setEnabled(False)
        btn_layout.addWidget(self._first_scan_btn)

        self._next_scan_btn = QPushButton("→ Next Scan")
        self._next_scan_btn.setMinimumHeight(32)
        self._next_scan_btn.clicked.connect(self._on_next_scan)
        self._next_scan_btn.setEnabled(False)
        btn_layout.addWidget(self._next_scan_btn)

        self._new_scan_btn = QPushButton("🔄 New Scan")
        self._new_scan_btn.setMinimumHeight(32)
        self._new_scan_btn.clicked.connect(self._on_new_scan)
        self._new_scan_btn.setEnabled(False)
        btn_layout.addWidget(self._new_scan_btn)

        self._cancel_btn = QPushButton("✕ Cancel")
        self._cancel_btn.setMinimumHeight(32)
        self._cancel_btn.clicked.connect(self._on_cancel_scan)
        self._cancel_btn.setEnabled(False)
        btn_layout.addWidget(self._cancel_btn)

        btn_layout.addStretch()

        self._scan_status_label = QLabel("")
        self._scan_status_label.setStyleSheet("color: #aaa;")
        btn_layout.addWidget(self._scan_status_label)
        main_layout.addLayout(btn_layout)

        # ── Progress bar ───────────────────────────────────
        self._progress_bar = QProgressBar()
        self._progress_bar.setMaximum(100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFormat("Ready")
        self._progress_bar.setMaximumHeight(20)
        main_layout.addWidget(self._progress_bar)

        # ── Results table ──────────────────────────────────
        main_layout.addWidget(QLabel("Scan Results:"))
        self._results_table = QTableWidget()
        self._results_table.setColumnCount(5)
        self._results_table.setHorizontalHeaderLabels([
            "Address", "Value", "Previous", "Type", "Region Info"
        ])
        self._results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._results_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._results_table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._results_table.setAlternatingRowColors(True)
        self._results_table.setSortingEnabled(True)
        self._results_table.verticalHeader().setVisible(False)
        self._results_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._results_table.customContextMenuRequested.connect(self._on_result_context_menu)
        self._results_table.doubleClicked.connect(self._on_result_double_click)

        hdr = self._results_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Address
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Value
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)  # Previous
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Type
        hdr.setStretchLastSection(True)  # Region Info

        main_layout.addWidget(self._results_table, 1)

        # ── Bottom tabs: Address List + Log ─────────────────
        self._bottom_tabs = QTabWidget()
        self._bottom_tabs.setMinimumHeight(220)

        # Tab 1: Address / Frozen list
        self._frozen_table = QTableWidget()
        self._frozen_table.setColumnCount(5)
        self._frozen_table.setHorizontalHeaderLabels([
            "Freeze", "Address", "Type", "Current Value", "Description"
        ])
        self._frozen_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._frozen_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._frozen_table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._frozen_table.verticalHeader().setVisible(False)
        self._frozen_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._frozen_table.customContextMenuRequested.connect(self._on_frozen_context_menu)
        self._frozen_table.doubleClicked.connect(self._on_frozen_double_click)
        fh = self._frozen_table.horizontalHeader()
        fh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._frozen_table.setColumnWidth(0, 50)
        fh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        fh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        fh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        fh.setStretchLastSection(True)

        frozen_widget = QWidget()
        frozen_layout = QVBoxLayout(frozen_widget)
        frozen_layout.setContentsMargins(4, 4, 4, 4)
        frozen_btns = QHBoxLayout()
        self._freeze_selected_btn = QPushButton("➕ Add Selected from Results")
        self._freeze_selected_btn.clicked.connect(self._add_selected_to_frozen)
        frozen_btns.addWidget(self._freeze_selected_btn)
        self._unfreeze_all_btn = QPushButton("✕ Unfreeze All")
        self._unfreeze_all_btn.clicked.connect(self._unfreeze_all)
        frozen_btns.addWidget(self._unfreeze_all_btn)
        self._delete_all_btn = QPushButton("Delete All")
        self._delete_all_btn.clicked.connect(self._delete_all_frozen)
        frozen_btns.addWidget(self._delete_all_btn)
        frozen_btns.addStretch()
        self._save_list_btn = QPushButton("💾 Save List")
        self._save_list_btn.clicked.connect(self._save_address_list)
        frozen_btns.addWidget(self._save_list_btn)
        self._load_list_btn = QPushButton("📂 Load List")
        self._load_list_btn.clicked.connect(self._load_address_list)
        frozen_btns.addWidget(self._load_list_btn)
        frozen_layout.addLayout(frozen_btns)
        frozen_layout.addWidget(self._frozen_table)
        self._bottom_tabs.addTab(frozen_widget, "📌 Address List")

        # Tab 2: CLI / AI output
        cli_widget = QWidget()
        cli_layout = QVBoxLayout(cli_widget)
        cli_layout.setContentsMargins(4, 4, 4, 4)
        cli_help = QLabel(
            "<b>CLI / AI Integration</b><br>"
            "Use these commands with Claude Code or any CLI tool:<br>"
            "<code>python -m memtool.cli processes</code> — list processes<br>"
            "<code>python -m memtool.cli attach --pid 1234</code> — attach to PID<br>"
            "<code>python -m memtool.cli scan --type int4 --value 100 --kind exact</code><br>"
            "<code>python -m memtool.cli write --address 0x7FF... --type int4 --value 999</code><br>"
            "<code>python -m memtool.cli freeze --address 0x7FF... --type int4 --value 999</code><br>"
            "<code>python -m memtool.cli results --json</code> — get results as JSON"
        )
        cli_help.setStyleSheet("QLabel { color: #aaa; padding: 8px; }")
        cli_help.setTextFormat(Qt.TextFormat.RichText)
        cli_layout.addWidget(cli_help)

        copy_btn = QPushButton("📋 Copy CLI Path to Clipboard")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(
            "python -m memtool.cli"
        ))
        cli_layout.addWidget(copy_btn)
        cli_layout.addStretch()
        self._bottom_tabs.addTab(cli_widget, "🤖 CLI / AI")

        # Tab 3: Debug log
        log_widget = QWidget()
        log_layout = QVBoxLayout(log_widget)
        log_layout.setContentsMargins(4, 4, 4, 4)
        self._log_text = QPlainTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setMaximumBlockCount(500)
        self._log_text.setStyleSheet(
            "QPlainTextEdit { background-color: #11111b; color: #a6e3a1; "
            "font-family: Consolas; font-size: 11px; }"
        )
        log_layout.addWidget(self._log_text)
        self._bottom_tabs.addTab(log_widget, "📋 Log")

        # Wire engine diagnostics to log
        self._engine.set_log_callback(self._append_log)
        self._append_log("MemTool started — log initialized")

        # Freeze stats label
        self._freeze_stats_label = QLabel("Freeze: 0 frozen | 0 ticks | 0 failures")
        self._freeze_stats_label.setStyleSheet("color: #a6adc8; font-size: 11px; padding: 2px 8px;")
        main_layout.addWidget(self._freeze_stats_label)

        main_layout.addWidget(self._bottom_tabs, 1)  # stretch factor 1 — grows with window

        # ── Status bar ─────────────────────────────────────
        self.statusBar().showMessage("Ready — select a process to begin")

    @staticmethod
    def _make_separator() -> QFrame:
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        return line

    # ── Process Management ───────────────────────────────────────

    def _show_process_dialog(self):
        dlg = ProcessDialog(self._engine, self)
        dlg.process_selected.connect(self._on_process_chosen)
        dlg.exec()

    def _on_process_chosen(self, pid: int, name: str):
        success = self._engine.open_process(pid)
        if not success:
            QMessageBox.warning(
                self, "Error",
                f"Could not open process {name} (PID {pid}).\n\n"
                "Try running MemTool as Administrator for full access."
            )
            return

        self._process_name = name
        self._update_process_label()
        self._first_scan_btn.setEnabled(True)
        self._detach_btn.setEnabled(True)
        self._new_scan_btn.setEnabled(True)

        if not self._engine.has_write_access:
            self.statusBar().showMessage(
                f"⚠ READ-ONLY — Attached to {name} (PID {pid}). Run as Admin for write access."
            )
        else:
            self.statusBar().showMessage(f"Attached to {name} (PID {pid})")

        # Check smart cache for this executable
        self._check_smart_cache()

    def _detach_process(self):
        self._engine.close_process()
        self._scanner.clear_session()
        self._update_process_label()
        self._clear_results()
        self._first_scan_btn.setEnabled(False)
        self._next_scan_btn.setEnabled(False)
        self._new_scan_btn.setEnabled(False)
        self._detach_btn.setEnabled(False)
        self._progress_bar.setValue(0)
        self._progress_bar.setFormat("Ready")
        self.statusBar().showMessage("Detached")

    def _update_process_label(self):
        if self._engine.is_attached:
            pid = self._engine.current_pid
            if self._engine.has_write_access:
                self._process_label.setText(f"PID: {pid} (read+write)")
                self._process_label.setStyleSheet("color: #4caf50; font-weight: bold;")
            else:
                self._process_label.setText(f"PID: {pid} (⚠ read-only)")
                self._process_label.setStyleSheet("color: #fab387; font-weight: bold;")
        else:
            self._process_label.setText("No process attached")
            self._process_label.setStyleSheet("color: #888; font-weight: bold;")

    # ── Scan Actions ─────────────────────────────────────────────

    def _on_first_scan(self):
        self._run_scan("first")

    def _on_next_scan(self):
        self._run_scan("next")

    def _on_new_scan(self):
        self._scanner.clear_session()
        self._clear_results()
        self._next_scan_btn.setEnabled(False)
        self._on_first_scan()

    def _on_cancel_scan(self):
        if self._scan_worker and self._scan_worker.isRunning():
            self._scan_worker.cancel_scan()
            self._scan_status_label.setText("Cancelling...")

    def _run_scan(self, scan_type: str):
        """Start a scan (first or next) in a background thread."""
        if not self._engine.is_attached:
            return

        # Parse inputs
        value_str = self._value_input.text().strip()
        scan_kind_key = self._scan_kind_combo.currentData()
        value_type_key = self._type_combo.currentData()

        scan_kind = ScanKind.from_key(scan_kind_key)
        value_type = ValueType.from_key(value_type_key)

        # Parse search value
        search_value = None
        search_value2 = None

        # For valueless scans (changed, unchanged, etc.), no value needed
        valueless = scan_kind in (
            ScanKind.CHANGED, ScanKind.UNCHANGED,
            ScanKind.INCREASED, ScanKind.DECREASED,
        )

        if not valueless:
            if not value_str:
                QMessageBox.warning(self, "Input Error", "Please enter a search value.")
                return
            search_value = self._parse_value(value_str, value_type)
            if search_value is None:
                QMessageBox.warning(
                    self, "Input Error",
                    f"Could not parse '{value_str}' as {value_type.label}."
                )
                return

            if scan_kind == ScanKind.BETWEEN:
                value2_str = self._value2_input.text().strip()
                if not value2_str:
                    QMessageBox.warning(self, "Input Error", "Please enter a second value for 'between' scan.")
                    return
                search_value2 = self._parse_value(value2_str, value_type)
                if search_value2 is None:
                    QMessageBox.warning(self, "Input Error", f"Could not parse '{value2_str}'.")
                    return

        # Disable buttons during scan
        self._set_scan_buttons_enabled(False)
        self._cancel_btn.setEnabled(True)
        self._progress_bar.setValue(0)
        self._scan_status_label.setText("Starting scan...")

        # Launch worker
        self._scan_worker = ScanWorker(
            self._engine, self._scanner,
            scan_type, value_type, scan_kind,
            search_value, search_value2,
        )
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    def _on_scan_progress(self, msg: str, fraction: float):
        self._progress_bar.setValue(int(fraction * 100))
        self._progress_bar.setFormat(f"{msg[:80]}")
        self._scan_status_label.setText(msg[:100])

    def _on_scan_finished(self, count: int):
        self._set_scan_buttons_enabled(True)
        self._cancel_btn.setEnabled(False)
        self._next_scan_btn.setEnabled(True)

        session = self._scanner.session
        elapsed = session.elapsed_ms if session else 0
        self._progress_bar.setValue(100)
        self._progress_bar.setFormat(f"Done — {count:,} results")
        self._scan_status_label.setText(
            f"Pass #{session.pass_number if session else '?'} — "
            f"{count:,} results in {elapsed:.0f}ms"
        )
        self.statusBar().showMessage(
            f"Scan complete: {count:,} results | Pass #{session.pass_number if session else '?'} "
            f"| {elapsed:.0f}ms"
        )

        self._populate_results()
        self._scan_worker = None

    def _on_scan_error(self, error_msg: str):
        self._set_scan_buttons_enabled(True)
        self._cancel_btn.setEnabled(False)
        self._scan_status_label.setText(f"Error: {error_msg}")
        self._progress_bar.setFormat("Error")
        QMessageBox.critical(self, "Scan Error", error_msg)
        self._scan_worker = None

    def _set_scan_buttons_enabled(self, enabled: bool):
        self._first_scan_btn.setEnabled(enabled)
        self._next_scan_btn.setEnabled(enabled and self._scanner.session is not None)
        self._new_scan_btn.setEnabled(enabled)

    # ── Results Display ──────────────────────────────────────────

    def _populate_results(self):
        """Fill the results table with current scan results."""
        results = self._scanner.get_results()
        self._results_table.setSortingEnabled(False)
        self._results_table.setRowCount(len(results))

        for row, entry in enumerate(results):
            self._results_table.setItem(row, 0,
                QTableWidgetItem(f"0x{entry.address:016X}"))
            self._results_table.setItem(row, 1,
                QTableWidgetItem(str(entry.value)))
            self._results_table.setItem(row, 2,
                QTableWidgetItem(str(entry.previous_value) if entry.previous_value is not None else "-"))
            self._results_table.setItem(row, 3,
                QTableWidgetItem(entry.data_type))
            # Show region type hint (MAPPED/PRIVATE/IMAGE)
            self._results_table.setItem(row, 4,
                QTableWidgetItem(self._guess_region_type(entry.address)))

        self._results_table.setSortingEnabled(True)
        if results:
            self._results_table.selectRow(0)

    def _guess_region_type(self, address: int) -> str:
        """Quick region type hint for a memory address."""
        return ""  # Placeholder — could query VirtualQueryEx for type

    def _clear_results(self):
        self._results_table.setRowCount(0)

    def _on_result_double_click(self, index):
        """Double-click on a result row — add to address list silently."""
        row = index.row()
        results = self._scanner.get_results()
        if row >= len(results):
            return
        entry = results[row]

        addr = entry.address
        if addr not in self._frozen_items:
            self._frozen_items[addr] = {
                "type": entry.data_type,
                "value": entry.value,
                "desc": "",
                "freeze": False,
            }
        else:
            # Already in list — update its type/value from latest scan
            self._frozen_items[addr]["type"] = entry.data_type
            self._frozen_items[addr]["value"] = entry.value

        self._refresh_frozen_table()
        # Switch to the Address List tab so user sees it appear
        self._bottom_tabs.setCurrentIndex(0)
        self.statusBar().showMessage(
            f"Added 0x{addr:016X} to Address List ({len(self._frozen_items)} total)"
        )

    # ── Context Menu: Results ────────────────────────────────────

    def _on_result_context_menu(self, pos):
        rows = set(idx.row() for idx in self._results_table.selectedIndexes())
        if not rows:
            return

        menu = QMenu(self)

        add_action = menu.addAction("➕ Add to Address List")
        add_action.triggered.connect(self._add_selected_to_frozen)

        menu.addSeparator()

        edit_action = menu.addAction("✏️ Edit Value...")
        edit_action.triggered.connect(self._edit_selected_value)

        menu.addSeparator()

        hex_action = menu.addAction("🔎 View Memory (Hex Dump)")
        hex_action.triggered.connect(self._show_hex_view)

        verify_action = menu.addAction("✅ Verify Address (Test Write)")
        verify_action.triggered.connect(self._verify_address)

        menu.addSeparator()

        copy_addr = menu.addAction("📋 Copy Address")
        copy_addr.triggered.connect(lambda: self._copy_column(0, rows))

        copy_val = menu.addAction("📋 Copy Value")
        copy_val.triggered.connect(lambda: self._copy_column(1, rows))

        menu.addSeparator()

        what_writes = menu.addAction("🔍 Find What Writes Here (TODO)")
        what_writes.setEnabled(False)

        what_access = menu.addAction("🔍 Find What Accesses Here (TODO)")
        what_access.setEnabled(False)

        menu.exec(self._results_table.viewport().mapToGlobal(pos))

    # ── Context Menu: Frozen ─────────────────────────────────────

    def _on_frozen_context_menu(self, pos):
        rows = set(idx.row() for idx in self._frozen_table.selectedIndexes())
        if not rows:
            return

        menu = QMenu(self)

        # Get addresses for selected rows
        selected = self._get_selected_frozen_rows(rows)
        if not selected:
            return

        menu.addSeparator()

        edit_action = menu.addAction("✏️ Edit Value...")
        edit_action.triggered.connect(lambda: self._edit_frozen_values(selected))

        edit_desc_action = menu.addAction("📝 Edit Description...")
        edit_desc_action.triggered.connect(lambda: self._edit_frozen_desc(rows))

        menu.addSeparator()

        freeze_action = menu.addAction("🔒 Freeze Selected")
        freeze_action.triggered.connect(lambda: self._bulk_freeze(selected, True))

        unfreeze_action = menu.addAction("🔓 Unfreeze Selected")
        unfreeze_action.triggered.connect(lambda: self._bulk_freeze(selected, False))

        menu.addSeparator()

        verify_action = menu.addAction("✅ Verify Address (Test Write)")
        verify_action.triggered.connect(lambda: self._verify_frozen_addr(selected))

        hex_action = menu.addAction("🔎 View Memory (Hex Dump)")
        hex_action.triggered.connect(lambda: self._hex_frozen_addr(selected))

        menu.addSeparator()

        ptr_action = menu.addAction("🔍 Find Pointer Chains...")
        ptr_action.triggered.connect(lambda: self._find_pointers_for_selected(selected))

        sig_action = menu.addAction("🧬 Create Signature")
        sig_action.triggered.connect(lambda: self._create_signature_for_selected(selected))

        menu.addSeparator()

        delete_action = menu.addAction("🗑 Delete Selected")
        delete_action.triggered.connect(lambda: self._delete_frozen_rows(rows))

        menu.exec(self._frozen_table.viewport().mapToGlobal(pos))

    def _get_selected_frozen_rows(self, rows: set[int]) -> list[dict]:
        """Get the (addr, info) tuples for selected rows."""
        result = []
        for row in sorted(rows):
            addr_item = self._frozen_table.item(row, 1)
            if not addr_item:
                continue
            addr = addr_item.data(Qt.ItemDataRole.UserRole)
            if addr is None or addr not in self._frozen_items:
                continue
            result.append({"addr": addr, "info": self._frozen_items[addr], "row": row})
        return result

    def _bulk_freeze(self, selected: list[dict], freeze: bool):
        """Freeze or unfreeze multiple addresses at once."""
        for s in selected:
            addr = s["addr"]
            info = self._frozen_items.get(addr)
            if info:
                info["freeze"] = freeze
                if freeze:
                    current = self._engine.read_value(addr, info["type"])
                    if current is not None:
                        info["value"] = current
                        self._engine.freeze_value(addr, info["type"], current)
                    else:
                        self._engine.freeze_value(addr, info["type"], info["value"])
                else:
                    self._engine.unfreeze_value(addr)
        self._refresh_frozen_table()
        verb = "frozen" if freeze else "unfrozen"
        self.statusBar().showMessage(f"{len(selected)} addresses {verb}")

    def _delete_frozen_rows(self, rows: set[int]):
        """Delete selected rows from the address list."""
        for row in sorted(rows, reverse=True):
            addr_item = self._frozen_table.item(row, 1)
            if addr_item:
                addr = addr_item.data(Qt.ItemDataRole.UserRole)
                if addr is not None:
                    self._engine.unfreeze_value(addr)
                    self._frozen_items.pop(addr, None)
        self._refresh_frozen_table()
        self.statusBar().showMessage(f"Deleted {len(rows)} addresses")

    def _verify_frozen_addr(self, selected: list[dict]):
        """Run address verification on a frozen address."""
        if not selected:
            return
        # Use the scanner's pattern — fake a ScanEntry for _edit_single_value
        from ..scanner import ScanEntry
        s = selected[0]
        entry = ScanEntry(
            address=s["addr"],
            value=s["info"]["value"],
            data_type=s["info"]["type"],
        )
        # Actually, we want the verify test, not edit
        # Select the row in results doesn't make sense here — do inline verify
        self._verify_frozen_inline(s["addr"], s["info"])

    def _hex_frozen_addr(self, selected: list[dict]):
        """Show hex dump for a frozen address."""
        if not selected:
            return
        s = selected[0]
        self._show_hex_at(s["addr"])

    def _verify_frozen_inline(self, addr: int, info: dict):
        """Run the write-verify test directly on a frozen address."""
        import time
        vt = ValueType.from_key(info["type"])
        original = self._engine.read_value(addr, vt.key)
        if original is None:
            QMessageBox.warning(self, "Read Failed", f"Can't read 0x{addr:016X}")
            return

        test_val = 0x5A5A5A5A if vt.key.startswith("int") or vt.key.startswith("uint") else (
            12345.67 if vt.key in ("float", "double") else "TEST"
        )
        ok = self._engine.write_value(addr, vt.key, test_val)
        if not ok:
            QMessageBox.critical(self, "Write Failed",
                f"WriteProcessMemory FAILED at 0x{addr:016X}\n\n"
                "This address is NOT writable. Check the Log tab for details.")
            return

        verify1 = self._engine.read_value(addr, vt.key)
        time.sleep(0.25)
        verify2 = self._engine.read_value(addr, vt.key)
        self._engine.write_value(addr, vt.key, original)

        if verify1 == test_val and verify2 == test_val:
            QMessageBox.information(self, "Address Verified",
                f"0x{addr:016X} is WRITABLE and STABLE.\n\n"
                f"Original: {original}\nTest write: {test_val}\n"
                f"Read-back (immediate): {verify1}\nRead-back (250ms): {verify2}\n\n"
                f"This address should be editable. "
                f"If the game doesn't reflect changes, you found a display copy.")
        elif verify1 == test_val:
            QMessageBox.warning(self, "Address Unstable",
                f"Write succeeded but value was OVERWRITTEN within 250ms.\n\n"
                f"Original: {original}\nTest write: {test_val}\n"
                f"Read-back (immediate): {verify1}\nRead-back (250ms): {verify2}\n\n"
                f"The game actively rewrites this. FREEZING should hold it.")
        else:
            QMessageBox.critical(self, "Address Ghost",
                f"Write appears to succeed but read-back shows {verify1} instead of {test_val}.\n\n"
                f"This address is a GHOST — writes don't stick. Try a different address.")

        self._append_log(
            f"VERIFY 0x{addr:016X}: orig={original}, test={test_val}, "
            f"immediate={verify1}, delayed={verify2}"
        )

    # ── Frozen / Address List ────────────────────────────────────

    def _add_selected_to_frozen(self):
        """Add selected result rows to the frozen address list."""
        rows = set(idx.row() for idx in self._results_table.selectedIndexes())
        results = self._scanner.get_results()
        if not rows or not results:
            return

        for row in rows:
            if row >= len(results):
                continue
            entry = results[row]
            addr = entry.address
            if addr not in self._frozen_items:
                self._frozen_items[addr] = {
                    "type": entry.data_type,
                    "value": entry.value,
                    "desc": "",
                    "freeze": False,
                }

        self._refresh_frozen_table()

    def _edit_selected_value(self):
        """Edit the value at selected result addresses (context menu)."""
        rows = set(idx.row() for idx in self._results_table.selectedIndexes())
        results = self._scanner.get_results()
        if not rows:
            return
        for row in rows:
            if row >= len(results):
                continue
            self._edit_single_value(results[row])

    def _edit_single_value(self, entry):
        """Edit the value at a single address. Verifies write by reading back."""
        current = entry.value
        new_val, ok = QInputDialog.getText(
            self, "Edit Value",
            f"New value for 0x{entry.address:016X} ({entry.data_type}):",
            text=str(current)
        )
        if not ok or not new_val:
            return

        parsed = self._parse_value(new_val, ValueType.from_key(entry.data_type))
        if parsed is None:
            QMessageBox.warning(self, "Parse Error",
                f"Could not parse '{new_val}' as {entry.data_type}")
            return

        old_val = self._engine.read_value(entry.address, entry.data_type)
        success = self._engine.write_value(entry.address, entry.data_type, parsed)

        # Verify by reading back
        verify = self._engine.read_value(entry.address, entry.data_type)

        if success and verify == parsed:
            self._append_log(
                f"WRITE OK  0x{entry.address:016X}: {old_val} -> {parsed} ({entry.data_type})"
            )
            self.statusBar().showMessage(
                f"✅ Wrote {parsed} to 0x{entry.address:016X}"
            )
            if entry.address in self._frozen_items:
                self._frozen_items[entry.address]["value"] = parsed
                self._refresh_frozen_table()
        elif success and verify != parsed:
            self._append_log(
                f"WRITE GHOST 0x{entry.address:016X}: wrote {parsed}, read-back={verify} ({entry.data_type}) — game overwrote it"
            )
            QMessageBox.warning(self, "Write Overwritten",
                f"Write appeared to succeed but read-back shows {verify} instead of {parsed}.\n\n"
                "The game immediately overwrote our value — this is common with:\n"
                "• Anti-cheat protected values\n"
                "• Server-authoritative games\n"
                "• Encrypted/obfuscated memory\n\n"
                "Try freezing the value instead of a one-shot edit.")
        else:
            self._append_log(
                f"WRITE FAIL 0x{entry.address:016X}: {old_val} -> {parsed} ({entry.data_type})"
            )
            QMessageBox.warning(self, "Write Failed",
                f"Could not write to 0x{entry.address:016X}.\n\n"
                "Possible causes:\n"
                "• Kernel-level anti-cheat blocking writes\n"
                "• Memory page is protected\n"
                "• Address is in a code section\n\n"
                "Check the Log tab for details.")

    def _refresh_frozen_table(self):
        """Update the frozen address table."""
        self._frozen_table.setRowCount(len(self._frozen_items))
        for row, (addr, info) in enumerate(self._frozen_items.items()):
            # Freeze checkbox
            cb = QCheckBox()
            cb.setChecked(info["freeze"])
            cb.toggled.connect(lambda checked, a=addr: self._toggle_freeze(a, checked))
            # Center the checkbox
            cb_widget = QWidget()
            cb_layout = QHBoxLayout(cb_widget)
            cb_layout.addWidget(cb)
            cb_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cb_layout.setContentsMargins(0, 0, 0, 0)
            self._frozen_table.setCellWidget(row, 0, cb_widget)

            # Store address as UserRole data so we can retrieve it after edits
            addr_item = QTableWidgetItem(f"0x{addr:016X}")
            addr_item.setData(Qt.ItemDataRole.UserRole, addr)
            self._frozen_table.setItem(row, 1, addr_item)

            self._frozen_table.setItem(row, 2,
                QTableWidgetItem(info["type"]))
            self._frozen_table.setItem(row, 3,
                QTableWidgetItem(str(info["value"])))
            self._frozen_table.setItem(row, 4,
                QTableWidgetItem(info.get("desc", "")))

    def _refresh_frozen_display(self):
        """Periodically refresh current values in the frozen table + freeze stats."""
        if not self._engine.is_attached:
            return

        # Update current values
        for row in range(self._frozen_table.rowCount()):
            addr_item = self._frozen_table.item(row, 1)
            if not addr_item:
                continue
            try:
                addr = int(addr_item.text(), 16)
                info = self._frozen_items.get(addr)
                if not info:
                    continue
                current = self._engine.read_value(addr, info["type"])
                if current is not None:
                    self._frozen_table.item(row, 3).setText(str(current))
            except (ValueError, KeyError):
                continue

        # Update freeze stats label
        stats = self._engine.freeze_stats
        color = "#a6e3a1" if stats["last_write_ok"] else "#fab387"
        self._freeze_stats_label.setText(
            f"Freeze: {stats['frozen_count']} frozen | "
            f"{stats['ticks']} ticks | "
            f"{stats['failures']} failures"
        )
        self._freeze_stats_label.setStyleSheet(
            f"color: {color}; font-size: 11px; padding: 2px 8px;"
        )

    def _toggle_freeze(self, address: int, freeze: bool):
        """Enable or disable freezing for an address."""
        if address not in self._frozen_items:
            return
        info = self._frozen_items[address]
        info["freeze"] = freeze

        if freeze:
            # Read the CURRENT value from memory (not the stale scan value)
            current = self._engine.read_value(address, info["type"])
            if current is not None:
                info["value"] = current
                fv = self._engine.freeze_value(address, info["type"], current)
                self._append_log(
                    f"FREEZE ON  0x{address:016X} = {current} ({info['type']})"
                )
                self.statusBar().showMessage(
                    f"🔒 Freezing 0x{address:016X} = {current}"
                )
            else:
                self._engine.freeze_value(address, info["type"], info["value"])
                self._append_log(
                    f"FREEZE ON  0x{address:016X} = {info['value']} ({info['type']}) [stored val, read failed]"
                )
                self.statusBar().showMessage(
                    f"🔒 Freezing 0x{address:016X} (stored value)"
                )
        else:
            self._engine.unfreeze_value(address)
            self._append_log(f"FREEZE OFF 0x{address:016X}")
            self.statusBar().showMessage(f"🔓 Unfroze 0x{address:016X}")

    def _unfreeze_rows(self, rows):
        for row in sorted(rows, reverse=True):
            addr_item = self._frozen_table.item(row, 1)
            if addr_item:
                try:
                    addr = int(addr_item.text(), 16)
                    self._engine.unfreeze_value(addr)
                    self._frozen_items.pop(addr, None)
                except (ValueError, KeyError):
                    pass
        self._refresh_frozen_table()

    def _unfreeze_all(self):
        self._engine.unfreeze_all()
        self._frozen_items.clear()
        self._refresh_frozen_table()
        self.statusBar().showMessage("All values unfrozen")

    def _delete_all_frozen(self):
        """Delete all entries from the address list."""
        count = len(self._frozen_items)
        if count == 0:
            return
        reply = QMessageBox.question(
            self, "Delete All",
            f"Delete all {count} addresses from the list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._engine.unfreeze_all()
        self._frozen_items.clear()
        self._refresh_frozen_table()
        self.statusBar().showMessage(f"Deleted all {count} addresses")
        self._append_log(f"DELETE ALL: removed {count} addresses")

    # ── Pointer Scanning ─────────────────────────────────────

    def _find_pointers_for_selected(self, selected: list[dict]):
        """Run a pointer scan for the selected address."""
        if not selected or not self._engine.is_attached:
            return

        s = selected[0]
        addr = s["addr"]
        info = s["info"]

        depth, ok = QInputDialog.getInt(
            self, "Pointer Scan Depth",
            "Max pointer depth to search:",
            value=4, min=1, max=7, step=1,
        )
        if not ok:
            return

        self.statusBar().showMessage(f"Pointer scanning for 0x{addr:016X} (depth {depth})...")
        self._append_log(f"POINTER SCAN START: target=0x{addr:016X}, depth={depth}")

        # Run pointer scan in a thread to not freeze UI
        import threading
        def do_scan():
            result = self._ptr_scanner.scan_pointers(
                target_address=addr, max_depth=depth, max_results=200,
            )
            # Show results on the main thread
            self._ptr_result = result
            # Use invokeMethod or just flag — simpler: QTimer
            from PyQt6.QtCore import QMetaObject, Qt as Qt2, Q_ARG
            QMetaObject.invokeMethod(
                self, "_show_pointer_results",
                Qt2.ConnectionType.QueuedConnection,
            )

        t = threading.Thread(target=do_scan, daemon=True)
        t.start()

    def _show_pointer_results(self):
        """Display pointer scan results in a dialog."""
        result = getattr(self, '_ptr_result', None)
        if result is None:
            return

        # Build display text
        lines = []
        lines.append(f"Pointer scan for 0x{result.target_address:016X}")
        lines.append(f"Found {len(result.chains)} chains in {result.elapsed_ms:.0f}ms\n")

        if result.chains:
            lines.append("Top pointer chains (shorter = better):\n")
            for i, chain in enumerate(result.chains[:30]):
                parts = []
                for node in chain.chain:
                    if node.module_name:
                        parts.append(f"[{node.module_name}+0x{node.module_offset:X}]")
                    else:
                        parts.append(f"[0x{node.address:016X}]")
                parts.append(f"+0x{chain.final_offset:X}")
                path = " -> ".join(parts)
                lines.append(f"  {i+1:2d}. {path}")
        else:
            lines.append("No pointer chains found. The value may be:")
            lines.append("  - Dynamically allocated (not pointer-accessible)")
            lines.append("  - In a region with no static references")
            lines.append("  - Try increasing the max offset or depth")

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Pointer Scan — 0x{result.target_address:016X}")
        dlg.setMinimumSize(800, 550)
        layout = QVBoxLayout(dlg)
        edit = QPlainTextEdit()
        edit.setReadOnly(True)
        edit.setStyleSheet(
            "QPlainTextEdit { background-color: #11111b; color: #cdd6f4; "
            "font-family: Consolas; font-size: 11px; }"
        )
        edit.setPlainText("\n".join(lines))
        layout.addWidget(edit)

        btn_layout = QHBoxLayout()
        save_btn = QPushButton("💾 Save to Cache")
        save_btn.clicked.connect(lambda: self._save_pointer_to_cache(result))
        btn_layout.addWidget(save_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        dlg.exec()

        self._append_log(
            f"POINTER SCAN DONE: {len(result.chains)} chains for 0x{result.target_address:016X}"
        )

    def _save_pointer_to_cache(self, result):
        """Save the best pointer chain to the pointer cache for this executable."""
        if not result.chains:
            QMessageBox.information(self, "Nothing to Save", "No pointer chains found.")
            return

        # Ask for a label
        label, ok = QInputDialog.getText(
            self, "Label", "Name for this pointer (e.g. Gold, HP, Ammo):",
            text="Value"
        )
        if not ok or not label:
            return

        exe_name = self._process_name or "unknown.exe"
        best = result.chains[0]

        cache = ExecutableCache(exe_name=exe_name)
        cache.pointers.append(PointerCache(
            exe_name=exe_name,
            target_label=label,
            pointer_path=best.display_string,
        ))
        self._persistence.save_pointer_cache(cache)

        self._append_log(f"CACHE SAVED: {label} → {best.display_string}")
        self.statusBar().showMessage(f"Pointer '{label}' saved for {exe_name}")

    # ── Signatures ────────────────────────────────────────────

    def _create_signature_for_selected(self, selected: list[dict]):
        """Create a byte signature for the selected address."""
        if not selected or not self._engine.is_attached:
            return
        s = selected[0]
        addr = s["addr"]
        info = s["info"]

        label, ok = QInputDialog.getText(
            self, "Label", "Name for this signature (e.g. Gold):",
            text=info.get("desc", "Value")
        )
        if not ok or not label:
            return

        sig = self._sig_scanner.create_signature_around(addr, radius=64)
        if sig is None:
            QMessageBox.warning(self, "Failed", "Could not read memory to create signature.")
            return

        self._append_log(f"SIGNATURE: {label} at 0x{addr:016X} → {sig[:60]}...")

        # Save to cache
        exe_name = self._process_name or "unknown.exe"
        cache = self._persistence.load_pointer_cache(exe_name) or ExecutableCache(exe_name=exe_name)
        cache.signatures.append({
            "label": label,
            "address": f"0x{addr:016X}",
            "type": info.get("type", "int4"),
            "signature": sig,
            "signature_offset": 64,
        })
        self._persistence.save_pointer_cache(cache)

        QMessageBox.information(self, "Signature Saved",
            f"Signature for '{label}' saved.\n\n"
            f"When you reopen the game, use the Smart Cache to re-find this value.\n\n"
            f"Signature (first 60 chars):\n{sig[:60]}...")

    # ── Save / Load Address Lists ─────────────────────────────

    def _save_address_list(self):
        """Save the current address list to a file."""
        if not self._frozen_items:
            QMessageBox.information(self, "Nothing to Save", "The address list is empty.")
            return

        name, ok = QInputDialog.getText(
            self, "Save List", "List name:",
            text=self._process_name or "MyList"
        )
        if not ok or not name:
            return

        import datetime
        al = AddressList(
            name=name,
            created=datetime.datetime.now().isoformat(),
            process_name=self._process_name or "",
            entries=[
                AddressEntry(
                    address=addr,
                    display_address=f"0x{addr:016X}",
                    value_type=info.get("type", "int4"),
                    current_value=str(info.get("value", "")),
                    frozen_value=str(info.get("value", "")),
                    freeze=info.get("freeze", False),
                    description=info.get("desc", ""),
                )
                for addr, info in self._frozen_items.items()
            ],
        )

        path = self._persistence.save_list(al)
        self._append_log(f"SAVED LIST: {path}")
        self.statusBar().showMessage(f"Saved '{name}' ({len(al.entries)} addresses)")

    def _load_address_list(self):
        """Load a saved address list and merge into current list."""
        saved = self._persistence.list_saved_lists()
        if not saved:
            QMessageBox.information(self, "No Saved Lists",
                f"No saved lists found in:\n{self._persistence.lists_dir}")
            return

        # Show dialog to pick a list
        names = [os.path.basename(p).replace(".json", "") for p in saved]
        item, ok = QInputDialog.getItem(
            self, "Load List", "Select a saved list:",
            names, 0, False,
        )
        if not ok or not item:
            return

        idx = names.index(item)
        al = self._persistence.load_list(saved[idx])
        if al is None:
            QMessageBox.warning(self, "Load Failed", "Could not load the list.")
            return

        count = 0
        for entry in al.entries:
            addr = entry.address
            if addr not in self._frozen_items:
                self._frozen_items[addr] = {
                    "type": entry.value_type,
                    "value": entry.current_value,
                    "desc": entry.description,
                    "freeze": entry.freeze,
                }
                count += 1

        self._refresh_frozen_table()
        self._append_log(f"LOADED LIST: {item} — {count} new addresses added")
        self.statusBar().showMessage(f"Loaded '{item}' ({count} addresses)")

    # ── Smart Cache (on attach) ───────────────────────────────

    def _check_smart_cache(self):
        """After attaching, check if we have cached pointers for this executable."""
        if not self._process_name:
            return

        cache = self._persistence.load_pointer_cache(self._process_name)
        if cache is None or (not cache.pointers and not cache.signatures):
            return

        pointers = cache.pointers
        sigs = cache.signatures

        msg = f"Found cached data for '{self._process_name}':\n"
        if pointers:
            msg += f"  {len(pointers)} pointer chains\n"
        if sigs:
            msg += f"  {len(sigs)} signatures\n"
        msg += "\nTry to resolve these now?"

        reply = QMessageBox.question(
            self, "Smart Cache",
            msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        resolved = 0
        # Try signatures first
        for s in sigs:
            matches = self._sig_scanner.scan(s.get("signature", ""), max_results=5)
            if matches:
                match = matches[0]
                target_addr = match.address + s.get("signature_offset", 64)
                label = s.get("label", "sig")
                vt = s.get("type", "int4")

                # Read current value
                current = self._engine.read_value(target_addr, vt)
                if current is not None:
                    self._frozen_items[target_addr] = {
                        "type": vt,
                        "value": current,
                        "desc": f"[SIG] {label}",
                        "freeze": False,
                    }
                    resolved += 1
                    self._append_log(
                        f"CACHE HIT (sig): {label} → 0x{target_addr:016X} = {current}"
                    )

        # Then try pointer paths (best effort)
        for p in pointers:
            label = p.target_label
            path = p.pointer_path
            self._append_log(f"CACHE: {label} → {path} (manual resolve needed)")

        if resolved > 0:
            self._refresh_frozen_table()
            self._bottom_tabs.setCurrentIndex(0)
            self.statusBar().showMessage(
                f"Smart Cache: auto-resolved {resolved} addresses"
            )
        else:
            self.statusBar().showMessage(
                "Smart Cache: no signatures auto-resolved. Pointer chains available for manual use."
            )

    def _edit_frozen_desc(self, rows):
        for row in rows:
            addr_item = self._frozen_table.item(row, 1)
            if not addr_item:
                continue
            try:
                addr = int(addr_item.text(), 16)
            except ValueError:
                continue
            info = self._frozen_items.get(addr)
            if info is None:
                continue
            new_desc, ok = QInputDialog.getText(
                self, "Edit Description",
                "Description for this address:",
                text=info.get("desc", "")
            )
            if ok:
                info["desc"] = new_desc
        self._refresh_frozen_table()

    def _on_frozen_double_click(self, index):
        """Double-click on a frozen table row — pop up edit dialog."""
        row = index.row()
        col = index.column()
        addr_item = self._frozen_table.item(row, 1)
        if not addr_item:
            return
        addr = addr_item.data(Qt.ItemDataRole.UserRole)
        if addr is None or addr not in self._frozen_items:
            return

        info = self._frozen_items[addr]

        if col == 0:  # Freeze checkbox — toggle
            info["freeze"] = not info["freeze"]
            self._toggle_freeze(addr, info["freeze"])
            self._refresh_frozen_table()

        elif col == 2:  # Type
            self._edit_frozen_type(addr, info)

        elif col == 3:  # Current Value
            self._edit_frozen_value(addr, info)

        elif col == 4:  # Description
            self._edit_frozen_desc_single(addr, info)

    def _edit_frozen_type(self, addr: int, info: dict):
        """Pop up a dialog to change the value type."""
        types = [vt.key for vt in ValueType]
        current_idx = types.index(info["type"]) if info["type"] in types else 2
        item, ok = QInputDialog.getItem(
            self, "Change Type",
            f"Select type for 0x{addr:016X}:",
            types, current_idx, False,
        )
        if ok and item:
            info["type"] = item
            self._refresh_frozen_table()
            self.statusBar().showMessage(f"Type changed to {item} for 0x{addr:016X}")

    def _edit_frozen_value(self, addr: int, info: dict):
        """Pop up a dialog to edit the value at a frozen address."""
        current = self._engine.read_value(addr, info["type"])
        if current is not None:
            info["value"] = current  # update to live value
        display_val = info.get("value", current)

        new_val, ok = QInputDialog.getText(
            self, "Edit Value",
            f"New value for 0x{addr:016X} ({info['type']}):",
            text=str(display_val)
        )
        if not ok or not new_val:
            return

        parsed = self._parse_value(new_val, ValueType.from_key(info["type"]))
        if parsed is None:
            QMessageBox.warning(self, "Parse Error",
                f"Could not parse '{new_val}' as {info['type']}")
            return

        old_val = self._engine.read_value(addr, info["type"])
        success = self._engine.write_value(addr, info["type"], parsed)
        verify = self._engine.read_value(addr, info["type"])

        if success and verify == parsed:
            info["value"] = parsed
            self._append_log(
                f"WRITE OK  0x{addr:016X}: {old_val} -> {parsed} ({info['type']})"
            )
            self.statusBar().showMessage(
                f"Wrote {parsed} to 0x{addr:016X}"
            )
            self._refresh_frozen_table()
        elif success and verify != parsed:
            self._append_log(
                f"WRITE GHOST 0x{addr:016X}: wrote {parsed}, read-back={verify} — game overwrote"
            )
            QMessageBox.warning(self, "Write Overwritten",
                f"Value was written but immediately changed back to {verify}.\n"
                "The game is actively protecting this value. Try freezing it.")
            self._refresh_frozen_table()
        else:
            self._append_log(
                f"WRITE FAIL 0x{addr:016X}: {old_val} -> {parsed}"
            )
            QMessageBox.warning(self, "Write Failed",
                f"Could not write to 0x{addr:016X}.\n"
                "See the Log tab for details.")

    def _edit_frozen_desc_single(self, addr: int, info: dict):
        """Pop up a dialog to edit the description."""
        new_desc, ok = QInputDialog.getText(
            self, "Edit Description",
            f"Description for 0x{addr:016X}:",
            text=info.get("desc", "")
        )
        if ok:
            info["desc"] = new_desc
            self._refresh_frozen_table()

    def _edit_frozen_values(self, selected: list[dict]):
        """Edit values for selected frozen addresses (from context menu)."""
        for s in selected:
            self._edit_frozen_value(s["addr"], s["info"])

    def _show_hex_at(self, addr: int):
        """Show hex dump at an arbitrary address."""
        base = max(0, addr - 64)
        data = self._engine.read_bytes(base, 256)
        if data is None:
            QMessageBox.warning(self, "Read Failed",
                f"Could not read memory at 0x{addr:016X}")
            return

        vt = ValueType.from_key(
            self._frozen_items.get(addr, {}).get("type", "int4")
        )
        current = self._engine.read_value(addr, vt.key) if vt.key != "string" else None

        lines = [f"Hex dump around 0x{addr:016X}"]
        if current is not None:
            lines.append(f"Current value: {current}")
        lines.append("")
        lines.append(f"{'Offset':>8s}  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |ASCII|")
        lines.append("-" * 72)

        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            marker = " <--" if (base + offset <= addr < base + offset + 16) else ""
            lines.append(
                f"0x{base + offset:08X}  {hex_part:<48s} |{ascii_part}|{marker}"
            )

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Hex View — 0x{addr:016X}")
        dlg.setMinimumSize(750, 480)
        layout = QVBoxLayout(dlg)
        edit = QPlainTextEdit()
        edit.setReadOnly(True)
        edit.setStyleSheet(
            "QPlainTextEdit { background-color: #11111b; color: #cdd6f4; "
            "font-family: Consolas; font-size: 12px; }"
        )
        edit.setPlainText("\n".join(lines))
        layout.addWidget(edit)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)
        dlg.exec()

    # ── Hex Viewer ────────────────────────────────────────────────

    def _show_hex_view(self):
        """Open a hex dump dialog for the selected address."""
        rows = set(idx.row() for idx in self._results_table.selectedIndexes())
        results = self._scanner.get_results()
        if not rows:
            return
        row = min(rows)
        if row >= len(results):
            return
        entry = results[row]

        # Read 256 bytes around the address
        base = entry.address - 64
        if base < 0:
            base = 0
        data = self._engine.read_bytes(base, 256)
        if data is None:
            QMessageBox.warning(self, "Read Failed",
                f"Could not read memory at 0x{entry.address:016X}")
            return

        # Build hex dump text
        lines = []
        lines.append(f"Hex dump around 0x{entry.address:016X} ({entry.data_type}):")
        lines.append(f"Current value: {self._engine.read_value(entry.address, entry.data_type)}")
        lines.append(f"Page protection: {self._get_page_protection(entry.address)}")
        lines.append("")
        lines.append(f"{'Offset':>8s}  {'00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F':<48s}  ASCII")
        lines.append("-" * 78)

        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            marker = " <--" if (base + offset <= entry.address < base + offset + 16) else ""
            lines.append(
                f"0x{base + offset:08X}  {hex_part:<48s}  |{ascii_part}|{marker}"
            )

        # Show in a dialog
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Hex View — 0x{entry.address:016X}")
        dlg.setMinimumSize(750, 500)
        layout = QVBoxLayout(dlg)
        edit = QPlainTextEdit()
        edit.setReadOnly(True)
        edit.setStyleSheet(
            "QPlainTextEdit { background-color: #11111b; color: #cdd6f4; "
            "font-family: Consolas; font-size: 12px; }"
        )
        edit.setPlainText("\n".join(lines))
        layout.addWidget(edit)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn)
        dlg.exec()

    def _verify_address(self):
        """Test an address by writing a pattern and reading it back."""
        rows = set(idx.row() for idx in self._results_table.selectedIndexes())
        results = self._scanner.get_results()
        if not rows:
            return
        row = min(rows)
        if row >= len(results):
            return
        entry = results[row]

        addr = entry.address
        vt = ValueType.from_key(entry.data_type)

        # Read current value
        original = self._engine.read_value(addr, vt.key)
        if original is None:
            QMessageBox.warning(self, "Read Failed", f"Can't read 0x{addr:016X}")
            return

        # Write a test pattern
        test_val = 0x5A5A5A5A if vt.key.startswith("int") or vt.key.startswith("uint") else (
            12345.67 if vt.key in ("float", "double") else "TEST"
        )
        ok = self._engine.write_value(addr, vt.key, test_val)
        if not ok:
            QMessageBox.critical(self, "Write Failed",
                f"WriteProcessMemory FAILED at 0x{addr:016X}\n\n"
                "This address is NOT writable.\n"
                "• Page may be execute-only\n"
                "• Anti-cheat may be blocking writes\n"
                "• Run as Administrator")
            return

        # Read back immediately
        verify1 = self._engine.read_value(addr, vt.key)

        # Wait 250ms and read again (game might overwrite)
        import time
        time.sleep(0.25)
        verify2 = self._engine.read_value(addr, vt.key)

        # Restore original
        self._engine.write_value(addr, vt.key, original)

        # Report
        if verify1 == test_val and verify2 == test_val:
            QMessageBox.information(self, "Address Verified ✅",
                f"0x{addr:016X} is WRITABLE and STABLE.\n\n"
                f"Original: {original}\n"
                f"Test write: {test_val}\n"
                f"Read-back (immediate): {verify1}\n"
                f"Read-back (250ms later): {verify2}\n\n"
                f"✅ This address should be editable.\n"
                f"If the game doesn't reflect changes, this is a DISPLAY COPY\n"
                f"of the value — you need to find the AUTHORITATIVE address\n"
                f"(the one the game reads from, not the one it writes to).")
        elif verify1 == test_val:
            QMessageBox.warning(self, "Address Unstable ⚠",
                f"Write succeeded but value was OVERWRITTEN within 250ms.\n\n"
                f"Original: {original}\n"
                f"Test write: {test_val}\n"
                f"Read-back (immediate): {verify1}\n"
                f"Read-back (250ms later): {verify2}\n\n"
                f"⚠ The game actively rewrites this address.\n"
                f"FREEZING this address should work (it writes every 4ms).\n"
                f"Try toggling the freeze checkbox.")
        else:
            QMessageBox.critical(self, "Address Ghost 👻",
                f"Write appeared to succeed but read-back shows {verify1} instead of {test_val}.\n\n"
                f"👻 This address is a GHOST — writes don't stick even immediately.\n"
                f"• Likely a copy-on-write page\n"
                f"• Or kernel-level anti-cheat intercepting writes\n"
                f"• Try a different address from your scan results")

        # Log the test
        self._append_log(
            f"VERIFY 0x{addr:016X}: orig={original}, test={test_val}, "
            f"immediate={verify1}, delayed={verify2}"
        )

    def _get_page_protection(self, address: int) -> str:
        """Get the page protection string for an address."""
        if not self._engine.is_attached:
            return "N/A"
        # Read 1 byte to check if readable
        data = self._engine.read_bytes(address, 1)
        if data is None:
            return "UNREADABLE"
        return "READABLE+WRITABLE" if self._engine.has_write_access else "READ-ONLY"

    # ── Helpers ──────────────────────────────────────────────────

    def _copy_column(self, col: int, rows: set[int]):
        items = []
        for row in sorted(rows):
            item = self._results_table.item(row, col)
            if item:
                items.append(item.text())
        QApplication.clipboard().setText("\n".join(items))

    def _on_scan_kind_changed(self):
        key = self._scan_kind_combo.currentData()
        is_between = (key == "between")
        is_valueless = key in ("changed", "unchanged", "increased", "decreased")
        self._value2_label.setVisible(is_between)
        self._value2_input.setVisible(is_between)
        self._value_input.setEnabled(not is_valueless)
        if is_valueless:
            self._value_input.setPlaceholderText("(not needed for this scan type)")
        else:
            self._value_input.setPlaceholderText("Enter value to scan...")

    @staticmethod
    def _parse_value(text: str, value_type: ValueType):
        """Parse a string into a typed value."""
        try:
            if value_type.key.startswith("int"):
                return int(text, 0)  # supports hex: 0xFF
            if value_type.key.startswith("uint"):
                return int(text, 0)
            if value_type.key in ("float", "double"):
                return float(text)
            if value_type.key == "string":
                return text
        except (ValueError, TypeError):
            return None
        return None

    # ── Cleanup ──────────────────────────────────────────────────

    def closeEvent(self, event):
        self._engine.close_process()
        self._status_timer.stop()
        event.accept()
