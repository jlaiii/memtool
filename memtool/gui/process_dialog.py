"""
Process selection dialog — searchable, sortable list of running processes.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLineEdit,
    QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QHeaderView, QAbstractItemView,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon

from ..engine import MemoryEngine, ProcessInfo


class ProcessDialog(QDialog):
    """Dialog for selecting a process to attach to."""

    process_selected = pyqtSignal(int, str)  # pid, name

    def __init__(self, engine: MemoryEngine, parent=None):
        super().__init__(parent)
        self._engine = engine
        self._processes: list[ProcessInfo] = []

        self.setWindowTitle("Select Process")
        self.setMinimumSize(600, 480)
        self.setModal(True)

        self._build_ui()
        self._refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Type to filter by name or PID...")
        self._search_input.textChanged.connect(self._on_search)
        search_layout.addWidget(self._search_input)

        self._refresh_btn = QPushButton("↻ Refresh")
        self._refresh_btn.clicked.connect(self._refresh)
        search_layout.addWidget(self._refresh_btn)
        layout.addLayout(search_layout)

        # Process table
        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(["PID", "Name", "Architecture"])
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._table.doubleClicked.connect(self._on_accept)
        layout.addWidget(self._table)

        # Status
        self._status_label = QLabel("")
        layout.addWidget(self._status_label)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self._select_btn = QPushButton("Attach to Process")
        self._select_btn.setDefault(True)
        self._select_btn.clicked.connect(self._on_accept)
        btn_layout.addWidget(self._select_btn)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def _refresh(self):
        """Reload the process list."""
        self._processes = self._engine.list_processes()
        self._populate_table(self._processes)
        self._status_label.setText(f"{len(self._processes)} processes")

    def _populate_table(self, processes: list[ProcessInfo]):
        """Fill the table with process data."""
        self._table.setSortingEnabled(False)
        search = self._search_input.text().lower().strip()

        if search:
            processes = [
                p for p in processes
                if search in p.name.lower() or search == str(p.pid)
            ]

        self._table.setRowCount(len(processes))
        for row, proc in enumerate(processes):
            pid_item = QTableWidgetItem(str(proc.pid))
            pid_item.setData(Qt.ItemDataRole.UserRole, proc.pid)
            self._table.setItem(row, 0, pid_item)
            self._table.setItem(row, 1, QTableWidgetItem(proc.name))
            self._table.setItem(row, 2, QTableWidgetItem(proc.architecture or "-"))

        self._table.setSortingEnabled(True)
        self._status_label.setText(f"Showing {len(processes)} / {len(self._processes)} processes")

    def _on_search(self):
        self._populate_table(self._processes)

    def _on_accept(self):
        """Accept the selected process."""
        row = self._table.currentRow()
        if row < 0:
            return
        pid_item = self._table.item(row, 0)
        name_item = self._table.item(row, 1)
        if pid_item and name_item:
            pid = pid_item.data(Qt.ItemDataRole.UserRole)
            self.process_selected.emit(pid, name_item.text())
            self.accept()
