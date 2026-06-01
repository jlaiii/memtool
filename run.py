#!/usr/bin/env python3
"""
MemTool — A user-friendly memory scanner & editor.
Inspired by Cheat Engine, with CLI integration for AI-assisted memory hacking.

Usage:
  python run.py                    # Launch the GUI
  python -m memtool.cli <command>  # CLI mode (for AI/script integration)
"""

import sys
import os
import ctypes
import threading
import time

# Ensure the project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def is_admin() -> bool:
    """Check if running with administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_to_admin():
    """Re-launch this script with admin privileges via UAC prompt."""
    if is_admin():
        return True  # already admin, nothing to do

    script = sys.argv[0]
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,            # hwnd
            "runas",         # verb — triggers UAC
            sys.executable,  # python.exe
            f'"{script}" {params}',
            os.path.dirname(script),
            1,               # SW_SHOWNORMAL
        )
        return False  # shelled to elevated instance, exit current
    except Exception:
        return False


def main():
    # Must be admin for memory editing
    if not is_admin():
        print("MemTool requires administrator privileges for memory access.")
        print("Requesting elevation (UAC prompt will appear)...")
        if not elevate_to_admin():
            sys.exit(0)
        # elevate_to_admin returns True if already admin after the ShellExecute
        # (it launched the new process, current one should exit)
        sys.exit(0)

    from PyQt6.QtWidgets import QApplication, QMessageBox
    from PyQt6.QtCore import Qt

    from memtool.gui.main_window import MainWindow

    # Enable high-DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("MemTool")
    app.setOrganizationName("MemTool")

    # Apply a dark-ish stylesheet for readability
    app.setStyleSheet("""
        QMainWindow {
            background-color: #1e1e2e;
        }
        QLabel {
            color: #cdd6f4;
        }
        QPushButton {
            background-color: #45475a;
            color: #cdd6f4;
            border: 1px solid #585b70;
            padding: 5px 12px;
            border-radius: 4px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #585b70;
        }
        QPushButton:disabled {
            background-color: #313244;
            color: #6c7086;
        }
        QPushButton#processBtn {
            background-color: #a6e3a1;
            color: #1e1e2e;
        }
        QLineEdit {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #585b70;
            padding: 4px 8px;
            border-radius: 4px;
        }
        QComboBox {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #585b70;
            padding: 4px 8px;
            border-radius: 4px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            background-color: #313244;
            color: #cdd6f4;
            selection-background-color: #585b70;
        }
        QTableWidget {
            background-color: #181825;
            color: #cdd6f4;
            gridline-color: #45475a;
            border: 1px solid #45475a;
            alternate-background-color: #1e1e2e;
        }
        QTableWidget::item:selected {
            background-color: #45475a;
        }
        QHeaderView::section {
            background-color: #313244;
            color: #cdd6f4;
            border: 1px solid #45475a;
            padding: 4px 8px;
        }
        QTabWidget::pane {
            border: 1px solid #45475a;
            background-color: #1e1e2e;
        }
        QTabBar::tab {
            background-color: #313244;
            color: #cdd6f4;
            padding: 6px 16px;
            border: 1px solid #45475a;
            border-bottom: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        QTabBar::tab:selected {
            background-color: #1e1e2e;
        }
        QProgressBar {
            background-color: #313244;
            border: 1px solid #585b70;
            border-radius: 3px;
            text-align: center;
            color: #cdd6f4;
        }
        QProgressBar::chunk {
            background-color: #89b4fa;
            border-radius: 2px;
        }
        QStatusBar {
            background-color: #313244;
            color: #a6adc8;
        }
        QCheckBox {
            color: #cdd6f4;
        }
    """)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
