"""
Allow `python -m memtool` to run the GUI.
(Use `python -m memtool.cli` for the CLI.)
"""

import sys
import os
import ctypes

def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _elevate():
    if _is_admin():
        return True
    script = sys.argv[0]
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            f'"{script}" {params}',
            os.path.dirname(script), 1,
        )
        return False
    except Exception:
        return False

if not _is_admin():
    print("MemTool requires Administrator privileges for memory editing.")
    print("Requesting elevation...")
    if not _elevate():
        sys.exit(0)

from memtool.gui.main_window import MainWindow
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("MemTool")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
