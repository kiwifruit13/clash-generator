"""QApplication 启动入口。

职责:创建 QApplication 实例 + 显示主窗 + 进入事件循环。
不含业务逻辑(对应 M7 计划 Step 5)。
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .main_window import MainWindow


def run() -> int:
    """启动 GUI 应用。

    Returns:
        QApplication.exec() 的退出码
    """
    # 复用已有 QApplication(避免重复创建,便于测试)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Clash Generator")
    app.setApplicationVersion("0.1.0")

    window = MainWindow()
    window.show()
    return app.exec()
