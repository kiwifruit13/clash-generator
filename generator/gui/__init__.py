"""gui 子包:PySide6 GUI 壳(core 的可视化封装)。

公开接口:
    MainWindow: 主窗口类
    run: 启动 GUI 应用
"""

from generator.gui.app import run
from generator.gui.main_window import MainWindow

__all__ = ["MainWindow", "run"]
