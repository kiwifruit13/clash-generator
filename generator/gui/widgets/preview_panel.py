"""预览面板:final.yaml 只读展示 + 搜索高亮。

纯展示 widget,不持有 core 引用,通过 setYaml() 接收文本。

对应 M7 计划 Step 2。
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QTextCharFormat
from PySide6.QtWidgets import (
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QWidget,
)


class PreviewPanel(QWidget):
    """YAML 预览面板。

    顶部搜索框(实时高亮匹配)+ 主体只读等宽文本区。
    由 MainWindow 在 PipelineWorker 完成后调用 setYaml() 填充。
    """

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # 顶部工具栏:搜索 + 清除
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("搜索:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("输入关键字高亮匹配(如 mixed-port、proxy-groups)...")
        self.search_edit.textChanged.connect(self._highlight_search)
        toolbar.addWidget(self.search_edit, 1)
        self.clear_btn = QPushButton("清除")
        self.clear_btn.clicked.connect(self.search_edit.clear)
        toolbar.addWidget(self.clear_btn)
        layout.addLayout(toolbar)

        # YAML 显示区(等宽只读)
        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setLineWrapMode(QPlainTextEdit.NoWrap)
        font = self.viewer.font()
        font.setFamily("Consolas")
        font.setPointSize(10)
        self.viewer.setFont(font)
        self.viewer.setPlaceholderText("点击「生成配置」后,此处显示 final.yaml 内容...")
        layout.addWidget(self.viewer, 1)

    def setYaml(self, yaml_str: str) -> None:
        """设置 YAML 文本(由 MainWindow 调用)。

        Args:
            yaml_str: 完整 final.yaml 文本
        """
        self.viewer.setPlainText(yaml_str)
        # 重置光标到开头
        cursor = self.viewer.textCursor()
        cursor.movePosition(cursor.MoveOperation.Start)
        self.viewer.setTextCursor(cursor)
        # 重新应用当前搜索高亮(若有)
        self._highlight_search(self.search_edit.text())

    def _highlight_search(self, text: str) -> None:
        """高亮所有匹配关键字的文本(ExtraSelection)。"""
        # 先清除旧高亮
        self.viewer.setExtraSelections([])

        text = text.strip()
        if not text:
            return

        # 准备高亮格式
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#fff3a3"))  # 浅黄色背景
        fmt.setForeground(QColor("#cc0000"))  # 红色文字

        selections = []
        doc = self.viewer.document()
        cursor = self.viewer.textCursor()
        cursor.movePosition(cursor.MoveOperation.Start)

        # 遍历文档查找所有匹配
        find_cursor = doc.find(text, cursor)
        while not find_cursor.isNull():
            sel = self.viewer.ExtraSelection()
            sel.format = fmt
            sel.cursor = find_cursor
            selections.append(sel)
            # 从当前匹配末尾继续找
            find_cursor = doc.find(text, find_cursor)

        if selections:
            self.viewer.setExtraSelections(selections)
