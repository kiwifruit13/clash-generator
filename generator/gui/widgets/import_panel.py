"""导入面板:文件选择 + 节点画像展示 + 清洗警告。

交互 widget,通过信号通知 MainWindow:
- fileSelected: 用户选择/拖入文件
- generateRequested: 用户点击"生成配置"

对应 M7 计划 Step 3。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from generator.core.analyzer import GroupingSuggestion, NodeProfile
    from generator.core.models import CleanResult


class ImportPanel(QWidget):
    """导入面板:选择 proxies 文件 + 展示节点画像 + 清洗警告。

    信号:
        fileSelected(object): 用户选择文件,携带 Path
        generateRequested(object): 用户点击生成,携带 Path
    """

    fileSelected = Signal(object)
    generateRequested = Signal(object)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)  # 启用拖拽
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # === 顶部:文件选择 ===
        file_row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("选择或拖入 proxies 文件(chromego.txt / 333.txt)...")
        self.path_edit.textChanged.connect(self._on_path_changed)
        self.browse_btn = QPushButton("浏览...")
        self.browse_btn.clicked.connect(self._on_browse)
        self.generate_btn = QPushButton("⚡ 生成配置")
        self.generate_btn.setStyleSheet("font-weight:bold; padding:4px 12px;")
        self.generate_btn.setEnabled(False)  # 未选文件时禁用
        self.generate_btn.clicked.connect(self._on_generate)
        file_row.addWidget(self.path_edit, 1)
        file_row.addWidget(self.browse_btn)
        file_row.addWidget(self.generate_btn)
        layout.addLayout(file_row)

        # === 中部:节点画像(只读) ===
        profile_box_label = QLabel("📊 节点画像")
        profile_box_label.setStyleSheet("font-weight:bold; margin-top:8px;")
        layout.addWidget(profile_box_label)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        self.lbl_total = QLabel("—")
        self.lbl_proto = QLabel("—")
        self.lbl_ipv6 = QLabel("—")
        self.lbl_domain = QLabel("—")
        self.lbl_skipcert = QLabel("—")
        self.lbl_strategy = QLabel("—")
        form.addRow("节点总数:", self.lbl_total)
        form.addRow("协议分布:", self.lbl_proto)
        form.addRow("IPv6 server:", self.lbl_ipv6)
        form.addRow("域名 server:", self.lbl_domain)
        form.addRow("skip-cert-verify:", self.lbl_skipcert)
        form.addRow("分组策略:", self.lbl_strategy)
        layout.addLayout(form)

        # === 底部:清洗警告 ===
        warn_label = QLabel("⚠️ 清洗警告")
        warn_label.setStyleSheet("font-weight:bold; margin-top:8px;")
        layout.addWidget(warn_label)
        self.warn_list = QListWidget()
        self.warn_list.setMaximumHeight(150)
        layout.addWidget(self.warn_list, 1)

    # --- 交互处理 ---

    def _on_browse(self) -> None:
        """打开文件对话框选择 proxies 文件。"""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择 proxies 文件",
            "",
            "YAML/文本文件 (*.txt *.yaml *.yml);;所有文件 (*)",
        )
        if path:
            self.path_edit.setText(path)

    def _on_path_changed(self, text: str) -> None:
        """路径变化时更新按钮状态 + 发出 fileSelected 信号。"""
        path = Path(text) if text else None
        valid = path is not None and path.exists() and path.is_file()
        self.generate_btn.setEnabled(valid)
        if valid:
            self.fileSelected.emit(path)

    def _on_generate(self) -> None:
        """点击生成按钮,发出 generateRequested 信号。"""
        path = Path(self.path_edit.text())
        if path.exists():
            self.generateRequested.emit(path)

    # --- 拖拽支持 ---

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        """拖入文件时,仅接受含 URL 的拖拽。"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        """放下文件,取第一个 URL 填入路径框。"""
        urls = event.mimeData().urls()
        if urls:
            local_file = urls[0].toLocalFile()
            if local_file:
                self.path_edit.setText(local_file)
                event.acceptProposedAction()
            else:
                event.ignore()
        else:
            event.ignore()

    # --- 公开方法(由 MainWindow 调用) ---

    def showProfile(
        self,
        result: "CleanResult",
        profile: "NodeProfile",
        grouping: "GroupingSuggestion",
    ) -> None:
        """填充节点画像展示(由 MainWindow 在流水线完成后调用)。

        Args:
            result: 清洗结果(含 warnings)
            profile: 节点画像
            grouping: 分组可行性分析
        """
        # 画像字段
        self.lbl_total.setText(f"{profile.total} 个")
        proto_str = " / ".join(f"{k}:{v}" for k, v in profile.protocol_counts.items())
        self.lbl_proto.setText(proto_str or "—")
        self.lbl_ipv6.setText(f"{len(profile.ipv6_nodes)} 个")
        self.lbl_domain.setText(f"{len(profile.domain_server_nodes)} 个")
        self.lbl_skipcert.setText(f"{len(profile.skip_cert_nodes)} 个")
        strategy_map = {
            "standard": "标准(安全+网页+下载 全组)",
            "minimal": "精简(仅自动优选)",
            "partial": "部分(自动优选 + 非空子组)",
        }
        strategy_text = strategy_map.get(grouping.suggested_strategy, grouping.suggested_strategy)
        self.lbl_strategy.setText(
            f"{strategy_text}  [safe={grouping.safe_count} web={grouping.web_count} "
            f"dl={grouping.download_count} diversity={grouping.diversity_score:.2f}]"
        )

        # 清洗警告
        self.warn_list.clear()
        if result.warnings:
            for w in result.warnings:
                tag = w.node_name or "全局"
                QListWidgetItem(f"{w.level} [{tag}] {w.message}", self.warn_list)
        else:
            QListWidgetItem("✅ 无清洗警告", self.warn_list)

    def setGenerating(self, generating: bool) -> None:
        """生成进行时禁用按钮(由 MainWindow 调用)。"""
        self.generate_btn.setEnabled(not generating)
        self.browse_btn.setEnabled(not generating)
