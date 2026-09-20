"""报告面板:35 红线静态校验报告 + 动态验证结果。

纯展示 widget(动态验证按钮除外,通过 verifyRequested 信号通知 MainWindow)。

对应 M7 计划 Step 2。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from generator.core.checker import Report
    from generator.core.verifier import VerifyResult


class ReportPanel(QWidget):
    """校验报告面板。

    组成:
    - 顶部大字评分(绿/红色)
    - 三栏 Tab:🔴 硬红线 / 🟠 软红线 / 🟡 约定
    - 跨段命名校验错误列表
    - 底部动态验证区(mihomo -t)

    信号:
        verifyRequested: 用户点击"开始动态验证"按钮
    """

    verifyRequested = Signal()

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        # === 顶部评分 ===
        self.score_label = QLabel("--/10")
        self.score_label.setStyleSheet(
            "font-size:28px; font-weight:bold; color:#888; padding:4px;"
        )
        self.score_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.score_label)

        # === 三栏 Tab(红线分级) ===
        self.tabs = QTabWidget()
        self.errors_list = QListWidget()
        self.errors_list.setToolTip("硬红线:必须修复,否则配置无法启动")
        self.warnings_list = QListWidget()
        self.warnings_list.setToolTip("软红线:建议修复,影响适配度评分")
        self.conventions_list = QListWidget()
        self.conventions_list.setToolTip("约定提示:最佳实践建议")
        self.tabs.addTab(self.errors_list, "🔴 硬红线 (0)")
        self.tabs.addTab(self.warnings_list, "🟠 软红线 (0)")
        self.tabs.addTab(self.conventions_list, "🟡 约定 (0)")
        layout.addWidget(self.tabs, 2)

        # === 跨段命名校验 ===
        layout.addWidget(QLabel("跨段命名校验:"))
        self.cross_list = QListWidget()
        layout.addWidget(self.cross_list, 1)

        # === 动态验证区 ===
        verify_box = QGroupBox("动态验证 (mihomo -t)")
        vb = QVBoxLayout(verify_box)
        self.mihomo_label = QLabel("mihomo: 未检测")
        self.mihomo_label.setStyleSheet("color:#666;")

        # geodata 目录输入(可选)
        geo_row = QHBoxLayout()
        geo_label = QLabel("geodata 目录(可选):")
        geo_label.setStyleSheet("color:#666;")
        self.geo_edit = QLineEdit()
        self.geo_edit.setPlaceholderText("留空=跳过动态验证 / 填入含 GeoSite.dat 的目录=启用")
        self.geo_edit.setToolTip(
            "geodata 目录:指向含 GeoSite.dat / GeoIP.dat 的目录\n"
            "(通常是 Clash 客户端的数据目录)\n"
            "留空则跳过动态验证,仅依赖静态 35 红线校验"
        )
        self.geo_browse = QPushButton("浏览...")
        self.geo_browse.clicked.connect(self._on_geo_browse)
        geo_row.addWidget(geo_label)
        geo_row.addWidget(self.geo_edit, 1)
        geo_row.addWidget(self.geo_browse)

        self.verify_btn = QPushButton("▶ 开始动态验证(可能耗时 45s)")
        self.verify_btn.setEnabled(False)  # 生成配置后才启用
        self.verify_output = QPlainTextEdit()
        self.verify_output.setReadOnly(True)
        self.verify_output.setPlaceholderText(
            "点击上方按钮启动 mihomo -t 动态验证...\n"
            "未填 geodata 目录将跳过(静态验证已足够保障正确性)"
        )
        self.verify_output.setMaximumHeight(150)
        vb.addWidget(self.mihomo_label)
        vb.addLayout(geo_row)
        vb.addWidget(self.verify_btn)
        vb.addWidget(self.verify_output)
        layout.addWidget(verify_box, 2)

        # 信号连接
        self.verify_btn.clicked.connect(self.verifyRequested.emit)

    def _on_geo_browse(self) -> None:
        """浏览选择 geodata 目录。"""
        path = QFileDialog.getExistingDirectory(
            self, "选择 geodata 目录(含 GeoSite.dat/GeoIP.dat)"
        )
        if path:
            self.geo_edit.setText(path)

    def get_geodata_dir(self) -> str:
        """返回当前填写的 geodata 目录(空字符串表示未提供)。"""
        return self.geo_edit.text().strip()

    def showReport(self, report: "Report", cross_errors: list[str]) -> None:
        """显示 35 红线校验报告(由 MainWindow 调用)。

        Args:
            report: checker.check() 返回的校验报告
            cross_errors: assembler 跨段命名校验错误列表
        """
        # 评分 + 颜色
        score = report.score
        self.score_label.setText(f"{score}/10")
        if not report.has_errors and score >= 9:
            color = "#2e7d32"  # 绿色
        elif report.has_errors:
            color = "#c62828"  # 红色
        else:
            color = "#f57f17"  # 橙色(有警告但无硬红线)
        self.score_label.setStyleSheet(
            f"font-size:28px; font-weight:bold; color:{color}; padding:4px;"
        )

        # 三栏列表
        self._fill_list(self.errors_list, report.errors)
        self._fill_list(self.warnings_list, report.warnings)
        self._fill_list(self.conventions_list, report.conventions)

        # 更新 Tab 标签计数
        self.tabs.setTabText(0, f"🔴 硬红线 ({len(report.errors)})")
        self.tabs.setTabText(1, f"🟠 软红线 ({len(report.warnings)})")
        self.tabs.setTabText(2, f"🟡 约定 ({len(report.conventions)})")

        # 跨段命名校验
        self.cross_list.clear()
        if cross_errors:
            for e in cross_errors:
                QListWidgetItem(f"❌ {e}", self.cross_list)
        else:
            QListWidgetItem("✅ 跨段命名一致性校验通过", self.cross_list)

        # 有配置后才允许动态验证
        self.verify_btn.setEnabled(True)

    def _fill_list(self, list_widget: QListWidget, items: list) -> None:
        """填充校验项列表。"""
        list_widget.clear()
        for it in items:
            text = f"{it.red_line}  {it.message}"
            if it.suggestion:
                text += f"  →  {it.suggestion}"
            QListWidgetItem(text, list_widget)

    def showVerifyResult(self, vres: "VerifyResult", mihomo_path: str | None) -> None:
        """显示动态验证结果(由 MainWindow 调用)。

        Args:
            vres: verifier.verify() 返回的验证结果
            mihomo_path: find_mihomo() 找到的路径(None 表示未找到)
        """
        self.mihomo_label.setText(f"mihomo: {mihomo_path or '未找到'}")
        self.verify_btn.setEnabled(True)  # 允许重试

        # 输出文本(截取最后 2000 字符避免过长)
        tail = vres.output[-2000:] if vres.output else ""
        if vres.success:
            self.verify_output.setPlainText(f"✅ mihomo -t 测试通过!\n\n{tail}")
            self.verify_output.setStyleSheet("color:#2e7d32;")
        else:
            err = vres.error or "未知错误"
            self.verify_output.setPlainText(f"❌ 动态验证失败\n{err}\n\n--- 完整输出 ---\n{tail}")
            self.verify_output.setStyleSheet("color:#c62828;")
