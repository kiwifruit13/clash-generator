"""主窗口:组合 4 widget + 信号路由 + 状态栏。

QMainWindow 布局:
- QSplitter(水平):左 QTabWidget(导入/偏好) + 右 QTabWidget(预览/报告)
- 菜单栏:文件(导入/导出/退出) + 帮助(关于)
- 状态栏:状态文本 + 进度条(busy) + 评分徽章

信号路由(关键):
- import_panel.generateRequested → 启动 PipelineWorker
- PipelineWorker.finished_ok → 更新 4 widget + 评分 + 切预览 Tab
- report_panel.verifyRequested → 写临时文件 + 启动 VerifyWorker
- VerifyWorker.finished_ok → 更新报告 + 删临时文件
- prefs_panel.exportRequested → 写 yaml_str 到用户路径

对应 M7 计划 Step 4。
"""

from __future__ import annotations

import tempfile
import traceback
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import (
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QLabel,
    QProgressBar,
)

from .state import SessionState
from .workers import PipelineWorker, VerifyWorker, STAGE_PERCENT
from .widgets.import_panel import ImportPanel
from .widgets.prefs_panel import PrefsPanel
from .widgets.preview_panel import PreviewPanel
from .widgets.report_panel import ReportPanel


class MainWindow(QMainWindow):
    """Clash/Mihomo 配置生成器主窗。

    持有 SessionState + Worker 引用(防 GC),路由 4 widget 的信号。
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Clash/Mihomo 配置生成器")
        self.resize(1100, 750)
        self.state = SessionState()

        # Worker 引用(防 GC,同一时刻只运行一个)
        self._pipeline_worker: PipelineWorker | None = None
        self._verify_worker: VerifyWorker | None = None

        self._build_ui()
        self._build_menu()
        self._connect_signals()

    # === UI 构建 ===

    def _build_ui(self) -> None:
        # 4 widget
        self.import_panel = ImportPanel()
        self.prefs_panel = PrefsPanel()
        self.preview_panel = PreviewPanel()
        self.report_panel = ReportPanel()

        # 左右分栏 Tab
        self.left_tabs = QTabWidget()
        self.left_tabs.addTab(self.import_panel, "📁 导入")
        self.left_tabs.addTab(self.prefs_panel, "⚙️ 偏好")

        self.right_tabs = QTabWidget()
        self.right_tabs.addTab(self.preview_panel, "📄 预览")
        self.right_tabs.addTab(self.report_panel, "📊 报告")

        # QSplitter 水平分栏
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.left_tabs)
        splitter.addWidget(self.right_tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([350, 750])
        self.setCentralWidget(splitter)

        # 状态栏
        self.status_label = QLabel("就绪")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)  # 百分比模式
        self.progress.setMaximumWidth(150)
        self.progress.setFormat("%v%")
        self.progress.hide()
        self.score_badge = QLabel("--/10")
        self.score_badge.setStyleSheet("font-weight:bold; padding:0 8px;")
        sb: QStatusBar = self.statusBar()
        sb.addWidget(self.status_label, 1)
        sb.addPermanentWidget(self.progress)
        sb.addPermanentWidget(self.score_badge)

    def _build_menu(self) -> None:
        menubar = self.menuBar()

        # 文件菜单
        file_menu = menubar.addMenu("文件(&F)")
        self.action_import = QAction("导入 proxies...", self)
        self.action_import.triggered.connect(self._menu_import)
        file_menu.addAction(self.action_import)

        self.action_export = QAction("导出配置(不覆盖)...", self)
        self.action_export.setEnabled(False)
        self.action_export.triggered.connect(self._menu_export)
        file_menu.addAction(self.action_export)

        file_menu.addSeparator()
        action_quit = QAction("退出", self)
        action_quit.triggered.connect(self.close)
        file_menu.addAction(action_quit)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助(&H)")
        action_about = QAction("关于", self)
        action_about.triggered.connect(self._menu_about)
        help_menu.addAction(action_about)

    def _connect_signals(self) -> None:
        """连接 4 widget 的信号到 MainWindow 的槽函数。"""
        self.import_panel.fileSelected.connect(self.on_file_selected)
        self.import_panel.generateRequested.connect(self.on_generate)
        self.prefs_panel.exportRequested.connect(self.on_export)
        self.prefs_panel.prefsChanged.connect(self.on_prefs_changed)
        self.report_panel.verifyRequested.connect(self.on_verify)

    # === 槽函数:偏好变更 ===

    def on_prefs_changed(self, prefs) -> None:
        """用户修改进阶选项:存入 state(下次生成时生效)。"""
        self.state.prefs = prefs

    # === 槽函数:文件选择 ===

    def on_file_selected(self, path: Path) -> None:
        """用户选择/拖入文件。"""
        self.state.input_path = path
        self.state.reset()  # 切换文件时清空旧产物
        self.status_label.setText(f"已选择:{path.name}")
        self.score_badge.setText("--/10")
        self.action_export.setEnabled(False)

    # === 槽函数:生成配置 ===

    def on_generate(self, path: Path) -> None:
        """用户点击"生成配置":启动 PipelineWorker。"""
        if not path.exists():
            QMessageBox.critical(self, "错误", f"文件不存在:{path}")
            return

        # 从偏好面板采集当前 prefs(智能模式=全默认)
        prefs = self.prefs_panel.get_prefs()
        self.state.prefs = prefs

        # 禁用 UI + 显示进度
        self.import_panel.setGenerating(True)
        self.action_export.setEnabled(False)
        self.progress.setValue(0)  # 重置进度条
        self.progress.show()
        mode_label = "进阶模式" if prefs.advanced_mode else "智能模式"
        self.status_label.setText(f"生成中({mode_label})...")

        # 启动 Worker(携带 prefs)
        self._pipeline_worker = PipelineWorker(path, prefs)
        self._pipeline_worker.progress.connect(self._on_progress)
        self._pipeline_worker.finished_ok.connect(self._on_pipeline_done)
        self._pipeline_worker.failed.connect(self._on_pipeline_failed)
        self._pipeline_worker.start()

    def _on_progress(self, stage: int, message: str) -> None:
        """Worker 报告进度(阶段索引 + 文本)。"""
        self.progress.setValue(stage)
        self.status_label.setText(message)

    def _on_pipeline_done(self, result) -> None:
        """PipelineWorker 成功完成:更新 4 widget + 状态。"""
        # 更新会话状态
        self.state.yaml_str = result.yaml_str
        self.state.report = result.report

        # 更新 4 widget
        self.import_panel.showProfile(
            result.clean_result, result.profile, result.grouping
        )
        self.preview_panel.setYaml(result.yaml_str)
        self.report_panel.showReport(result.report, result.cross_errors)

        # 更新状态栏
        score = result.report.score
        color = "#2e7d32" if score >= 9 and not result.report.has_errors else "#c62828"
        self.score_badge.setText(f"{score}/10")
        self.score_badge.setStyleSheet(f"font-weight:bold; padding:0 8px; color:{color};")
        self.status_label.setText(f"完成 评分 {score}/10")

        # 恢复 UI
        self.import_panel.setGenerating(False)
        self.action_export.setEnabled(True)
        self.prefs_panel.setHasYaml(True)
        self.progress.hide()

        # BUG-05 修复:存在跨段/红线错误时自动切到"报告"Tab,避免错误被隐藏
        if result.cross_errors or result.report.has_errors:
            self.right_tabs.setCurrentIndex(1)
        else:
            self.right_tabs.setCurrentIndex(0)

    def _on_pipeline_failed(self, tb: str) -> None:
        """PipelineWorker 失败:弹窗显示 traceback。"""
        self.import_panel.setGenerating(False)
        self.progress.hide()
        self.status_label.setText("生成失败")
        QMessageBox.critical(self, "生成失败", f"配置生成过程中发生错误:\n\n{tb}")

    # === 槽函数:动态验证 ===

    def on_verify(self) -> None:
        """用户点击"开始动态验证":写临时文件 + 启动 VerifyWorker。"""
        if not self.state.has_yaml():
            QMessageBox.warning(self, "无法验证", "请先生成配置。")
            return

        # 检查 geodata 目录(留空=跳过动态验证)
        geodata_str = self.report_panel.get_geodata_dir()
        if not geodata_str:
            # A3b(F5)增强:未提供 geodata 或未安装内核时,明确标注"动态验证降级",不宣称静态=正确
            self.report_panel.verify_output.setPlainText(
                "⏸ 动态验证已降级(未提供 geodata 目录)\n\n"
                "跳过 mihomo -t 真实测试。静态 35 红线校验只能保证规则/引用一致性,\n"
                "不能完全替代内核实测。\n"
                "如需动态验证,请在上方填入 geodata 目录\n"
                "(通常为 Clash 客户端的数据目录,含 GeoSite.dat/GeoIP.dat)"
            )
            self.report_panel.verify_output.setStyleSheet("color:#b26a00;")
            self.status_label.setText("动态验证已降级(静态校验通过)")
            return

        geodata_dir = Path(geodata_str)
        if not geodata_dir.is_dir():
            QMessageBox.warning(self, "目录不存在", f"geodata 目录不存在:\n{geodata_dir}")
            return
        self.state.geodata_dir = geodata_dir

        # 写临时文件(core verify() 需要文件路径)
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False, encoding="utf-8"
            )
            tmp.write(self.state.yaml_str)
            tmp.close()
            self.state.tmp_verify_path = Path(tmp.name)
        except OSError as e:
            QMessageBox.critical(self, "错误", f"写入临时文件失败:{e}")
            return

        # 禁用按钮 + 显示进度
        self.report_panel.verify_btn.setEnabled(False)
        self.progress.setValue(0)  # 重置进度条
        self.progress.show()
        self.status_label.setText(f"动态验证中(geodata: {geodata_dir.name})...")

        # 启动 Worker(携带 geodata_dir)
        self._verify_worker = VerifyWorker(
            self.state.tmp_verify_path, timeout=45, geodata_dir=geodata_dir
        )
        self._verify_worker.progress.connect(self._on_progress)
        self._verify_worker.finished_ok.connect(self._on_verify_done)
        self._verify_worker.failed.connect(self._on_verify_failed)
        self._verify_worker.start()

    def _on_verify_done(self, vres) -> None:
        """VerifyWorker 完成:更新报告 + 清理临时文件。"""
        # 显示结果(同步查找 mihomo 路径用于展示,find_mihomo 很快)
        from generator.core.verifier import find_mihomo
        mihomo_path = find_mihomo()
        self.report_panel.showVerifyResult(vres, mihomo_path)

        # 恢复 UI
        self.progress.hide()
        if vres.success:
            self.status_label.setText("动态验证通过 ✅")
        else:
            self.status_label.setText("动态验证失败 ❌")

        # 清理临时文件
        self._cleanup_tmp_verify()

    def _on_verify_failed(self, tb: str) -> None:
        """VerifyWorker 异常:弹窗 + 清理。"""
        self.report_panel.verify_btn.setEnabled(True)
        self.progress.hide()
        self.status_label.setText("验证异常")
        self._cleanup_tmp_verify()
        QMessageBox.critical(self, "验证异常", f"动态验证过程中发生错误:\n\n{tb}")

    def _cleanup_tmp_verify(self) -> None:
        """清理临时验证文件。"""
        if self.state.tmp_verify_path is not None:
            try:
                self.state.tmp_verify_path.unlink(missing_ok=True)
            except OSError:
                pass
            self.state.tmp_verify_path = None

    # === 槽函数:导出 ===

    def on_export(self, path: Path) -> None:
        """用户选择导出路径:写 yaml_str 到文件。"""
        if not self.state.has_yaml():
            QMessageBox.warning(self, "无法导出", "请先生成配置。")
            return

        # 评分较低时二次确认(进阶用户知情赋能)
        if self.state.report is not None and self.state.report.has_errors:
            ret = QMessageBox.warning(
                self, "导出确认",
                "当前配置存在 🔴 硬红线错误,导出后可能无法启动。确定导出吗?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if ret != QMessageBox.Yes:
                return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.state.yaml_str)
            self.status_label.setText(f"已导出:{path.name}")
            QMessageBox.information(self, "导出成功", f"配置已导出到:\n{path}")
        except OSError as e:
            QMessageBox.warning(self, "导出失败", f"写入文件失败:{e}")

    # === 菜单动作 ===

    def _menu_import(self) -> None:
        """菜单"导入":触发导入面板的浏览。"""
        self.import_panel._on_browse()

    def _menu_export(self) -> None:
        """菜单"导出":触发偏好面板的导出。"""
        if not self.state.has_yaml():
            QMessageBox.information(self, "提示", "请先生成配置再导出。")
            return
        self.prefs_panel._on_export()

    def _menu_about(self) -> None:
        """菜单"关于"。"""
        QMessageBox.about(
            self, "关于",
            "Clash/Mihomo 配置生成器 v0.1.0\n\n"
            "用户提供 proxies 文件,自动补全其余 6 段,\n"
            "生成适配度 ≥ 9/10 的完整 Clash YAML 配置。\n\n"
            "内核:Mihomo\n"
            "框架:PySide6",
        )

    # === 关闭清理 ===

    def closeEvent(self, event: QCloseEvent) -> None:
        """关闭窗口时清理临时文件 + 终止 Worker。"""
        self._cleanup_tmp_verify()
        # 等待 Worker 结束(若仍在运行)
        if self._pipeline_worker is not None and self._pipeline_worker.isRunning():
            self._pipeline_worker.quit()
            self._pipeline_worker.wait(3000)
        if self._verify_worker is not None and self._verify_worker.isRunning():
            self._verify_worker.quit()
            self._verify_worker.wait(3000)
        event.accept()
