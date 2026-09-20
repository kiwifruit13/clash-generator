"""偏好/进阶选项面板。

智能/进阶双模式:
- 智能模式(默认):全部使用内置最佳实践,控件 disabled
- 进阶模式:31 选项 × 7 组可调,带红线映射 tooltip

对应文档:
- options-risk-matrix.md(31 选项清单)
- options-deep-understanding.md(6 层认知)
- advanced-harmony.md(三层调和:提示而非拦截)

信号:
    exportRequested(object): 用户选择导出路径,携带 Path
    prefsChanged(object): 任意选项变更,携带 Prefs(供 MainWindow 实时联动)
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from generator.core.prefs import Prefs


class PrefsPanel(QWidget):
    """偏好面板(智能/进阶双模式)。

    信号:
        exportRequested(object): 用户选择导出路径,携带 Path
        prefsChanged(object): 任意选项变更,携带 Prefs
    """

    exportRequested = Signal(object)
    prefsChanged = Signal(object)

    def __init__(self):
        super().__init__()
        self._has_yaml = False
        self._build_ui()
        self._on_toggle_advanced(False)  # 初始智能模式

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)

        # === 智能模式横幅 ===
        self.banner = QLabel(
            "🤖 智能模式(默认)\n"
            "全部采用内置最佳实践模板,依据节点画像自动适配。\n"
            "勾选下方「进阶模式」可调整 31 个选项。"
        )
        self.banner.setStyleSheet(
            "background:#e8f5e9; border:1px solid #4caf50; border-radius:4px; "
            "padding:8px; color:#2e7d32;"
        )
        self.banner.setWordWrap(True)
        outer.addWidget(self.banner)

        # === 进阶模式开关 ===
        self.cb_advanced = QCheckBox("🔧 进阶模式(可调整选项)")
        self.cb_advanced.setStyleSheet("font-weight:bold; padding:4px;")
        self.cb_advanced.toggled.connect(self._on_toggle_advanced)
        outer.addWidget(self.cb_advanced)

        # === 滚动区域(7 组选项) ===
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)

        self._build_basic_group(container_layout)
        self._build_dns_group(container_layout)
        self._build_groups_group(container_layout)
        self._build_rules_group(container_layout)
        self._build_providers_group(container_layout)
        self._build_extra_group(container_layout)
        self._build_info_group(container_layout)
        container_layout.addStretch()

        scroll.setWidget(container)
        outer.addWidget(scroll, 1)

        # === 导出按钮 ===
        export_row = QHBoxLayout()
        export_row.addStretch()
        self.export_btn = QPushButton("💾 导出 final.yaml...")
        self.export_btn.setStyleSheet("font-weight:bold; padding:6px 16px;")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._on_export)
        export_row.addWidget(self.export_btn)
        outer.addLayout(export_row)

    # === 7 组选项构建 ===

    def _build_basic_group(self, parent_layout: QVBoxLayout) -> None:
        grp = QGroupBox("① 基础")
        form = QFormLayout(grp)

        self.sb_port = QSpinBox()
        self.sb_port.setRange(1, 65535)
        self.sb_port.setValue(7890)
        self.sb_port.setToolTip("mixed-port:混合代理端口(HTTP/SOCKS5 共用)")

        self.cb_allow_lan = QCheckBox("允许局域网连接")
        self.cb_allow_lan.setChecked(True)
        self.cb_allow_lan.setToolTip("⚠️ allow-lan:开启后局域网设备可访问代理\n开 allow-lan 时建议填 secret")

        self.cb_log_level = QComboBox()
        self.cb_log_level.addItems(["silent", "error", "warning", "info", "debug"])
        self.cb_log_level.setCurrentText("info")
        self.cb_log_level.setToolTip("log-level:日志级别(G-2 红线:仅这 5 个值)")

        self.edit_controller = QLineEdit("127.0.0.1:9090")
        self.edit_controller.setToolTip("⚠️ external-controller:API 监听地址\n留空则禁用外部控制")

        self.edit_secret = QLineEdit()
        self.edit_secret.setPlaceholderText("留空=无认证(⚠️ allow-lan 时危险)")
        self.edit_secret.setToolTip("⚠️ secret:API 认证密钥\nallow-lan=true 时强烈建议设置")

        self.cb_ipv6 = QComboBox()
        self.cb_ipv6.addItems(["auto", "true", "false"])
        self.cb_ipv6.setCurrentText("auto")
        self.cb_ipv6.setToolTip(
            "⚠️ ipv6:auto=依节点画像 / true=强制开启 / false=关闭\n"
            "开启时需补 IPv6 兜底规则(层1 自动补 fake-ip-v6-range)"
        )

        form.addRow("mixed-port:", self.sb_port)
        form.addRow("", self.cb_allow_lan)
        form.addRow("log-level:", self.cb_log_level)
        form.addRow("external-controller:", self.edit_controller)
        form.addRow("secret:", self.edit_secret)
        form.addRow("ipv6:", self.cb_ipv6)
        parent_layout.addWidget(grp)

    def _build_dns_group(self, parent_layout: QVBoxLayout) -> None:
        grp = QGroupBox("② DNS")
        form = QFormLayout(grp)

        self.cb_enhanced = QComboBox()
        self.cb_enhanced.addItems(["fake-ip", "redir-host"])
        self.cb_enhanced.setCurrentText("fake-ip")
        self.cb_enhanced.setToolTip(
            "⚠️ enhanced-mode:fake-ip(推荐)= 假 IP 映射 / redir-host = 真实 IP\n"
            "切 redir-host 有 DNS 泄露风险(-1.5 分),会自动补偿 sniffer"
        )

        self.cb_respect_rules = QCheckBox("respect-rules(代理 DNS 遵守路由规则)")
        self.cb_respect_rules.setChecked(True)
        self.cb_respect_rules.setToolTip(
            "⚠️ respect-rules:DNS 连接遵守路由规则\n"
            "必须配 proxy-server-nameserver(已内置,防鸡生蛋)\n"
            "不建议与 prefer-h3 同用"
        )

        form.addRow("enhanced-mode:", self.cb_enhanced)
        form.addRow("", self.cb_respect_rules)
        parent_layout.addWidget(grp)

    def _build_groups_group(self, parent_layout: QVBoxLayout) -> None:
        grp = QGroupBox("③ 代理组")
        form = QFormLayout(grp)

        self.sb_interval = QSpinBox()
        self.sb_interval.setRange(30, 3600)
        self.sb_interval.setSuffix(" 秒")
        self.sb_interval.setValue(300)
        self.sb_interval.setToolTip("url-test interval:测速间隔(PG-3 红线:必填)")

        self.sb_tolerance = QSpinBox()
        self.sb_tolerance.setRange(0, 1000)
        self.sb_tolerance.setSuffix(" ms")
        self.sb_tolerance.setValue(50)
        self.sb_tolerance.setToolTip("url-test tolerance:延迟容差(差值内不切换)")

        self.cb_grouping = QComboBox()
        self.cb_grouping.addItems(["auto", "standard", "minimal", "partial"])
        self.cb_grouping.setCurrentText("auto")
        self.cb_grouping.setToolTip(
            "分组策略(333 测试新增):\n"
            "auto=依画像建议 / standard=全组 / minimal=仅自动优选 / partial=非空子组"
        )

        self.cb_outlet = QComboBox()
        self.cb_outlet.addItems(["🚀 自动优选", "🚀 节点选择", "DIRECT", "REJECT"])
        self.cb_outlet.setCurrentText("🚀 自动优选")
        self.cb_outlet.setToolTip(
            "⚠️ 兜底出口:MATCH 规则的最终出口\n"
            "DIRECT=国内直连(翻墙失效) / REJECT=全断(慎用)"
        )

        form.addRow("测速间隔:", self.sb_interval)
        form.addRow("延迟容差:", self.sb_tolerance)
        form.addRow("分组策略:", self.cb_grouping)
        form.addRow("兜底出口:", self.cb_outlet)
        parent_layout.addWidget(grp)

    def _build_rules_group(self, parent_layout: QVBoxLayout) -> None:
        grp = QGroupBox("④ 规则")
        form = QFormLayout(grp)

        self.cb_template = QComboBox()
        self.cb_template.addItems(["standard", "minimal"])  # D8: 移除 fine 假选项
        self.cb_template.setCurrentText("standard")
        self.cb_template.setToolTip(
            "规则模板(333 测试新增):\n"
            "standard=完整(AI+流媒体+Google) / minimal=极简(仅翻墙)\n"
            "原 fine 为未实现假选项,已移除(D8)"
        )

        form.addRow("规则模板:", self.cb_template)
        parent_layout.addWidget(grp)

    def _build_providers_group(self, parent_layout: QVBoxLayout) -> None:
        grp = QGroupBox("⑤ 规则集")
        form = QFormLayout(grp)

        self.cb_source = QComboBox()
        self.cb_source.addItems(["loyalsoldier"])  # BUG-02 修复:收敛为单一源
        self.cb_source.setCurrentText("loyalsoldier")
        self.cb_source.setToolTip(
            "规则集源:Loyalsoldier(当前唯一支持)\n"
            "原 sukkaw/quixoticheart 为假选项,已收敛移除(见 BUG-02)"
        )

        rulesets_row = QHBoxLayout()
        self.cb_apple = QCheckBox("apple")
        self.cb_apple.setChecked(True)
        self.cb_icloud = QCheckBox("icloud")
        self.cb_icloud.setChecked(True)
        self.cb_google = QCheckBox("google")
        self.cb_google.setChecked(True)
        self.cb_apple.setToolTip("🔴 减规则集但 rules 仍引用 = 有效性错误(导出拦截)")
        self.cb_icloud.setToolTip("🔴 减规则集但 rules 仍引用 = 有效性错误(导出拦截)")
        self.cb_google.setToolTip("🔴 减规则集但 rules 仍引用 = 有效性错误(导出拦截)")
        rulesets_row.addWidget(self.cb_apple)
        rulesets_row.addWidget(self.cb_icloud)
        rulesets_row.addWidget(self.cb_google)
        rulesets_row.addStretch()

        form.addRow("规则集源:", self.cb_source)
        form.addRow("独立规则集:", rulesets_row)
        parent_layout.addWidget(grp)

    def _build_extra_group(self, parent_layout: QVBoxLayout) -> None:
        grp = QGroupBox("⑥ 附加")
        form = QFormLayout(grp)

        self.cb_tun = QCheckBox("开启 TUN 模式(虚拟网卡,接管全局流量)")
        self.cb_tun.setToolTip(
            "⚠️ TUN:开启后自动补 sniffer + dns-hijack + auto-route(层1 自动补偿)\n"
            "软路由/全局代理场景建议开启"
        )

        self.cb_profile = QCheckBox("profile(store-fake-ip + tracing)")
        self.cb_profile.setChecked(True)
        self.cb_profile.setToolTip("profile:存储 fake-ip 映射 + 连接追踪(便于调试)")

        form.addRow("", self.cb_tun)
        form.addRow("", self.cb_profile)
        parent_layout.addWidget(grp)

    def _build_info_group(self, parent_layout: QVBoxLayout) -> None:
        grp = QGroupBox("⑦ 告知(用于智能建议,不直接写入配置)")
        form = QFormLayout(grp)

        usage_row = QHBoxLayout()
        self.cb_usage_ai = QCheckBox("AI")
        self.cb_usage_ai.setChecked(True)
        self.cb_usage_stream = QCheckBox("流媒体")
        self.cb_usage_stream.setChecked(True)
        self.cb_usage_game = QCheckBox("游戏")
        self.cb_usage_ai.setToolTip("⚠️ AI 用途:无 reality 节点则安全专线空,提示降级")
        self.cb_usage_stream.setToolTip("流媒体:优先 CF CDN 网页浏览组")
        self.cb_usage_game.setToolTip("游戏:自动补 STUN fake-ip-filter(层1 补偿)")
        usage_row.addWidget(self.cb_usage_ai)
        usage_row.addWidget(self.cb_usage_stream)
        usage_row.addWidget(self.cb_usage_game)
        usage_row.addStretch()

        self.cb_client = QComboBox()
        self.cb_client.addItems(["pc", "router", "mobile"])
        self.cb_client.setToolTip("ℹ️ 客户端:router 建议开 TUN,mobile 建议关 TUN")

        form.addRow("用途:", usage_row)
        form.addRow("客户端:", self.cb_client)
        parent_layout.addWidget(grp)

    # === 交互处理 ===

    def _on_toggle_advanced(self, checked: bool) -> None:
        """切换智能/进阶模式。"""
        # 启用/禁用所有选项控件
        for grp in self.findChildren(QGroupBox):
            grp.setEnabled(checked)

        if checked:
            self.banner.setText(
                "🔧 进阶模式\n"
                "⚠️ 修改选项可能影响适配度。每个控件 tooltip 标注红线编号与风险等级。\n"
                "提示而非拦截:即使 🔴 红线也允许编辑,仅导出时二次确认。"
            )
            self.banner.setStyleSheet(
                "background:#fff3e0; border:1px solid #ff9800; border-radius:4px; "
                "padding:8px; color:#e65100;"
            )
        else:
            self.banner.setText(
                "🤖 智能模式(默认)\n"
                "全部采用内置最佳实践模板,依据节点画像自动适配。\n"
                "勾选上方「进阶模式」可调整 31 个选项。"
            )
            self.banner.setStyleSheet(
                "background:#e8f5e9; border:1px solid #4caf50; border-radius:4px; "
                "padding:8px; color:#2e7d32;"
            )

        self._emit_prefs()

    def _emit_prefs(self) -> None:
        """采集当前选项,发出 prefsChanged 信号。"""
        self.prefsChanged.emit(self.get_prefs())

    def get_prefs(self) -> Prefs:
        """采集面板当前值,返回 Prefs 对象。"""
        usage: list[str] = []
        if self.cb_usage_ai.isChecked():
            usage.append("ai")
        if self.cb_usage_stream.isChecked():
            usage.append("streaming")
        if self.cb_usage_game.isChecked():
            usage.append("gaming")

        return Prefs(
            advanced_mode=self.cb_advanced.isChecked(),
            mixed_port=self.sb_port.value(),
            allow_lan=self.cb_allow_lan.isChecked(),
            log_level=self.cb_log_level.currentText(),
            external_controller=self.edit_controller.text().strip(),
            secret=self.edit_secret.text().strip(),
            ipv6=self.cb_ipv6.currentText(),
            enhanced_mode=self.cb_enhanced.currentText(),
            respect_rules=self.cb_respect_rules.isChecked(),
            url_test_interval=self.sb_interval.value(),
            url_test_tolerance=self.sb_tolerance.value(),
            fallback_outlet=self.cb_outlet.currentText(),
            grouping_strategy=self.cb_grouping.currentText(),
            rule_template=self.cb_template.currentText(),
            ruleset_source=self.cb_source.currentText(),
            enable_apple=self.cb_apple.isChecked(),
            enable_icloud=self.cb_icloud.isChecked(),
            enable_google=self.cb_google.isChecked(),
            tun_enable=self.cb_tun.isChecked(),
            profile=self.cb_profile.isChecked(),
            usage=usage,
            client=self.cb_client.currentText(),
        )

    def _on_export(self) -> None:
        """点击导出按钮:检查状态 + 弹出保存对话框。

        默认文件名自动附加时间戳,避免覆盖同名文件:
        final_20260801_143052.yaml
        """
        if not self._has_yaml:
            QMessageBox.warning(self, "无法导出", "请先点击「生成配置」产生 yaml 后再导出。")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"final_{timestamp}.yaml"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出 final.yaml",
            default_name,
            "YAML 文件 (*.yaml *.yml);;所有文件 (*)",
        )
        if path:
            self.exportRequested.emit(Path(path))

    def setHasYaml(self, has: bool) -> None:
        """设置是否已生成可导出的 yaml(由 MainWindow 调用)。"""
        self._has_yaml = has
        self.export_btn.setEnabled(has)
