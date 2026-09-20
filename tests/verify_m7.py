"""M7 GUI 壳验证脚本:offscreen 自动化验收(无需人工点击)。

设置 QT_QPA_PLATFORM=offscreen 后,用 QEventLoop 等待 Worker 信号:
1. 启动 MainWindow
2. 直接启动 PipelineWorker(绕过文件对话框)
3. 断言:节点数>0、无🔴硬红线、评分≥9、yaml 含 mixed-port
4. 手动调 _on_pipeline_done 验证 UI 同步更新
5. 启动 VerifyWorker,断言:success=True 或 error 含"未安装"

用法:
    uv run python tests/verify_m7.py
    (QT_QPA_PLATFORM=offscreen 已在脚本内设置)

对应 M7 计划 Step 6。
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# 必须在 import PySide6 前设置 offscreen 平台
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).parent.parent))

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

app = QApplication.instance() or QApplication(sys.argv)

from generator.gui.main_window import MainWindow  # noqa: E402
from generator.gui.workers import PipelineWorker, VerifyWorker  # noqa: E402

CHROMEGO = Path(__file__).parent.parent.parent / "chromego.txt"


def wait_worker(worker, timeout_ms: int = 15000) -> tuple[str, object]:
    """启动 Worker 并等待完成(QEventLoop 方式)。

    QSignalSpy.wait() 在 offscreen 模式下不可靠,改用 QEventLoop。

    Args:
        worker: PipelineWorker 或 VerifyWorker 实例
        timeout_ms: 超时毫秒

    Returns:
        (status, payload): status 为 "ok"/"fail"/"timeout"
            "ok" → payload 是 PipelineResult/VerifyResult
            "fail" → payload 是 traceback 字符串
            "timeout" → payload 是 None
    """
    loop = QEventLoop()
    result: list[tuple[str, object]] = []

    def on_ok(payload):
        result.append(("ok", payload))
        loop.quit()

    def on_fail(err):
        result.append(("fail", err))
        loop.quit()

    worker.finished_ok.connect(on_ok)
    worker.failed.connect(on_fail)

    # 超时定时器
    QTimer.singleShot(timeout_ms, loop.quit)

    worker.start()
    loop.exec()

    if result:
        return result[0]
    return ("timeout", None)


def print_header(text: str) -> None:
    bar = "=" * 60
    print(f"\n{bar}\n  {text}\n{bar}")


def main() -> int:
    print_header("M7 GUI 壳验证 (offscreen)")

    if not CHROMEGO.exists():
        print(f"❌ 测试输入不存在: {CHROMEGO}")
        return 1

    # === 1. 启动 MainWindow ===
    print("\n[1] 启动 MainWindow")
    w = MainWindow()
    w.show()
    QTest.qWait(100)  # 让窗口初始化
    print("  ✅ 主窗已显示")
    print(f"  ✅ 窗口标题: {w.windowTitle()}")
    print(f"  ✅ 状态栏初始: {w.status_label.text()}")

    # === 2. PipelineWorker 全链路 ===
    print_header("[2] PipelineWorker 全链路")
    worker = PipelineWorker(CHROMEGO)
    status, payload = wait_worker(worker, timeout_ms=20000)

    if status == "timeout":
        print("❌ PipelineWorker 超时(20s)")
        return 1
    if status == "fail":
        print(f"❌ PipelineWorker 失败:\n{payload}")
        return 1

    result = payload
    print(f"  ✅ 节点数: {result.clean_result.count}")
    print(f"  ✅ 协议: {result.profile.protocol_counts}")
    print(f"  ✅ 分组策略: {result.grouping.suggested_strategy}")
    print(f"  ✅ 评分: {result.report.score}/10")
    print(f"  ✅ 跨段错误: {len(result.cross_errors)} 项")
    print(f"  ✅ YAML 长度: {len(result.yaml_str)} 字符")
    print(f"  ✅ 红线: 🔴{len(result.report.errors)}  🟠{len(result.report.warnings)}  🟡{len(result.report.conventions)}")

    # === 3. 核心断言 ===
    print_header("[3] 核心断言")
    assert result.clean_result.count > 0, "节点数为 0"
    print("  ✅ 节点数 > 0")
    assert not result.report.has_errors, f"存在🔴硬红线: {[i.message for i in result.report.errors]}"
    print("  ✅ 无🔴硬红线")
    assert result.report.score >= 9, f"评分 {result.report.score} < 9"
    print(f"  ✅ 评分 {result.report.score} >= 9")
    assert "mixed-port" in result.yaml_str, "yaml 缺 mixed-port"
    print("  ✅ yaml 含 mixed-port")
    assert "proxy-groups" in result.yaml_str, "yaml 缺 proxy-groups"
    print("  ✅ yaml 含 proxy-groups")
    assert "rules" in result.yaml_str, "yaml 缺 rules"
    print("  ✅ yaml 含 rules")

    # === 4. UI 同步更新验证 ===
    print_header("[4] UI 同步更新验证")
    w._on_pipeline_done(result)
    QTest.qWait(50)

    preview_text = w.preview_panel.viewer.toPlainText()
    assert preview_text.startswith("mixed-port"), "预览面板未更新或内容错误"
    print("  ✅ 预览面板已填充 YAML")
    print(f"  ✅ 预览前 40 字符: {preview_text[:40]!r}")

    score_badge = w.score_badge.text()
    assert score_badge == f"{result.report.score}/10", f"评分徽章错误: {score_badge}"
    print(f"  ✅ 评分徽章: {score_badge}")

    # 检查导入面板画像已更新
    assert w.import_panel.lbl_total.text() != "—", "画像总数未更新"
    print(f"  ✅ 画像总数: {w.import_panel.lbl_total.text()}")

    # 检查报告面板已更新
    assert w.report_panel.score_label.text() == f"{result.report.score}/10", "报告评分未更新"
    print(f"  ✅ 报告评分: {w.report_panel.score_label.text()}")

    # 检查导出按钮已启用
    assert w.prefs_panel.export_btn.isEnabled(), "导出按钮未启用"
    print("  ✅ 导出按钮已启用")

    # === 5. VerifyWorker 动态验证 ===
    print_header("[5] VerifyWorker 动态验证")
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        f.write(result.yaml_str)
        tmp_path = Path(f.name)
    print(f"  临时文件: {tmp_path}")

    vw = VerifyWorker(tmp_path, timeout=45)
    v_status, v_payload = wait_worker(vw, timeout_ms=60000)

    if v_status == "timeout":
        print("❌ VerifyWorker 超时(60s)")
        tmp_path.unlink(missing_ok=True)
        return 1
    if v_status == "fail":
        print(f"❌ VerifyWorker 异常:\n{v_payload}")
        tmp_path.unlink(missing_ok=True)
        return 1

    vres = v_payload
    print(f"  ✅ success={vres.success}")
    if vres.success:
        print("  ✅ mihomo -t 测试通过")
        for line in vres.output.splitlines()[-5:]:
            if line.strip():
                print(f"     {line.strip()}")
    else:
        print(f"  ⚠️ 失败/未安装: {vres.error[:100]}")
        # 未安装 mihomo 是可接受的(测试环境未必有 mihomo)
        assert ("未安装" in vres.error or "PATH" in vres.error
                or "未找到" in vres.error), \
            f"验证失败原因非'未安装': {vres.error}"
        print("  ✅ 失败原因符合预期(mihomo 未安装)")

    tmp_path.unlink(missing_ok=True)

    # === 6. 关闭清理 ===
    print_header("[6] 关闭清理")
    w.close()
    QTest.qWait(50)
    print("  ✅ 主窗已关闭")

    # === 总结 ===
    print_header("M7 GUI 壳验证总结")
    status_map = {
        "PipelineWorker 全链路": "✅",
        "核心断言(节点/评分/yaml)": "✅",
        "UI 同步更新": "✅",
        "VerifyWorker": "✅",
        "主窗关闭清理": "✅",
    }
    for k, v in status_map.items():
        print(f"  {v}  {k}")

    print("\n✅ M7 GUI 壳验证全部通过")
    print("👉 下一步:手动运行 'uv run python main.py' 确认 GUI 可见可交互")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
