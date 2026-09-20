"""后台工作线程(QThread):封装 core 全链路调用,避免卡 UI。

两个 Worker:
- PipelineWorker: 跑 clean → analyze_all → assemble → check
- VerifyWorker:   跑 find_mihomo → verify(可能 45s)

设计要点(M7 计划 Step 1):
- 继承 QThread(MVP 一次性任务,无需事件循环)
- 所有 run() 用 try/except 包裹,失败回传 traceback(防 QThread 静默崩溃)
- 不在 Worker 内更新任何 UI(Qt 严格规定:UI 控件只能在主线程操作)
- finished_ok 用 Signal(object) 传 dataclass,避免类型耦合

性能优化(v1.1):
- PipelineWorker 使用 analyze_all() 单次遍历生成画像+分组建议
- 分阶段进度反馈:progress 信号携带阶段索引(0-4)

对应 mihomo-spec.md 错误规避指南第五条(鲁棒性):完整异常捕获。
"""

from __future__ import annotations

import logging
import traceback
from pathlib import Path

import yaml
from PySide6.QtCore import QThread, Signal

from generator.core.analyzer import analyze_all
from generator.core.assembler import assemble
from generator.core.checker import check
from generator.core.cleaner import clean
from generator.core.prefs import Prefs
from generator.core.verifier import VerifyResult, find_mihomo, verify

from .state import PipelineResult

# D6: 轻量流水线打点(stdout;GUI 环境下通常被 PySide6 前端可见或重定向,CLI/日志可见)
log = logging.getLogger("clash-generator")

# 分阶段进度常量(用于 progress 信号的第一个参数)
STAGE_CLEAN = 0        # 清洗 (25%)
STAGE_ANALYZE = 1      # 画像分析 (50%)
STAGE_ASSEMBLE = 2     # 组装 7 段 (75%)
STAGE_CHECK = 3        # 红线校验 (90%)
STAGE_DONE = 4         # 完成 (100%)

# 每个阶段对应的进度百分比
STAGE_PERCENT = {
    STAGE_CLEAN: 25,
    STAGE_ANALYZE: 50,
    STAGE_ASSEMBLE: 75,
    STAGE_CHECK: 90,
    STAGE_DONE: 100,
}


class PipelineWorker(QThread):
    """跑 clean → analyze → assemble → check 全链路(后台)。

    信号:
        progress(int, str): 阶段索引 + 阶段文本
        finished_ok(PipelineResult): 成功完成,携带全链路产物
        failed(str): 失败,携带 traceback 字符串
    """

    progress = Signal(int, str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, input_path: Path, prefs: Prefs | None = None):
        super().__init__()
        self.input_path = input_path
        self.prefs = prefs or Prefs.smart()

    def run(self) -> None:  # noqa: PLR0915
        """执行全链路(在线程内运行)。

        任何异常都通过 failed 信号回传,不向上抛出(QThread 顶层异常会静默丢失)。
        """
        try:
            log.info("pipeline start: %s", self.input_path)
            # M2: 输入清洗 (0% → 25%)
            self.progress.emit(STAGE_CLEAN, "清洗中...")
            clean_result = clean(self.input_path)
            log.info("clean done: nodes=%d excluded=%d", len(clean_result.nodes), len(clean_result.excluded_names))

            # M3: 节点画像 + 分组可行性分析(单次遍历优化) (25% → 50%)
            self.progress.emit(STAGE_ANALYZE, "画像分析中...")
            profile, grouping = analyze_all(clean_result)

            # M4+M5: 组装 7 段 (50% → 75%)
            # BUG-04 修复:复用首次 clean 结果,避免二次清洗导致双快照不一致
            self.progress.emit(STAGE_ASSEMBLE, "组装 7 段中...")
            yaml_str, cross_errors = assemble(self.input_path, self.prefs, clean_result=clean_result)
            log.info("assemble done: cross_errors=%d", len(cross_errors))

            # M5: 35 红线静态校验 (75% → 90%)
            self.progress.emit(STAGE_CHECK, "35 红线校验中...")
            config = yaml.safe_load(yaml_str)
            report = check(config)
            log.info("check done: score=%.1f, errors=%d", report.score, len(report.errors))

            # 完成 (90% → 100%)
            self.progress.emit(STAGE_DONE, "完成!")
            log.info("pipeline done")

            self.finished_ok.emit(PipelineResult(
                clean_result=clean_result,
                profile=profile,
                grouping=grouping,
                yaml_str=yaml_str,
                cross_errors=cross_errors,
                report=report,
            ))
        except Exception:
            self.failed.emit(traceback.format_exc())


class VerifyWorker(QThread):
    """跑 mihomo -t 动态验证(可能耗时 45s)。

    信号:
        progress(int, str): 进度百分比 + 阶段文本
        finished_ok(VerifyResult): 验证结果(含 success/output/error)
        failed(str): 失败,携带 traceback 字符串

    注意:未找到 mihomo 不算异常,转 VerifyResult(success=False) 通过 finished_ok 传递。
    """

    progress = Signal(int, str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        config_path: Path,
        timeout: int = 45,
        geodata_dir: Path | None = None,
    ):
        super().__init__()
        self.config_path = config_path
        self.timeout = timeout
        self.geodata_dir = geodata_dir

    def run(self) -> None:
        """执行动态验证(在线程内运行)。"""
        try:
            self.progress.emit(10, "查找 mihomo 内核...")
            mihomo = find_mihomo()
            if not mihomo:
                # 未找到 mihomo 是业务结果(非异常),通过 finished_ok 传递
                self.finished_ok.emit(VerifyResult(
                    success=False,
                    output="",
                    error="mihomo 未安装或不在 PATH 中。请从 "
                          "https://github.com/MetaCubeX/mihomo/releases 下载并加入 PATH。",
                ))
                return

            geo_info = f"(geodata: {self.geodata_dir})" if self.geodata_dir else "(无 geodata,可能下载)"
            self.progress.emit(30, f"调用 mihomo -t {geo_info}(最多 {self.timeout}s)...")
            vres = verify(
                self.config_path,
                timeout=self.timeout,
                geodata_dir=self.geodata_dir,
            )
            self.progress.emit(95, "验证完成,处理结果...")
            self.finished_ok.emit(vres)
        except Exception:
            self.failed.emit(traceback.format_exc())
