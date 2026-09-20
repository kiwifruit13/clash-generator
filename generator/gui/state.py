"""GUI 会话状态与流水线产物数据容器。

纯数据载体,无业务逻辑,供 workers.py 传递结果、main_window.py 持有会话状态。

对应 M7 计划 Step 1。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from generator.core.analyzer import GroupingSuggestion, NodeProfile
    from generator.core.checker import Report
    from generator.core.models import CleanResult
    from generator.core.prefs import Prefs


@dataclass
class PipelineResult:
    """流水线产物容器(供 PipelineWorker.finished_ok 信号传递)。

    封装 clean → analyze → assemble → check 全链路结果,
    避免 MainWindow 分别接收多个信号参数。

    Attributes:
        clean_result: 清洗结果(含节点列表 + 警告)
        profile: 节点画像(协议分布/IPv6/域名server 等)
        grouping: 分组可行性分析(safe/web/download 计数 + 策略建议)
        yaml_str: 组装后的完整 final.yaml 文本
        cross_errors: 跨段命名校验错误列表(空表示无错误)
        report: 35 红线静态校验报告(含评分)
    """

    clean_result: "CleanResult"
    profile: "NodeProfile"
    grouping: "GroupingSuggestion"
    yaml_str: str
    cross_errors: list[str]
    report: "Report"


@dataclass
class SessionState:
    """主窗会话状态(贯穿用户操作全流程)。

    Attributes:
        input_path: 用户选择的 proxies 文件路径;None 表示未选择
        prefs: 用户偏好(进阶选项);None 表示智能模式
        yaml_str: 最近一次生成的 final.yaml 文本;None 表示未生成
        report: 最近一次静态校验报告;None 表示未校验
        tmp_verify_path: 动态验证用的临时 yaml 文件路径;None 表示无临时文件
            (verify() 接收文件路径,需把 yaml_str 写入临时文件)
        geodata_dir: 动态验证用的 geodata 目录(可选);None 表示未提供
    """

    input_path: Optional[Path] = None
    prefs: Optional["Prefs"] = None
    yaml_str: Optional[str] = None
    report: Optional["Report"] = None
    tmp_verify_path: Optional[Path] = None
    geodata_dir: Optional[Path] = None

    def has_yaml(self) -> bool:
        """是否已生成可导出/可验证的 yaml。"""
        return self.yaml_str is not None and len(self.yaml_str) > 0

    def reset(self) -> None:
        """重置会话状态(切换输入文件时调用)。"""
        self.yaml_str = None
        self.report = None
        # 清理临时文件
        if self.tmp_verify_path is not None:
            try:
                self.tmp_verify_path.unlink(missing_ok=True)
            except OSError:
                pass
            self.tmp_verify_path = None
