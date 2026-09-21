"""Clash/Mihomo 配置生成器入口。

M7:默认启动 GUI;--cli 走 M8 端到端 CLI 流程;--version 查版本。

用法:
    python main.py              # 启动 GUI(默认)
    python main.py --cli        # CLI 模式(等价 verify_m8.py)
    python main.py --cli --input 333.txt --output final_333.yaml
    python main.py --version    # 查看版本
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

__version__ = "1.1.0"


def main() -> int:
    """主入口。

    Returns:
        0 表示成功,非 0 表示错误。
    """
    if "--version" in sys.argv:
        print(f"clash-generator {__version__}")
        return 0

    if "--cli" in sys.argv:
        # CLI 模式:运行 verify_m8.py(移除 --cli,保留 --input/--output 等参数)
        cli_args = [a for a in sys.argv[1:] if a != "--cli"]
        sys.argv = [sys.argv[0]] + cli_args
        verify_m8_path = str(Path(__file__).parent / "tests" / "verify_m8.py")
        runpy.run_path(verify_m8_path, run_name="__main__")
        return 0

    # 默认:启动 GUI
    from generator.gui.app import run
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
