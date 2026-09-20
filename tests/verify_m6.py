"""M6 验证脚本:调用 mihomo -t -f 进行动态验证。

验证项:
- mihomo 可执行文件是否在 PATH
- final.yaml 是否通过 mihomo -t 语法+配置测试
- 错误信息提取(如有)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.verifier import find_mihomo, verify


def main() -> None:
    print("=" * 60)
    print("M6 动态验证(mihomo -t 实测)")
    print("=" * 60)

    config_path = Path(__file__).parent.parent / "final.yaml"

    # 1. 查找 mihomo
    print("\n[1] 查找 mihomo 可执行文件")
    mihomo = find_mihomo()
    if not mihomo:
        print("    ❌ 未找到 mihomo/clash-meta(不在 PATH 中)")
        print("       请从 https://github.com/MetaCubeX/mihomo/releases 下载并加入 PATH")
        return
    print(f"    ✅ 找到: {mihomo}")

    # 2. 检查配置文件
    print(f"\n[2] 配置文件")
    if not config_path.exists():
        print(f"    ❌ 文件不存在: {config_path}")
        return
    size_kb = config_path.stat().st_size / 1024
    print(f"    ✅ {config_path} ({size_kb:.0f} KB)")

    # 3. 动态验证
    print("\n[3] 调用 mihomo -t -f (最多30s)...")
    result = verify(config_path, timeout=30)

    print(f"\n[4] 结果")
    if result.success:
        print("    ✅ mihomo -t 测试通过!配置语法和引用均正确")
        if result.output:
            print(f"\n    输出(截取末尾20行):")
            lines = [l for l in result.output.splitlines() if l.strip()][-20:]
            for line in lines:
                print(f"      {line}")
    else:
        print("    ❌ mihomo -t 测试失败")
        if result.error:
            print(f"\n    错误信息:")
            for line in result.error.splitlines():
                print(f"      ❌ {line}")
        if result.output:
            print(f"\n    完整输出(截取末尾30行):")
            lines = [l for l in result.output.splitlines() if l.strip()][-30:]
            for line in lines:
                print(f"      | {line}")

    # 汇总
    print("\n" + "=" * 60)
    if result.success:
        print("✅ M6 动态验证通过(mihomo 实测配置合法)")
    else:
        print("❌ M6 动态验证失败(见上方错误)")
    print("=" * 60)


if __name__ == "__main__":
    main()
