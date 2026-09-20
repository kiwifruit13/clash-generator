"""M5 验证脚本:验证 assembler + checker。

验证项:
1. assemble() 输出 final.yaml(7 段齐全)
2. 跨段命名校验无错误
3. checker.check() 报告 0 项 🔴
4. 适配度评分 ≥ 9.0
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.assembler import assemble
from generator.core.checker import check


def main() -> None:
    print("=" * 60)
    print("M5 验证报告(assembler + checker 35 红线)")
    print("=" * 60)

    chromego_path = Path(__file__).parent.parent.parent / "chromego.txt"
    output_path = Path(__file__).parent.parent / "final.yaml"

    # 1. 组装
    print("\n[1] assemble() 组装 final.yaml")
    yaml_str, cross_errors = assemble(chromego_path)
    print(f"    YAML 长度: {len(yaml_str)} 字符")

    # 写入文件
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(yaml_str)
    print(f"    已写入: {output_path}")

    # 2. 跨段命名校验
    print("\n[2] 跨段命名一致性校验")
    if cross_errors:
        print(f"    ❌ {len(cross_errors)} 项错误:")
        for e in cross_errors:
            print(f"       - {e}")
    else:
        print("    ✅ 无跨段命名错误")

    # 3. 7 段齐全检查
    print("\n[3] 7 段齐全检查")
    config = yaml.safe_load(yaml_str)
    required_sections = [
        "mixed-port", "mode", "log-level",  # basic 顶层
        "dns", "sniffer", "proxies", "proxy-groups", "rules", "rule-providers",
    ]
    missing = [s for s in required_sections if s not in config]
    if missing:
        print(f"    ❌ 缺少段:{missing}")
    else:
        print(f"    ✅ 7 段齐全(basic + dns + sniffer + proxies + groups + rules + providers)")
        print(f"    ✅ 节点数:{len(config['proxies'])}")
        print(f"    ✅ 策略组数:{len(config['proxy-groups'])}")
        print(f"    ✅ 规则数:{len(config['rules'])}")
        print(f"    ✅ 规则集数:{len(config['rule-providers'])}")

    # 4. 35 红线静态校验
    print("\n[4] checker.check() 35 红线静态校验")
    report = check(config)
    print(f"    🔴 硬红线错误:{len(report.errors)} 项")
    for item in report.errors:
        print(f"       {item.red_line} {item.message}")
    print(f"    🟠 软红线警告:{len(report.warnings)} 项")
    for item in report.warnings:
        print(f"       {item.red_line} {item.message}")
    print(f"    🟡 约定提示:{len(report.conventions)} 项")
    for item in report.conventions:
        print(f"       {item.red_line} {item.message}")

    # 5. 适配度评分
    print(f"\n[5] 适配度评分")
    print(f"    评分:{report.score}/10")
    if report.has_errors:
        print(f"    ❌ 存在 🔴 硬红线错误,不可导出")
    elif report.score >= 9.0:
        print(f"    ✅ 达到 9/10 目标")
    else:
        print(f"    ⚠️ 评分 {report.score} < 9.0,需优化")

    # 汇总
    print("\n" + "=" * 60)
    if not report.has_errors and not cross_errors and not missing:
        if report.score >= 9.0:
            print(f"✅ M5 验证通过(0 项 🔴,适配度 {report.score}/10)")
        else:
            print(f"⚠️ M5 部分通过(0 项 🔴,但评分 {report.score} < 9.0)")
    else:
        print(f"❌ M5 验证失败")
    print("=" * 60)


if __name__ == "__main__":
    main()
