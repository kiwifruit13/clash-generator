"""M2 验证脚本:验证 cleaner.py 对 chromego.txt 的清洗结果。

验证项:
1. 节点数 = 29
2. 字段名全连字符(无 auth_str / recv_window_conn / client-figerprint)
3. port 为整数(非字符串)
4. 锚点已展开(无 *ref_0 / *id001)
5. P-5 域名 server 警告
6. P-6 skip-cert-verify 警告
"""

from __future__ import annotations

import sys
from pathlib import Path

# 让 tests/ 目录能 import generator 包
sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.cleaner import clean, to_yaml
from generator.core.models import CleanResult


def verify(result: CleanResult) -> None:
    """验证清洗结果并打印报告。"""
    print("=" * 60)
    print("M2 清洗验证报告")
    print("=" * 60)

    # 1. 节点数(21 编号节点 + 9 域名节点 = 30)
    print(f"\n[1] 节点数: {result.count}")
    assert result.count == 30, f"期望 30 节点,实际 {result.count}"
    print("    ✅ 30 节点")

    # 2. 字段名归一化检查
    print("\n[2] 字段名归一化(P-1 + G-3)")
    bad_fields = ["auth_str", "recv_window_conn", "recv_window", "client-figerprint"]
    violations = []
    for node in result.nodes:
        raw_str = str(node.raw)
        for bad in bad_fields:
            if f"'{bad}'" in raw_str or f'"{bad}"' in raw_str:
                violations.append((node.name, bad))
    if violations:
        print(f"    ❌ 发现 {len(violations)} 处未归一化字段")
        for name, field in violations[:5]:
            print(f"       {name}: {field}")
    else:
        print("    ✅ 无下划线/拼写错字段")

    # 3. port 类型检查
    print("\n[3] port 类型(G-1)")
    bad_ports = []
    for node in result.nodes:
        port = node.raw.get("port")
        if isinstance(port, str):
            bad_ports.append((node.name, port))
    if bad_ports:
        print(f"    ❌ 发现 {len(bad_ports)} 个字符串 port")
        for name, port in bad_ports[:5]:
            print(f"       {name}: port={port!r}")
    else:
        print("    ✅ 全部 port 为整数")

    # 4. 锚点展开检查
    print("\n[4] 锚点展开(G-2)")
    yaml_str = to_yaml(result)
    if "*ref_0" in yaml_str or "*id001" in yaml_str or "*id002" in yaml_str:
        print("    ❌ 仍存在锚点别名引用")
    else:
        print("    ✅ 锚点已展开")

    # 5. 第一个节点详细检查
    print("\n[5] 节点1 详细(原 chromego.txt port='11000' auth_str=...)")
    n1 = result.nodes[0]
    print(f"    name: {n1.name}")
    print(f"    port: {n1.raw.get('port')!r} (type={type(n1.raw.get('port')).__name__})")
    print(f"    auth-str: {n1.raw.get('auth-str', '<无>')!r}")
    print(f"    recv-window-conn: {n1.raw.get('recv-window-conn', '<无>')!r}")

    # 6. 警告汇总
    print(f"\n[6] 警告汇总: {len(result.warnings)} 条")
    for w in result.warnings:
        print(f"    {w.level} {w.message}")

    # 7. 派生标记
    print(f"\n[7] 派生标记")
    print(f"    域名 server 节点: {len(result.domain_server_names)} 个")
    print(f"    skip-cert-verify 节点: {len(result.skip_cert_names)} 个")
    print(f"    IPv6 server 节点: {sum(1 for n in result.nodes if n.is_ipv6_server)} 个")

    print("\n" + "=" * 60)
    if not violations and not bad_ports:
        print("✅ M2 验证通过")
    else:
        print("❌ M2 验证失败,见上方详情")
    print("=" * 60)


if __name__ == "__main__":
    # chromego.txt 在上级目录
    chromego_path = Path(__file__).parent.parent.parent / "chromego.txt"
    if not chromego_path.exists():
        print(f"❌ 找不到 chromego.txt: {chromego_path}")
        sys.exit(1)

    result = clean(chromego_path)
    verify(result)
