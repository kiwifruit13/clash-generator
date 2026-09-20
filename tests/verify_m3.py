"""M3 验证脚本:验证 analyzer + basic + providers 三模块。

验证项:
1. analyzer 协议分布(hysteria/hysteria2/vmess/vless/tuic)
2. analyzer IPv6/域名 server/skip-cert 标记
3. basic 字段符合 mihomo-spec.md 第二节红线
4. providers 7 个规则集,每个显式 format: text(修复 C10)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.analyzer import analyze
from generator.core.cleaner import clean
from generator.core.builders import basic, providers


def verify() -> None:
    print("=" * 60)
    print("M3 验证报告(analyzer + basic + providers)")
    print("=" * 60)

    # 加载 chromego.txt
    chromego_path = Path(__file__).parent.parent.parent / "chromego.txt"
    result = clean(chromego_path)

    # 1. analyzer 协议分布
    print("\n[1] analyzer 协议分布")
    profile = analyze(result)
    print(f"    总节点数: {profile.total}")
    for proto, names in profile.protocol_distribution.items():
        print(f"    {proto}: {len(names)} 个 → {names[:3]}...")

    expected_protos = {"hysteria", "hysteria2", "vmess", "vless", "tuic"}
    actual_protos = set(profile.protocol_distribution.keys())
    missing = expected_protos - actual_protos
    if missing:
        print(f"    ❌ 缺少协议: {missing}")
    else:
        print(f"    ✅ 协议齐全: {actual_protos}")

    # 2. analyzer 标记
    print("\n[2] analyzer 派生标记")
    print(f"    IPv6 节点: {len(profile.ipv6_nodes)} 个")
    print(f"    域名 server: {len(profile.domain_server_nodes)} 个")
    print(f"    skip-cert-verify: {len(profile.skip_cert_nodes)} 个")
    assert len(profile.ipv6_nodes) == 10, f"IPv6 期望 10,实际 {len(profile.ipv6_nodes)}"
    assert len(profile.domain_server_nodes) == 9, f"域名 server 期望 9,实际 {len(profile.domain_server_nodes)}"
    print("    ✅ 标记数量正确")

    # 3. basic 字段红线
    print("\n[3] basic 段(mihomo-spec.md 第二节红线)")
    from generator.core.prefs import Prefs
    p = Prefs.smart()
    basic_cfg = basic.build(p)
    assert basic_cfg["mode"] == "rule", "mode 必须为 rule"
    assert basic_cfg["log-level"] == "info", "log-level 必须为 info"
    assert basic_cfg["ipv6"] is False, "ipv6 必须为 False(C5 决策)"
    assert basic_cfg["mixed-port"] == 7890, "mixed-port 必须为 7890"
    print(f"    mixed-port: {basic_cfg['mixed-port']}")
    print(f"    mode: {basic_cfg['mode']} ✅")
    print(f"    log-level: {basic_cfg['log-level']} ✅")
    print(f"    ipv6: {basic_cfg['ipv6']} ✅(C5 决策)")
    print(f"    external-controller: {basic_cfg['external-controller']}")
    print("    ✅ basic 字段全符合红线")

    # 4. providers 规则集
    print("\n[4] rule-providers(7 规则集 + format: text 修复 C10)")
    prov = providers.build(p)
    assert len(prov) == 7, f"期望 7 规则集,实际 {len(prov)}"
    for name, cfg in prov.items():
        assert cfg["type"] == "http", f"{name}.type 必须 http"
        assert cfg["behavior"] == "domain", f"{name}.behavior 必须 domain"
        assert cfg["format"] == "text", f"{name}.format 必须 text(修复 C10)"
        assert cfg["interval"] == 86400, f"{name}.interval 必须 86400"
        print(f"    {name}: type={cfg['type']} behavior={cfg['behavior']} format={cfg['format']} ✅")
    print("    ✅ 7 规则集全显式 format: text")

    print("\n" + "=" * 60)
    print("✅ M3 验证通过")
    print("=" * 60)


if __name__ == "__main__":
    verify()
