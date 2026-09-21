"""prefs 贯穿 pipeline 的冒烟测试。

验证:
1. 所有模块导入正常
2. Prefs.smart() 默认值 = 智能模式
3. 各 builder 接受 prefs 参数
4. assemble(input_path, prefs=None) 智能模式行为不变
5. assemble(input_path, Prefs.smart()) 显式智能模式
6. 进阶模式:enhanced_mode=redir-host 时 fake-ip-filter 不生成
"""

import sys
from pathlib import Path

# 确保项目根在 path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from generator.core.prefs import Prefs
from generator.core.builders import basic, dns, sniffer, groups, providers, rules
from generator.core.assembler import assemble


def test_imports():
    """1. 导入测试"""
    print("=== 1. 导入测试 ===")
    print("  prefs/builders/assembler 全部导入成功")
    print()


def test_smart_defaults():
    """2. 智能模式默认值"""
    print("=== 2. 智能模式默认值 ===")
    p = Prefs.smart()
    assert p.advanced_mode is False
    assert p.enhanced_mode == "fake-ip"
    assert p.respect_rules is True
    assert p.mixed_port == 7890
    assert p.allow_lan is True
    assert p.ipv6 == "auto"
    assert p.grouping_strategy == "auto"
    assert p.rule_template == "standard"
    assert p.ruleset_source == "loyalsoldier"
    assert p.tun_enable is False
    assert p.enable_apple is True
    # 000.txt 适配默认值
    assert p.dns_cache_algorithm == "arc"
    assert p.fake_ip_ttl == 1
    assert p.dns_ecs is True
    assert p.dns_disable_qtype_65 is True
    assert p.dns_use_fallback_filter is True
    print("  所有默认值符合预期")
    print()


def test_builders_with_smart_prefs():
    """3. builder 接受 prefs"""
    print("=== 3. builder 接受智能模式 prefs ===")
    p = Prefs.smart()
    b = basic.build(p)
    d = dns.build(p)
    s = sniffer.build(p)
    pr = providers.build(p)
    r = rules.build(set(), p)  # 空集合=所有组都存在(兼容旧行为)

    assert b["mixed-port"] == 7890
    assert b["allow-lan"] is True
    assert d["enhanced-mode"] == "fake-ip"
    assert d["respect-rules"] is True
    assert "fake-ip-filter" in d  # fake-ip 模式应有 filter
    # 000.txt 适配:dns 段默认输出
    assert d["cache-algorithm"] == "arc"
    assert d["fake-ip-ttl"] == 1
    assert "fallback" in d and "fallback-filter" in d
    assert all("#disable-qtype-65=true" in u for u in d["direct-nameserver"])
    assert any("ecs=" in u for u in d["nameserver"])
    assert s["enable"] is True
    assert len(pr) == 7  # 7 个规则集
    assert len(r) > 15  # 标准模板规则数

    print(f"  basic: port={b['mixed-port']}, allow-lan={b['allow-lan']}")
    print(f"  dns: mode={d['enhanced-mode']}, has_filter={'fake-ip-filter' in d}")
    print(f"  sniffer: enable={s['enable']}")
    print(f"  providers: {len(pr)} sets")
    print(f"  rules: {len(r)} rules")
    print()


def test_redir_host_mode():
    """4. redir-host 模式:fake-ip-filter 不生成"""
    print("=== 4. redir-host 模式 ===")
    p = Prefs(advanced_mode=True, enhanced_mode="redir-host")
    d = dns.build(p)
    assert d["enhanced-mode"] == "redir-host"
    assert "fake-ip-filter" not in d  # redir-host 不需要 filter
    assert "fake-ip-filter-mode" not in d
    print(f"  dns: mode={d['enhanced-mode']}, has_filter={'fake-ip-filter' in d}")
    print("  redir-host 模式正确跳过 fake-ip-filter")
    print()


def test_000_dns_toggles():
    """5b. 000.txt 适配:dns 可调项开关(关掉时不带对应参数)"""
    print("=== 5b. 000.txt dns 可调项 ===")
    p_off = Prefs(
        advanced_mode=True,
        dns_cache_algorithm="lru",
        dns_ecs=False,
        dns_disable_qtype_65=False,
        dns_use_fallback_filter=False,
    )
    d = dns.build(p_off)
    assert d["cache-algorithm"] == "lru"
    assert "fake-ip-ttl" in d and d["fake-ip-ttl"] == 1
    assert "fallback" not in d and "fallback-filter" not in d
    assert all("#disable-qtype-65=true" not in u for u in d["direct-nameserver"])
    assert all("ecs=" not in u for u in d["nameserver"])
    print("  关闭后 disable-qtype-65/ecs/fallback 均正确省略")

    p_err = None
    try:
        Prefs(dns_cache_algorithm="bogus")
    except ValueError as e:
        p_err = e
    assert p_err is not None, "非法 dns_cache_algorithm 应抛 ValueError"
    assert "dns_cache_algorithm" in str(p_err)
    print("  非法 dns_cache_algorithm 抛 ValueError")
    print()


def test_p1_dns_proxy_tag():
    """P1: #默认代理 标签(默认空=不生成;设置后打到 nameserver/fallback)"""
    print("=== P1. dns 代理标签 ===")
    p_default = Prefs.smart()
    d = dns.build(p_default)
    assert all("#" not in u for u in d["nameserver"])
    assert all("#" not in u for u in d["fallback"])

    p_tag = Prefs(advanced_mode=True, dns_proxy_tag="默认代理")
    d = dns.build(p_tag)
    assert all(u.endswith("#默认代理") for u in d["nameserver"])
    assert all(u.endswith("#默认代理") for u in d["fallback"])
    print("  默认不生成;设置后 nameserver/fallback 均带 #默认代理")
    print()


def test_p2_quic_reject_rule():
    """P2: AND() QUIC 拦截(默认关;开启后插在 reject 之后,R-5 不回归)"""
    print("=== P2. AND() QUIC 拦截 ===")
    p_off = Prefs.smart()
    r_off = rules.build(set(), p_off)
    assert not any(x.startswith("AND,") for x in r_off)

    p_on = Prefs(advanced_mode=True, enable_quic_reject=True)
    r_on = rules.build(set(), p_on)
    and_rules = [x for x in r_on if x.startswith("AND,")]
    assert len(and_rules) == 1, and_rules
    assert "REJECT" in and_rules[0]
    # R-5: reject 仍为第一条(AND 插在其后)
    assert r_on[0].startswith("RULE-SET,reject,")
    assert r_on[1].startswith("AND,")
    print("  开启后 AND 规则位于 reject 之后;关闭时无 AND 规则")
    print()


def test_b_fakeip_filter_pairing():
    """B: fakeipfilter 源(默认关;开启后单点成对注入 fake-ip-filter + nameserver-policy)"""
    print("=== B. fakeipfilter 成对注入 ===")
    p_off = Prefs.smart()
    pr_off = providers.build(p_off)
    assert "fakeipfilter_cn" not in pr_off
    assert "fakeipfilter_!cn" not in pr_off

    p_on = Prefs(advanced_mode=True, enable_fakeip_filter=True)
    pr_on = providers.build(p_on)
    assert "fakeipfilter_cn" in pr_on and pr_on["fakeipfilter_cn"]["format"] == "text"
    assert "fakeipfilter_!cn" in pr_on

    d = dns.build(p_on)  # fake-ip 模式
    fif = d.get("fake-ip-filter", [])
    assert any("fakeipfilter_cn" in e for e in fif)
    assert any("fakeipfilter_!cn" in e for e in fif)
    pol = d.get("nameserver-policy", {})
    assert "rule-set:fakeipfilter_cn" in pol
    assert "rule-set:fakeipfilter_!cn" in pol
    print("  开启后 providers 有 2 集,且同进 fake-ip-filter + nameserver-policy")
    print()


def test_minimal_rule_template():
    """5. minimal 模板:跳过 AI + 流媒体规则"""
    print("=== 5. minimal 规则模板 ===")
    p_smart = Prefs.smart()
    p_minimal = Prefs(advanced_mode=True, rule_template="minimal")

    r_smart = rules.build(set(), p_smart)
    r_minimal = rules.build(set(), p_minimal)

    print(f"  standard: {len(r_smart)} rules")
    print(f"  minimal:  {len(r_minimal)} rules")
    assert len(r_minimal) < len(r_smart)

    # minimal 不应包含 AI 规则
    ai_rules = [r for r in r_minimal if "openai" in r or "chatgpt" in r]
    assert len(ai_rules) == 0, f"minimal 不应含 AI 规则: {ai_rules}"
    print("  minimal 正确跳过 AI + 流媒体规则")
    print()


def test_disable_rulesets():
    """6. 关闭规则集:providers + rules 同步跳过"""
    print("=== 6. 关闭规则集 ===")
    p = Prefs(advanced_mode=True, enable_apple=False, enable_icloud=False, enable_google=False)
    pr = providers.build(p)
    r = rules.build(set(), p)

    assert "apple" not in pr
    assert "icloud" not in pr
    assert "google" not in pr
    apple_rules = [x for x in r if "apple" in x.lower() or "icloud" in x.lower() or "google" in x.lower()]
    # google 规则可能有 DOMAIN-SUFFIX,gemini.google.com 但不应有 RULE-SET,google
    ruleset_google = [x for x in r if x.startswith("RULE-SET,google")]
    assert len(ruleset_google) == 0

    print(f"  providers: {list(pr.keys())}")
    print(f"  rules: 无 RULE-SET,apple/icloud/google")
    print()


def test_full_assemble_smart():
    """7. 完整 assemble(智能模式)"""
    print("=== 7. 完整 assemble(智能模式) ===")
    input_path = project_root / "chromego.txt"
    if not input_path.exists():
        print(f"  跳过: {input_path} 不存在")
        print()
        return

    yaml_str, errors = assemble(input_path, prefs=None)  # None=智能模式
    assert len(yaml_str) > 0
    print(f"  yaml 长度: {len(yaml_str)} 字符")
    print(f"  跨段错误: {len(errors)} 个")
    for e in errors:
        print(f"    - {e}")
    print()


def test_full_assemble_advanced():
    """8. 完整 assemble(进阶模式:TUN + redir-host)"""
    print("=== 8. 完整 assemble(进阶模式) ===")
    input_path = project_root / "chromego.txt"
    if not input_path.exists():
        print(f"  跳过: {input_path} 不存在")
        print()
        return

    p = Prefs(
        advanced_mode=True,
        enhanced_mode="redir-host",
        tun_enable=True,
        grouping_strategy="minimal",
    )
    yaml_str, errors = assemble(input_path, prefs=p)
    assert len(yaml_str) > 0

    # 验证 TUN 段存在
    assert "tun:" in yaml_str
    # 验证 minimal 分组(无子组)
    assert "🔒 安全专线" not in yaml_str or "🌐 网页浏览" not in yaml_str

    print(f"  yaml 长度: {len(yaml_str)} 字符")
    print(f"  跨段错误: {len(errors)} 个")
    print(f"  TUN 段: {'存在' if 'tun:' in yaml_str else '缺失'}")
    print(f"  minimal 分组: {'是' if '🔒' not in yaml_str else '否'}")
    for e in errors:
        print(f"    - {e}")
    print()


if __name__ == "__main__":
    test_imports()
    test_smart_defaults()
    test_builders_with_smart_prefs()
    test_redir_host_mode()
    test_000_dns_toggles()
    test_p1_dns_proxy_tag()
    test_p2_quic_reject_rule()
    test_b_fakeip_filter_pairing()
    test_minimal_rule_template()
    test_disable_rulesets()
    test_full_assemble_smart()
    test_full_assemble_advanced()
    print("=== ALL TESTS PASSED ===")
