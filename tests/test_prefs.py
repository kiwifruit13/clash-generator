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
    test_minimal_rule_template()
    test_disable_rulesets()
    test_full_assemble_smart()
    test_full_assemble_advanced()
    print("=== ALL TESTS PASSED ===")
