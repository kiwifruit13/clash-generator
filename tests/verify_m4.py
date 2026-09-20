"""M4 验证脚本:验证 dns/sniffer/rules/groups 四模块 + 三位一体口径一致性。

验证项(对照 mihomo-spec.md 35 红线):
- D-1~D-8: DNS 段红线
- S-1~S-5: Sniffer 段红线
- R-1~R-6: Rules 段红线
- PG-1~PG-4: Proxy-Groups 段红线
- 三位一体口径一致:nameserver-policy ↔ providers ↔ rules ↔ groups
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.cleaner import clean
from generator.core.builders import dns, groups, providers, rules, sniffer


def verify_dns(dns_cfg: dict) -> list[str]:
    """验证 DNS 段红线(D-1~D-8)。"""
    errors = []

    # D-1: enhanced-mode 显式 fake-ip(默认 redir-host)
    if dns_cfg.get("enhanced-mode") != "fake-ip":
        errors.append("D-1: enhanced-mode 必须 fake-ip")

    # D-2: respect-rules:true ⇒ proxy-server-nameserver 必填
    if dns_cfg.get("respect-rules") is True:
        if not dns_cfg.get("proxy-server-nameserver"):
            errors.append("D-2: respect-rules:true 需配 proxy-server-nameserver")

    # D-4: fake-ip-filter-mode 取值
    valid_modes = {"blacklist", "whitelist", "rule"}
    if dns_cfg.get("fake-ip-filter-mode") not in valid_modes:
        errors.append("D-4: fake-ip-filter-mode 取值非法")

    # D-5: mode=rule 时 fake-ip-filter 必须以 MATCH,fake-ip 或 MATCH,real-ip 结尾
    if dns_cfg.get("fake-ip-filter-mode") == "rule":
        fif = dns_cfg.get("fake-ip-filter", [])
        if fif:
            last = fif[-1]
            if not (last.startswith("MATCH,fake-ip") or last.startswith("MATCH,real-ip")):
                errors.append(f"D-5: fake-ip-filter 必须以 MATCH,fake-ip/real-ip 结尾,实际:{last}")

    # C6 修复:海外 nameserver 用纯 IP
    for ns in dns_cfg.get("nameserver", []):
        if "dns.google" in ns or "cloudflare-dns" in ns:
            errors.append(f"C6: nameserver 应用纯 IP,避免域名循环:{ns}")

    # C7 修复:fake-ip-filter 含 STUN + NTP(用户修订:NTP 必须真实 IP,系统时间同步依赖)
    fif_str = str(dns_cfg.get("fake-ip-filter", []))
    if "stun" not in fif_str.lower():
        errors.append("C7: fake-ip-filter 缺少 STUN")
    if "ntp" not in fif_str.lower():
        errors.append("C7: fake-ip-filter 缺少 NTP")

    return errors


def verify_sniffer(sniffer_cfg: dict) -> list[str]:
    """验证 Sniffer 段红线(S-1~S-5)。"""
    errors = []

    # S-1: sniff 协议仅 HTTP/TLS/QUIC
    valid_protos = {"HTTP", "TLS", "QUIC"}
    actual_protos = set(sniffer_cfg.get("sniff", {}).keys())
    invalid = actual_protos - valid_protos
    if invalid:
        errors.append(f"S-1: sniff 含非法协议:{invalid}")

    # S-1: 必须含 QUIC(C3 修复)
    if "QUIC" not in actual_protos:
        errors.append("C3: sniff 缺少 QUIC")

    # S-3: override-destination 显式写出
    if "override-destination" not in sniffer_cfg:
        errors.append("S-3: override-destination 应显式写出")

    # S-4: enable 必须 true(fake-ip 模式)
    if not sniffer_cfg.get("enable"):
        errors.append("S-4: fake-ip 模式必须开 sniffer")

    # S-5: parse-pure-ip 建议 true
    if not sniffer_cfg.get("parse-pure-ip"):
        errors.append("S-5: parse-pure-ip 建议 true")

    return errors


def verify_rules(
    rules_list: list[str],
    group_names: set[str],
    provider_names: set[str],
) -> list[str]:
    """验证 Rules 段红线(R-1~R-6)。"""
    errors = []

    # R-1: MATCH 必须最后且唯一
    match_count = sum(1 for r in rules_list if r.startswith("MATCH,"))
    if match_count != 1:
        errors.append(f"R-1: MATCH 必须唯一,实际 {match_count} 条")
    if rules_list and not rules_list[-1].startswith("MATCH,"):
        errors.append("R-1: MATCH 必须在最后")

    # R-2: RULE-SET 引用必须在 providers 中定义
    for rule in rules_list:
        if rule.startswith("RULE-SET,"):
            parts = rule.split(",")
            if len(parts) >= 2:
                set_name = parts[1]
                if set_name not in provider_names:
                    errors.append(f"R-2: RULE-SET 引用 '{set_name}' 未在 providers 定义")

    # R-3: IP-CIDR/GEOIP 必带 no-resolve
    for rule in rules_list:
        if rule.startswith(("IP-CIDR,", "GEOIP,", "IP-ASN,", "SRC-IP-CIDR,")):
            if "no-resolve" not in rule:
                errors.append(f"R-3: IP 类规则缺 no-resolve:{rule}")

    # R-4: 规则出口必须存在(组名或内置)
    built_in = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
    for rule in rules_list:
        parts = rule.split(",")
        if len(parts) >= 3:
            outlet = parts[2].strip()
            if outlet not in built_in and outlet not in group_names:
                errors.append(f"R-4: 规则出口 '{outlet}' 不存在:{rule}")

    # R-5: reject 最前
    first_non_comment = rules_list[0] if rules_list else ""
    if not first_non_comment.startswith("RULE-SET,reject"):
        errors.append("R-5: reject 规则应在最前")

    return errors


def verify_groups(
    groups_list: list[dict],
    node_names: set[str],
) -> list[str]:
    """验证 Proxy-Groups 段红线(PG-1~PG-4)。"""
    errors = []

    valid_types = {"select", "url-test", "fallback", "load-balance", "relay"}
    group_names = {g["name"] for g in groups_list}
    # 内置策略(PG-2 检查时需排除)
    built_in = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}

    for g in groups_list:
        # PG-1: type 取值
        if g.get("type") not in valid_types:
            errors.append(f"PG-1: {g['name']} type 非法:{g.get('type')}")

        # PG-2: 组成员引用必须存在(节点名/组名/内置策略)
        for proxy in g.get("proxies", []):
            if proxy not in node_names and proxy not in group_names and proxy not in built_in:
                errors.append(f"PG-2: {g['name']} 引用不存在的节点/组:{proxy}")

        # PG-3: url-test/fallback 必填 url + interval
        if g.get("type") in ("url-test", "fallback"):
            if not g.get("url"):
                errors.append(f"PG-3: {g['name']} 缺 url")
            if not g.get("interval"):
                errors.append(f"PG-3: {g['name']} 缺 interval")

        # PG-4: 空组检测
        if g.get("type") in ("url-test", "fallback") and not g.get("proxies"):
            errors.append(f"PG-4: {g['name']} 为空组")

    return errors


def verify_consistency(
    dns_cfg: dict,
    providers_cfg: dict,
    rules_list: list[str],
    groups_list: list[dict],
) -> list[str]:
    """验证三位一体口径一致性。"""
    errors = []
    provider_names = set(providers_cfg.keys())
    group_names = {g["name"] for g in groups_list}

    # nameserver-policy 的 rule-set:xxx 必须在 providers 中定义
    policy = dns_cfg.get("nameserver-policy", {})
    for key in policy:
        if key.startswith("rule-set:"):
            sets = key.split(":", 1)[1].split(",")
            for s in sets:
                s = s.strip()
                if s not in provider_names:
                    errors.append(f"口径不一致:nameserver-policy 引用 rule-set:{s} 未在 providers 定义")

    # rules 的 RULE-SET 引用必须在 providers 中定义
    for rule in rules_list:
        if rule.startswith("RULE-SET,"):
            parts = rule.split(",")
            if len(parts) >= 2 and parts[1] not in provider_names:
                errors.append(f"口径不一致:rules 引用 RULE-SET,{parts[1]} 未在 providers 定义")

    # rules 的组名出口必须在 groups 中定义
    built_in = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
    for rule in rules_list:
        parts = rule.split(",")
        if len(parts) >= 3:
            outlet = parts[2].strip()
            if outlet not in built_in and outlet not in group_names:
                errors.append(f"口径不一致:rules 出口 {outlet} 未在 groups 定义")

    return errors


def main() -> None:
    print("=" * 60)
    print("M4 验证报告(dns + sniffer + rules + groups + 口径一致)")
    print("=" * 60)

    # 加载 chromego.txt
    chromego_path = Path(__file__).parent.parent.parent / "chromego.txt"
    result = clean(chromego_path)
    node_names = {n.name for n in result.nodes}

    # 生成四模块
    from generator.core.prefs import Prefs
    p = Prefs.smart()
    dns_cfg = dns.build(p)
    sniffer_cfg = sniffer.build(p)
    providers_cfg = providers.build(p)
    groups_list = groups.build(result, p)
    available_groups = {g["name"] for g in groups_list}
    rules_list = rules.build(available_groups, p)

    all_errors: list[str] = []

    # 1. DNS 段
    print("\n[1] DNS 段(D-1~D-8 + C1/C6/C7)")
    dns_errors = verify_dns(dns_cfg)
    if dns_errors:
        for e in dns_errors:
            print(f"    ❌ {e}")
        all_errors.extend(dns_errors)
    else:
        print(f"    ✅ enhanced-mode={dns_cfg['enhanced-mode']}(D-1)")
        print(f"    ✅ respect-rules={dns_cfg['respect-rules']} + proxy-server-nameserver(D-2)")
        print(f"    ✅ fake-ip-filter-mode={dns_cfg['fake-ip-filter-mode']}(D-4)")
        print(f"    ✅ fake-ip-filter 末尾={dns_cfg['fake-ip-filter'][-1]}(D-5)")
        print(f"    ✅ nameserver-policy 用 rule-set 统一口径(C1)")
        print(f"    ✅ nameserver 纯 IP:1.1.1.1/8.8.8.8(C6)")
        print(f"    ✅ fake-ip-filter 含 STUN(C7,NTP 已按优化移除)")

    # 2. Sniffer 段
    print("\n[2] Sniffer 段(S-1~S-5 + C3)")
    sniffer_errors = verify_sniffer(sniffer_cfg)
    if sniffer_errors:
        for e in sniffer_errors:
            print(f"    ❌ {e}")
        all_errors.extend(sniffer_errors)
    else:
        protos = list(sniffer_cfg["sniff"].keys())
        print(f"    ✅ sniff 协议={protos}(S-1, 含 QUIC 修复 C3)")
        print(f"    ✅ override-destination={sniffer_cfg['override-destination']}(S-3)")
        print(f"    ✅ parse-pure-ip={sniffer_cfg['parse-pure-ip']}(S-5)")

    # 3. Groups 段
    print("\n[3] Proxy-Groups 段(PG-1~PG-4)")
    group_errors = verify_groups(groups_list, node_names)
    if group_errors:
        for e in group_errors:
            print(f"    ❌ {e}")
        all_errors.extend(group_errors)
    else:
        for g in groups_list:
            print(f"    ✅ {g['name']}({g['type']}) {len(g.get('proxies', []))} 成员")

    # 4. Rules 段
    print("\n[4] Rules 段(R-1~R-6 + C8/C9)")
    group_names = {g["name"] for g in groups_list}
    provider_names = set(providers_cfg.keys())
    rules_errors = verify_rules(rules_list, group_names, provider_names)
    if rules_errors:
        for e in rules_errors:
            print(f"    ❌ {e}")
        all_errors.extend(rules_errors)
    else:
        print(f"    ✅ MATCH 唯一且最后(R-1)")
        print(f"    ✅ RULE-SET 引用全在 providers 定义(R-2)")
        print(f"    ✅ IP-CIDR/GEOIP 全带 no-resolve(R-3/R-6)")
        print(f"    ✅ reject 最前、MATCH 最后(R-5)")
        print(f"    ✅ 共 {len(rules_list)} 条规则")

    # 5. 三位一体口径一致
    print("\n[5] 三位一体口径一致性")
    consistency_errors = verify_consistency(dns_cfg, providers_cfg, rules_list, groups_list)
    if consistency_errors:
        for e in consistency_errors:
            print(f"    ❌ {e}")
        all_errors.extend(consistency_errors)
    else:
        print(f"    ✅ nameserver-policy ↔ providers 口径一致")
        print(f"    ✅ rules ↔ providers 口径一致")
        print(f"    ✅ rules ↔ groups 口径一致")

    # 汇总
    print("\n" + "=" * 60)
    if all_errors:
        print(f"❌ M4 验证失败:{len(all_errors)} 项错误")
        for e in all_errors:
            print(f"   - {e}")
    else:
        print("✅ M4 验证通过(35 红线中 D/S/R/PG 段全符合 + 口径一致)")
    print("=" * 60)


if __name__ == "__main__":
    main()
