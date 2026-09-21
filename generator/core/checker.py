"""35 红线静态校验器。

按 mihomo-spec.md 第十节红线汇总速查表实现。
输出 Report(items, score),items 含 level(🔴/🟠/🟡) + message + suggestion。

对应 mihomo-spec.md 第十节 35 条红线编号。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# 内置策略(R-4 检查时排除)
BUILT_IN = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}

# A: 必须真实 IP 的规则集(fakeipfilter)。此类集合一旦出现在 nameserver-policy,
# 就必须在 fake-ip-filter 成对出现,否则内核下发假 IP、DNS 分流失效。
MUST_REAL_IP_SETS: set[str] = {"fakeipfilter_cn", "fakeipfilter_!cn"}


def extract_ruleset_refs(entries) -> set[str]:
    """从 fake-ip-filter 条目 / nameserver-policy key 提取 `rule-set:<name>` 集合名。

    兼容形如 "rule-set:private" 与 "rule-set:cn_domain,private_domain" 两种写法。

    Args:
        entries: 字符串可迭代,如 dns.fake-ip-filter 列表

    Returns:
        set[str]: 引用的规则集名
    """
    out: set[str] = set()
    prefix = "rule-set:"
    for e in entries or []:
        s = str(e)
        if s.lower().startswith(prefix):
            names = s[len(prefix):].split(",")
            out.update(n.strip() for n in names if n.strip())
    return out


def parse_rule(rule: str) -> tuple[str, list[str], str]:
    """解析一条规则 → (kind, ruleset_refs, outlet)。

    P2:为逻辑规则(AND/OR/NOT,含嵌套括号)提供正确解析,避免朴素 split(",")
    把 `AND,((RULE-SET,...` 错拆(如 parts[1]==`((RULE-SET`)。

    Args:
        rule: 单条规则字符串,如 "RULE-SET,private,DIRECT" / "MATCH,DIRECT" /
            "AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT"

    Returns:
        (kind, ruleset_refs, outlet):
            kind: "RULE-SET" / "LOGICAL" / "OTHER"
            ruleset_refs: 规则内所有 `RULE-SET,<name>` 引用名(R-2 校验用)
            outlet: 出站目标(R-4 校验用)。RULE-SET 取第 3 段,逻辑/其它取整体末段
    """
    stripped = rule.strip()
    if stripped.startswith(("AND,", "OR,", "NOT,")):
        kind = "LOGICAL"
    elif stripped.startswith("RULE-SET,"):
        kind = "RULE-SET"
    else:
        kind = "OTHER"

    refs = re.findall(r"RULE-SET,\s*([^,) \t]+)", rule)
    parts = [p.strip() for p in rule.split(",")]
    if kind == "LOGICAL":
        # 逻辑规则:出口在末尾(条件被括号包裹,末段为动作)如 ...))))
        outlet = parts[-1] if parts else ""
    elif len(parts) >= 3:
        # 普通规则:出口为第 3 段(如 IP-CIDR,x,DIRECT,no-resolve → DIRECT)
        outlet = parts[2]
    else:
        # 非逻辑且不足 3 段(如 DOMAIN,x / MATCH,x / 裸 RULE-SET,x)无显式出口 → 不校验
        # (还原旧语义,避免把集合名/域名误当出口造成 R-4 误报)
        outlet = ""
    return kind, refs, outlet


def extract_dns_proxy_tags(*nameserver_lists) -> set[str]:
    """从 dns nameserver/fallback 条目提取代理解析标签。

    标签位于 '#' 与首个 '&' 之间(形如 `https://8.8.8.8/dns-query&ecs=...#默认代理`)。
    P1:校验这些标签都指向存在的策略组/内置策略,避免"标签过期→解析器被静默丢弃"。

    Args:
        *nameserver_lists: 若干 URL 列表(dns.nameserver / dns.fallback 等)

    Returns:
        set[str]: 出现过的标签集合(无标签则空集)
    """
    tags: set[str] = set()
    for lst in nameserver_lists:
        for entry in lst or []:
            s = str(entry)
            if "#" not in s:
                continue
            after = s[s.index("#") + 1:]
            tag = after.split("&", 1)[0].strip()
            if tag:
                tags.add(tag)
    return tags


@dataclass
class CheckItem:
    """校验项。

    Attributes:
        red_line: 红线编号(如 "D-1"/"R-3")
        level: 严重度('🔴' 硬红线 / '🟠' 软红线 / '🟡' 约定)
        message: 问题描述
        suggestion: 修复建议
    """

    red_line: str
    level: str
    message: str
    suggestion: str = ""


@dataclass
class Report:
    """校验报告。

    Attributes:
        items: 全部校验项
    """

    items: list[CheckItem] = field(default_factory=list)

    @property
    def errors(self) -> list[CheckItem]:
        """🔴 硬红线错误(必须拦截导出)。"""
        return [i for i in self.items if i.level == "🔴"]

    @property
    def warnings(self) -> list[CheckItem]:
        """🟠 软红线警告。"""
        return [i for i in self.items if i.level == "🟠"]

    @property
    def conventions(self) -> list[CheckItem]:
        """🟡 约定提示。"""
        return [i for i in self.items if i.level == "🟡"]

    @property
    def has_errors(self) -> bool:
        """是否存在硬红线错误。"""
        return len(self.errors) > 0

    @property
    def score(self) -> float:
        """适配度评分(0-10)。

        评分模型:
        - 有 🔴 错误 → 0 分(不可导出)
        - 基础 10 分,每个 🟠 扣 0.5,每个 🟡 扣 0.1
        - 最低 0 分
        """
        if self.has_errors:
            return 0.0
        base = 10.0
        base -= len(self.warnings) * 0.5
        base -= len(self.conventions) * 0.1
        return max(0.0, round(base, 1))


def check(config: dict) -> Report:
    """校验完整配置(35 红线)。

    Args:
        config: 完整配置 dict(7 模块组装后)

    Returns:
        Report: 校验报告
    """
    report = Report()
    dns_cfg = config.get("dns", {})
    sniffer_cfg = config.get("sniffer", {})
    proxies_list = config.get("proxies", [])
    groups_list = config.get("proxy-groups", [])
    rules_list = config.get("rules", [])
    providers_cfg = config.get("rule-providers", {})

    group_names = {g.get("name", "") for g in groups_list}
    provider_names = set(providers_cfg.keys())

    # === G 段:通用红线 ===

    # G-1: YAML 类型严格(port 整数、bool 不加引号)
    for proxy in proxies_list:
        port = proxy.get("port")
        if isinstance(port, str):
            report.items.append(CheckItem(
                "G-1", "🔴",
                f"节点 {proxy.get('name')} port 为字符串:{port}",
                "转为整数",
            ))

    # === D 段:DNS 红线 ===

    # D-1: enhanced-mode 必须显式给出合法值(fake-ip/redir-host 均可)
    # 修复 BUG-01: 原逻辑强制 fake-ip,使合法的 redir-host 被误判为硬红线。
    # 正确的红线语义是"字段必须显式且合法"(mihomo 默认 redir-host,防止未显式写入)。
    valid_modes_d1 = {"fake-ip", "redir-host"}
    if dns_cfg.get("enhanced-mode") not in valid_modes_d1:
        report.items.append(CheckItem(
            "D-1", "🔴",
            f"enhanced-mode 取值非法:{dns_cfg.get('enhanced-mode')}",
            "显式写出 fake-ip 或 redir-host",
        ))

    # D-2: respect-rules:true ⇒ proxy-server-nameserver 必填
    if dns_cfg.get("respect-rules") is True:
        if not dns_cfg.get("proxy-server-nameserver"):
            report.items.append(CheckItem(
                "D-2", "🔴",
                "respect-rules:true 需配 proxy-server-nameserver",
                "添加 proxy-server-nameserver(防鸡生蛋)",
            ))

    # D-4: fake-ip-filter-mode 取值(仅 fake-ip 模式有意义)
    # 修复 BUG-01: redir-host 模式下该字段无需存在,跳过校验,避免误报。
    valid_modes = {"blacklist", "whitelist", "rule"}
    if dns_cfg.get("enhanced-mode") == "fake-ip":
        if dns_cfg.get("fake-ip-filter-mode") not in valid_modes:
            report.items.append(CheckItem(
                "D-4", "🔴",
                f"fake-ip-filter-mode 取值非法:{dns_cfg.get('fake-ip-filter-mode')}",
                "可选 blacklist/whitelist/rule",
            ))

    # D-5: mode=rule 时 fake-ip-filter 必须以 MATCH 结尾
    if dns_cfg.get("fake-ip-filter-mode") == "rule":
        fif = dns_cfg.get("fake-ip-filter", [])
        if fif:
            last = fif[-1]
            if not (last.startswith("MATCH,fake-ip") or last.startswith("MATCH,real-ip")):
                report.items.append(CheckItem(
                    "D-5", "🔴",
                    f"fake-ip-filter 必须以 MATCH,fake-ip/real-ip 结尾,实际:{last}",
                    "末尾添加 MATCH,fake-ip",
                ))

    # D-6: nameserver-policy 的 rule-set:xxx 必须在 providers 中定义
    for key in dns_cfg.get("nameserver-policy", {}):
        if key.startswith("rule-set:"):
            sets = key.split(":", 1)[1].split(",")
            for s in sets:
                s = s.strip()
                if s not in provider_names:
                    report.items.append(CheckItem(
                        "D-6", "🔴",
                        f"nameserver-policy 引用 rule-set:{s} 未在 rule-providers 定义",
                        "补充对应的 rule-provider 或移除引用",
                    ))

    # D-9: nameserver/fallback 的代理标签(#TAG)必须指向存在的策略组/内置策略
    proxy_tags = extract_dns_proxy_tags(
        dns_cfg.get("nameserver"),
        dns_cfg.get("fallback"),
    )
    for tag in proxy_tags:
        if tag not in group_names and tag not in BUILT_IN:
            report.items.append(CheckItem(
                "D-9", "🔴",
                f"dns nameserver/fallback 代理标签 '#{tag}' 未在 proxy-groups/内置策略定义",
                "指向存在的策略组,或移除该标签",
            ))

    # D-10: fakeipfilter(必须真实 IP)规则集须与 fake-ip-filter 成对维护
    # A 方案:防止只改 nameserver-policy 却漏了 fake-ip-filter,导致假 IP 直接下发、分流失效。
    if dns_cfg.get("enhanced-mode") == "fake-ip":
        policy_sets: set[str] = set()
        for key in dns_cfg.get("nameserver-policy", {}):
            if key.startswith("rule-set:"):
                for s in key.split(":", 1)[1].split(","):
                    s = s.strip()
                    if s:
                        policy_sets.add(s)
        filter_sets = extract_ruleset_refs(dns_cfg.get("fake-ip-filter"))
        for name in MUST_REAL_IP_SETS & policy_sets:
            if name not in filter_sets:
                report.items.append(CheckItem(
                    "D-10", "🔴",
                    f"nameserver-policy 引用 rule-set:{name} 但 fake-ip-filter 未包含,"
                    "假 IP 直接下发导致 DNS 分流失效",
                    f"在 fake-ip-filter 同位置加入 rule-set:{name}(成对维护)",
                ))

    # === S 段:Sniffer 红线 ===

    # S-1: sniff 协议仅 HTTP/TLS/QUIC
    valid_protos = {"HTTP", "TLS", "QUIC"}
    actual_protos = set(sniffer_cfg.get("sniff", {}).keys())
    invalid = actual_protos - valid_protos
    if invalid:
        report.items.append(CheckItem(
            "S-1", "🔴",
            f"sniff 含非法协议:{invalid}",
            "仅支持 HTTP/TLS/QUIC",
        ))

    # S-4: fake-ip 模式必须开 sniffer
    if dns_cfg.get("enhanced-mode") == "fake-ip" and not sniffer_cfg.get("enable"):
        report.items.append(CheckItem(
            "S-4", "🟠",
            "fake-ip 模式必须开 sniffer",
            "设置 sniffer.enable: true",
        ))

    # === P 段:Proxies 红线 ===

    # P-2: 协议必填认证字段
    auth_fields = {
        "ss": ["password"], "vmess": ["uuid"], "vless": ["uuid"],
        "trojan": ["password"], "hysteria": ["auth-str"],
        "hysteria2": ["password"], "tuic": ["uuid", "password"],
    }
    for proxy in proxies_list:
        proto = proxy.get("type", "")
        name = proxy.get("name", "<未命名>")
        for field_name in auth_fields.get(proto, []):
            if not proxy.get(field_name):
                report.items.append(CheckItem(
                    "P-2", "🔴",
                    f"节点 {name}({proto}) 缺少必填字段:{field_name}",
                    f"补充 {field_name}",
                ))

    # P-4: 节点名唯一性
    names = [p.get("name", "") for p in proxies_list]
    seen: set[str] = set()
    for name in names:
        if name in seen:
            report.items.append(CheckItem(
                "P-4", "🔴",
                f"节点名重复:{name}",
                "归一化阶段应自动追加 (#2) 后缀",
            ))
        seen.add(name)

    # === PG 段:Proxy-Groups 红线 ===

    # PG-1: type 取值
    valid_types = {"select", "url-test", "fallback", "load-balance", "relay"}
    for g in groups_list:
        if g.get("type") not in valid_types:
            report.items.append(CheckItem(
                "PG-1", "🔴",
                f"组 {g.get('name')} type 非法:{g.get('type')}",
                "可选 select/url-test/fallback/load-balance/relay",
            ))

    # PG-2: 组成员引用一致性
    node_names = {p.get("name", "") for p in proxies_list}
    for g in groups_list:
        for proxy in g.get("proxies", []):
            if proxy not in node_names and proxy not in group_names and proxy not in BUILT_IN:
                report.items.append(CheckItem(
                    "PG-2", "🔴",
                    f"组 {g.get('name')} 引用不存在的节点/组:{proxy}",
                    "检查命名一致性",
                ))

    # PG-3: url-test/fallback 必填 url + interval
    for g in groups_list:
        if g.get("type") in ("url-test", "fallback"):
            if not g.get("url"):
                report.items.append(CheckItem(
                    "PG-3", "🔴", f"组 {g.get('name')} 缺 url", "添加 url"
                ))
            if not g.get("interval"):
                report.items.append(CheckItem(
                    "PG-3", "🔴", f"组 {g.get('name')} 缺 interval", "添加 interval"
                ))

    # PG-4: 空组检测
    for g in groups_list:
        if g.get("type") in ("url-test", "fallback") and not g.get("proxies"):
            report.items.append(CheckItem(
                "PG-4", "🟠", f"组 {g.get('name')} 为空组", "添加成员或删除"
            ))

    # === R 段:Rules 红线 ===

    # R-1: MATCH 必须最后且唯一
    match_count = sum(1 for r in rules_list if r.startswith("MATCH,"))
    if match_count != 1:
        report.items.append(CheckItem(
            "R-1", "🔴", f"MATCH 必须唯一,实际 {match_count} 条", "保留一条 MATCH"
        ))
    if rules_list and not rules_list[-1].startswith("MATCH,"):
        report.items.append(CheckItem(
            "R-1", "🔴", "MATCH 必须在最后", "调整规则顺序"
        ))

    # R-2: RULE-SET 引用必须在 providers 中定义(含逻辑规则内部引用)
    for rule in rules_list:
        _, refs, _ = parse_rule(rule)
        for name in refs:
            if name not in provider_names:
                report.items.append(CheckItem(
                    "R-2", "🔴",
                    f"RULE-SET,{name} 未在 rule-providers 定义",
                    "补充对应的 rule-provider",
                ))

    # R-3: IP-CIDR/GEOIP 必带 no-resolve
    for rule in rules_list:
        if rule.startswith(("IP-CIDR,", "GEOIP,", "IP-ASN,", "SRC-IP-CIDR,")):
            if "no-resolve" not in rule:
                report.items.append(CheckItem(
                    "R-3", "🔴", f"IP 类规则缺 no-resolve:{rule}", "添加 no-resolve"
                ))

    # R-4: 规则出口必须存在(P2:逻辑规则取整体末段,兼容 AND() 的 REJECT)
    for rule in rules_list:
        _, _, outlet = parse_rule(rule)
        if not outlet:
            continue
        if outlet not in BUILT_IN and outlet not in group_names:
            report.items.append(CheckItem(
                "R-4", "🔴", f"规则出口 '{outlet}' 不存在:{rule}", "检查组名"
            ))

    # R-5: reject 最前
    if rules_list and not rules_list[0].startswith("RULE-SET,reject"):
        report.items.append(CheckItem(
            "R-5", "🟠", "reject 规则应在最前", "调整顺序"
        ))

    # R-6: GEOIP 必带 no-resolve(R-3 已覆盖,这里单独标记)
    for rule in rules_list:
        if rule.startswith("GEOIP,") and "no-resolve" not in rule:
            report.items.append(CheckItem(
                "R-6", "🟠", f"GEOIP 缺 no-resolve:{rule}", "添加 no-resolve"
            ))

    # === RP 段:Rule-Providers 红线 ===

    # RP-1: type 取值
    valid_rp_types = {"http", "file", "inline"}
    for name, cfg in providers_cfg.items():
        if cfg.get("type") not in valid_rp_types:
            report.items.append(CheckItem(
                "RP-1", "🔴", f"规则集 {name} type 非法:{cfg.get('type')}", "可选 http/file/inline"
            ))

    # RP-2: behavior 取值
    valid_behaviors = {"domain", "ipcidr", "classical"}
    for name, cfg in providers_cfg.items():
        if cfg.get("behavior") not in valid_behaviors:
            report.items.append(CheckItem(
                "RP-2", "🔴", f"规则集 {name} behavior 非法:{cfg.get('behavior')}", "可选 domain/ipcidr/classical"
            ))

    # RP-3: format 取值
    valid_formats = {"yaml", "text", "mrs"}
    for name, cfg in providers_cfg.items():
        fmt = cfg.get("format")
        if fmt and fmt not in valid_formats:
            report.items.append(CheckItem(
                "RP-3", "🔴", f"规则集 {name} format 非法:{fmt}", "可选 yaml/text/mrs"
            ))

    # RP-4: format:mrs + behavior:classical 禁止
    for name, cfg in providers_cfg.items():
        if cfg.get("format") == "mrs" and cfg.get("behavior") == "classical":
            report.items.append(CheckItem(
                "RP-4", "🔴",
                f"规则集 {name} format:mrs + behavior:classical 禁止",
                "mrs 仅支持 domain/ipcidr",
            ))

    # RP-3b: http 提供者 format 必须与 url 扩展名一致(防 format/content 矛盾,承 BUG-02)
    #   规则: format==mrs 但 url 不以 .mrs 结尾 → 矛盾;http 恒式 text。
    for name, cfg in providers_cfg.items():
        url = str(cfg.get("url") or "")
        fmt = cfg.get("format")
        if cfg.get("type") == "http" and url:
            if fmt == "mrs" and not url.lower().endswith(".mrs"):
                report.items.append(CheckItem(
                    "RP-3b", "🔴",
                    f"规则集 {name} format:mrs 但 url 非 .mrs({url})——格式与内容矛盾",
                    "改用 text 或指向 .mrs 的 url",
                ))

    return report
