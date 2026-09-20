"""rules 段生成器(M4 三位一体之四)。

对应 plan.md Step 5 + mihomo-spec.md 第八节 R-1~R-6 红线。

关键改进(对照 ChromeGO.yaml):
- C8 修复:规则去重(每个 RULE-SET 只引用一次)
- C9 修复:域名规则前置(GEOIP 兜底)
- R-3/R-6: IP-CIDR/GEOIP 必带 no-resolve
- R-5: reject 最前,MATCH 最后
- 口径统一:RULE-SET 引用与 providers 段一致

P0-2 改进:规则出口优先级链(替代静态 fallback)。
每条规则定义出口优先级链,运行时按链解析,语义更清晰、更健壮。
"""

from __future__ import annotations

from ..prefs import Prefs
from .groups import GROUP_AUTO, GROUP_DOWNLOAD, GROUP_SAFE, GROUP_WEB

# 内置策略(R-4 检查时排除)
BUILT_IN = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}


# 规则出口优先级链定义
# 每个语义类别对应一个优先级链,运行时按顺序找第一个存在的组
# 好处:规则语义与组存在性解耦,组不存在时自动降级到次优选择
RULE_OUTLET_CHAINS: dict[str, list[str]] = {
    # AI 专线:优先安全专线(reality+tuic 抗风控),不存在则用自动优选
    "ai":         [GROUP_SAFE, GROUP_AUTO],
    # 流媒体:优先网页浏览(CF CDN),不存在则用自动优选
    "streaming":  [GROUP_WEB, GROUP_AUTO],
    # Google/YouTube:固定自动优选(CF CDN 易被 YouTube 封锁,C2 修复)
    "google":     [GROUP_AUTO],
    # 代理流量:固定自动优选
    "proxy":      [GROUP_AUTO],
    # 国内直连:固定 DIRECT
    "domestic":   ["DIRECT"],
    # 广告拦截:固定 REJECT
    "ad":         ["REJECT"],
    # 私有网络:固定 DIRECT
    "private":    ["DIRECT"],
    # Apple/iCloud:固定 DIRECT
    "apple":      ["DIRECT"],
    # 兜底:固定自动优选
    "fallback":   [GROUP_AUTO],
}


def _resolve_outlet(chain_name: str, available_groups: set[str] | None = None) -> str:
    """按优先级链解析实际出口。

    按 RULE_OUTLET_CHAINS[chain_name] 的顺序,找第一个存在的组。
    若链中所有组都不存在,则 fallback 到 GROUP_AUTO。

    Args:
        chain_name: 语义类别名(如 "ai"/"streaming"/"google")
        available_groups: 实际存在的策略组名集合(None 表示所有组都存在)

    Returns:
        实际出口组名
    """
    chain = RULE_OUTLET_CHAINS.get(chain_name, [GROUP_AUTO])

    # None 表示所有自定义组都存在(向后兼容)
    if available_groups is None:
        return chain[0]

    for outlet in chain:
        if outlet in available_groups or outlet in BUILT_IN:
            return outlet

    # 终极 fallback:链中所有组都不存在(理论上不会发生,GROUP_AUTO 始终存在)
    return GROUP_AUTO


def build(
    available_groups: set[str],
    prefs: Prefs,
    ipv6_on: bool = False,
) -> list[str]:
    """生成 rules 段。

    性能优化(v1.1):
    - prefs 改为必填参数(原可选,默认为 Prefs.smart())
    - available_groups 改为必填参数

    依据:
    - plan.md Step 5
    - mihomo-spec.md 第八节 R-1~R-6
    - adaptation-concerns.md C8/C9 修复
    - prefs: 规则模板/自定义规则/规则集开关/兜底出口
    - ipv6_on: B4 增强,开启 IPv6 时补 v6 私有/回环兜底规则(防 v6 泄漏/黑洞)

    Args:
        available_groups: 实际存在的策略组名集合(来自 groups.build())。
            规则出口按优先级链解析,不存在的组自动降级。
        prefs: 用户偏好(必填,不可为 None)
        ipv6_on: 是否启用 IPv6

    Returns:
        list[str]: 规则列表(自上而下匹配)
    """

    # 解析各语义类别的实际出口(优先级链)
    ai_outlet = _resolve_outlet("ai", available_groups)
    streaming_outlet = _resolve_outlet("streaming", available_groups)
    google_outlet = _resolve_outlet("google", available_groups)
    proxy_outlet = _resolve_outlet("proxy", available_groups)
    fallback_outlet = prefs.fallback_outlet or _resolve_outlet("fallback", available_groups)

    rules: list[str] = []

    # === 1. 拦截(R-5: reject 必须最前)===
    rules.append("RULE-SET,reject,REJECT")

    # === 2. 私有网络 ===
    rules.append("RULE-SET,private,DIRECT")
    # R-3: IP-CIDR 必带 no-resolve
    rules.extend([
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    ])

    # B4: 开启 IPv6 时补 v6 私有/回环兜底(防 v6 泄漏/黑洞;其余 v6 走 MATCH 兜底)
    if ipv6_on:
        rules.extend([
            "IP-CIDR6,::1/128,DIRECT,no-resolve",   # 回环
            "IP-CIDR6,fc00::/7,DIRECT,no-resolve",  # 唯一本地地址 ULA
        ])

    # === 3. Apple/iCloud 直连(依 prefs 开关)===
    if prefs.enable_icloud:
        rules.append("RULE-SET,icloud,DIRECT")
    if prefs.enable_apple:
        rules.append("RULE-SET,apple,DIRECT")

    # === 4. AI 专线(R-1: 域名规则前置,在 GEOIP 之前)===
    # minimal 模板:跳过 AI 专线(纯翻墙用户不需要)
    if prefs.rule_template != "minimal":
        rules.extend([
            "DOMAIN-SUFFIX,openai.com," + ai_outlet,
            "DOMAIN-SUFFIX,chatgpt.com," + ai_outlet,
            "DOMAIN-SUFFIX,anthropic.com," + ai_outlet,
            "DOMAIN-SUFFIX,claude.ai," + ai_outlet,
            "DOMAIN-SUFFIX,gemini.google.com," + ai_outlet,
            "DOMAIN-SUFFIX,x.ai," + ai_outlet,
        ])

    # === 5. Google(依 prefs 开关)===
    if prefs.enable_google:
        rules.append("RULE-SET,google," + google_outlet)

    # === 6. 流媒体(minimal 模板跳过)===
    if prefs.rule_template != "minimal":
        rules.extend([
            "GEOSITE,netflix," + streaming_outlet,
            "GEOSITE,disney," + streaming_outlet,
            "GEOSITE,youtube," + google_outlet,
            "DOMAIN-SUFFIX,twitch.tv," + streaming_outlet,
            "DOMAIN-SUFFIX,spotify.com," + streaming_outlet,
        ])

    # === 7. 国内直连 ===
    rules.append("RULE-SET,direct,DIRECT")
    rules.append("GEOSITE,cn,DIRECT")
    # R-6: GEOIP 必带 no-resolve(避免破坏 fake-ip)
    rules.append("GEOIP,CN,DIRECT,no-resolve")

    # === 8. 代理 ===
    rules.append("RULE-SET,proxy," + proxy_outlet)
    rules.append("GEOSITE,geolocation-!cn," + proxy_outlet)

    # === 8.5 (B2) 自定义规则集:RULE-SET 引用,出口复用已有组/默认 auto ===
    for item in prefs.custom_rulesets:
        cname = str(item.get("name", "")).strip()
        if not cname:
            continue
        cout = str(item.get("outlet", "")).strip()
        if cout not in available_groups:
            cout = GROUP_AUTO  # 组不存在则回退自动优选(cross-check 不误报)
        rules.append(f"RULE-SET,{cname},{cout}")

    # === 9. 自定义规则(插在 MATCH 之前)===
    rules.extend(prefs.custom_rules)

    # === 10. 兜底(R-1/R-5: MATCH 必须最后且唯一)===
    rules.append("MATCH," + fallback_outlet)

    return rules
