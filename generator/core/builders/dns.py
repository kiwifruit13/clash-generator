"""dns 段生成器(M4 三位一体之一)。

对应 plan.md Step 2 + mihomo-spec.md 第三节 D-1~D-8 红线。

关键改进(对照 ChromeGO.yaml):
- D-1: 显式 enhanced-mode: fake-ip(默认 redir-host)
- D-2: respect-rules: true + proxy-server-nameserver(防鸡生蛋)
- D-4: fake-ip-filter-mode: blacklist(兼容性优先,见下方说明)
- C1 修复: nameserver-policy 用 rule-set: 统一口径
- C6 修复: 海外 DoH 用纯 IP(1.1.1.1/8.8.8.8)
- C7 修复: fake-ip-filter 含 STUN + NTP(NTP 为用户 2026-08-09 修订,系统时间同步依赖)

⚠️ ERR_DNS_FakeIpFilterRuleMode(2026-07-31 发现):
  原设计用 fake-ip-filter-mode: rule + RULE-SET/GEOSITE/MATCH 语法。
  实测 GUI 客户端(Clash Verge/Mihomo Party 等)合并配置时会注入自己的
  blacklist 风格条目(含 "*"),rule 模式下 "*" 无 action 字段 →
  mihomo 报 "invalid action '', must be 'fake-ip' or 'real-ip'"。
  规避:改用 blacklist 模式(默认值,所有 mihomo 版本/GUI 通用),
  用 "rule-set:xxx" / "+.domain" / "*.domain" 通配符语法。
  blacklist 模式下注入的 "*" 合法(= 全部用真实 IP,保守降级,不报错)。
  语义损失:无法用 DOMAIN-KEYWORD(stun),改用具体 STUN 域名通配符。
"""

from __future__ import annotations

from ..prefs import Prefs


def build(prefs: Prefs, ipv6_on: bool = False) -> dict:
    """生成 dns 段。

    依据:
    - plan.md Step 2
    - mihomo-spec.md 第三节 D-1~D-8
    - adaptation-concerns.md C1/C6/C7 修复
    - prefs: enhanced_mode / respect_rules 可调
    - ipv6_on: B4 增强,开启 IPv6 时补 fake-ip-v6-range(否则 v6 不走 fake-ip)

    Args:
        prefs: 用户偏好(DNS 组 3 选项)
        ipv6_on: 是否启用 IPv6(fake-ip 模式下补 v6 假 IP 范围)

    Returns:
        dict: dns 段配置
    """
    is_fake_ip = prefs.enhanced_mode == "fake-ip"

    # 国内 DoH 列表;按 prefs.dns_disable_qtype_65 决定是否追加 disable-qtype-65 参数
    # (000.txt 适配:国内 DoH 关闭 HTTPS/SVCB(qtype 65)查询,提速)
    q65 = "#disable-qtype-65=true" if prefs.dns_disable_qtype_65 else ""
    domestic_doh = [
        f"https://doh.pub/dns-query{q65}",
        f"https://dns.alidns.com/dns-query{q65}",
    ]

    # 海外默认 DoH;按 prefs.dns_ecs 决定是否追加 EDNS Client Subnet(CDN 就近)
    # (000.txt 适配:ecs=223.5.5.0/24,向境外 DoH 声明客户端网段以换取就近结果)
    ecs = "&ecs=223.5.5.0/24" if prefs.dns_ecs else ""
    # P1: 境外 DNS 走代理的标签(如 #默认代理)。TAG 位于 '#' 与首个 '&' 之间。
    # 000.txt 用 "#默认代理",顺序上 ecs 在前、TAG 在后,与解析器 "$#...&" 约定一致。
    proxy_tag = f"#{prefs.dns_proxy_tag}" if prefs.dns_proxy_tag else ""
    foreign_doh = [
        f"https://1.1.1.1/dns-query{ecs}{proxy_tag}",
        f"https://8.8.8.8/dns-query{ecs}{proxy_tag}",
    ]

    cfg: dict = {
        "enable": True,
        "listen": "0.0.0.0:1053",
        "ipv6": False,  # C5 决策:保持 false(DNS 段独立控制,与 basic.ipv6 解耦)
        # D-1: 显式写出(默认 redir-host)
        "enhanced-mode": prefs.enhanced_mode,
        # 000.txt 适配:显式缓存淘汰算法(arc 抗突发,优于默认 lru)
        "cache-algorithm": prefs.dns_cache_algorithm,
        "fake-ip-range": "198.18.0.1/16",
        # D-2: respect-rules 必须配 proxy-server-nameserver(防鸡生蛋)
        "respect-rules": prefs.respect_rules,
        # 解析 DoH 服务器域名(纯 IP DNS)
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        # D-2: 解析节点域名(防鸡生蛋,独立于 nameserver-policy)
        "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
        # 直连流量 DNS(000.txt 适配:各条目按需附 disable-qtype-65)
        "direct-nameserver": list(domestic_doh),
        "direct-nameserver-follow-policy": False,
        # 默认 DNS(海外,C6 修复:纯 IP 避免 DoH 域名解析循环;000.txt 适配:按需附 ecs)
        "nameserver": list(foreign_doh),
        # C1 修复:口径统一到 rule-set(与 rules 段引用同一套规则集)
        # 000.txt 适配:国内走国内 DoH,境外走海外 DoH,解析更精准
        "nameserver-policy": {
            "rule-set:direct,private": list(domestic_doh),
            "rule-set:proxy": list(foreign_doh),
        },
    }

    # 000.txt 适配:加入 fallback + geoip 污染回退兜底(按 IP 归属判断是否被污染)
    if prefs.dns_use_fallback_filter:
        cfg["fallback"] = list(foreign_doh)
        cfg["fallback-filter"] = {"geoip": True, "geoip-code": "CN"}

    # fake-ip-filter 仅在 fake-ip 模式下生成(redir-host 模式无意义)
    # ⚠️ 优化原则(2026-08-09 用户反馈修订):
    #   fake-ip-filter 让特定域名返回真实 IP。只有"必须真实 IP 才能工作"的域名才放进来。
    #   已被规则 REJECT 的域名(如广告)根本不会解析,放这里毫无意义反而拖慢解析。
    #   故保留四类:局域网检测 / 微软连通性 / STUN 服务 / NTP 时间同步。
    #   NTP 必须使用真实 IP(系统时间同步依赖真实 NTP 服务器,fake-ip 会导致时间错误)。
    if is_fake_ip:
        cfg["fake-ip-filter-mode"] = "blacklist"
        # 000.txt 适配:显式短 TTL,降低 fake-ip 缓存陈旧
        cfg["fake-ip-ttl"] = prefs.fake_ip_ttl
        cfg["fake-ip-filter"] = [
            # === 1. 局域网/私有网络(真实 IP,本地设备发现必需) ===
            "rule-set:private",
            "+.lan",
            "+.local",
            "+.localdomain",
            "+.localhost",
            "+.home.arpa",
            # === 2. Windows 网络连通性检测(NCSI,系统网络状态判断) ===
            "+.msftconnecttest.com",
            "+.msftncsi.com",
            # === 3. STUN/WebRTC(游戏 NAT 穿透/视频通话必需真实 IP) ===
            "+.stun.l.google.com",
            "+.stun.miwifi.com",
            "+.stun.chat.bilibili.com",
            # === 4. NTP 时间同步(系统时间同步依赖真实 IP,否则时间错误) ===
            "+.ntp.org",
        ]
        # B4: 开启 IPv6 时补 v6 假 IP 范围,否则 v6 流量不走 fake-ip
        if ipv6_on:
            cfg["fake-ip-v6-range"] = "2001:db8::/64"

    # B(独立规格,默认关):fakeipfilter 成对注入 —— 同一清单同时驱动
    # fake-ip-filter(跳过假 IP)与 nameserver-policy(指定真实解析器)。
    # 只改一半会让 DNS 分流失效;此处由单点声明保证两者一致(checker D-10 兜底)。
    if prefs.enable_fakeip_filter:
        if is_fake_ip:
            cfg["fake-ip-filter"].append("rule-set:fakeipfilter_cn")
            cfg["fake-ip-filter"].append("rule-set:fakeipfilter_!cn")
        cfg["nameserver-policy"]["rule-set:fakeipfilter_cn"] = list(domestic_doh)
        cfg["nameserver-policy"]["rule-set:fakeipfilter_!cn"] = list(foreign_doh)

    return cfg
