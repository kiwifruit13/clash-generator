"""用户偏好(进阶选项)数据类。

31 选项 × 7 组,所有字段默认值 = 智能模式 = 当前 builder 固定模板行为。
用户在 GUI 进阶模式修改字段后,builder 依据 prefs 调整输出。

性能优化(v1.1):
- 添加 __post_init__ 校验,在构造时即时发现非法值

对应文档:
- options-risk-matrix.md(29 选项 + 333 测试新增 2 选项 = 31)
- options-deep-understanding.md(6 层认知)
- advanced-harmony.md(三层调和机制)

设计原则:
1. 默认值 = 智能模式(零修改时输出与改造前完全一致)
2. 纯数据无逻辑(校验由 checker 负责,GUI 负责联动提示)
3. fake_ip_filter_mode 不开放(GUI 注入 "*" 与 rule 模式冲突,已固定 blacklist)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class Prefs:
    """用户偏好(31 选项 × 7 组)。

    所有字段有默认值。advanced_mode=False 时 GUI 忽略全部修改,
    使用字段默认值(=智能模式)。

    校验规则(__post_init__):
    - log_level: silent/error/warning/info/debug
    - ipv6: auto/true/false
    - grouping_strategy: auto/standard/minimal/partial
    - rule_template: standard/minimal/fine
    - ruleset_source: loyalsoldier/sukkaw/quixoticheart
    - client: pc/router/mobile
    - mixed_port: 1-65535
    - url_test_interval: > 0
    - url_test_tolerance: > 0
    """

    # === 校验常量 ===
    VALID_LOG_LEVELS: ClassVar[set[str]] = {"silent", "error", "warning", "info", "debug"}
    VALID_IPV6_MODES: ClassVar[set[str]] = {"auto", "true", "false"}
    VALID_GROUPING_STRATEGIES: ClassVar[set[str]] = {"auto", "standard", "minimal", "partial"}
    VALID_RULE_TEMPLATES: ClassVar[set[str]] = {"standard", "minimal"}  # fine 为假选项,已移除(D8)
    VALID_RULESET_SOURCES: ClassVar[set[str]] = {"loyalsoldier"}
    VALID_CLIENTS: ClassVar[set[str]] = {"pc", "router", "mobile"}
    VALID_DNS_CACHE_ALGORITHMS: ClassVar[set[str]] = {"arc", "lru"}

    # === 元控制 ===
    advanced_mode: bool = False  # False=智能模式(全默认) True=进阶模式(用户可改)

    # === 1. 基础(6) ===
    mixed_port: int = 7890
    allow_lan: bool = True
    log_level: str = "info"  # silent/error/warning/info/debug
    external_controller: str = "127.0.0.1:9090"
    secret: str = ""
    ipv6: str = "auto"  # auto(依节点画像)/true/false

    # === 2. DNS(3 + 5 新增 000.txt 适配 = 8,原 fake-ip-filter-mode 已固定不开放)===
    enhanced_mode: str = "fake-ip"  # fake-ip/redir-host
    respect_rules: bool = True
    # 000.txt 适配新增(默认=智能模式基线):
    dns_cache_algorithm: str = "arc"  # arc/lru(000.txt: cache-algorithm)
    fake_ip_ttl: int = 1  # 秒,短 TTL 提新鲜度(000.txt: fake-ip-ttl)
    dns_ecs: bool = True  # 海外默认 DoH 追加 ecs,CDN 就近(000.txt: ecs=)
    dns_disable_qtype_65: bool = True  # 国内 DoH 关闭 HTTPS/SVCB 查询提速(000.txt)
    dns_use_fallback_filter: bool = True  # 加入 fallback + geoip 污染回退(000.txt)
    # P1(独立规格,默认关):境外 DNS 走代理的标签(空=关闭;填策略组名如"默认代理")
    dns_proxy_tag: str = ""
    # B(独立规格,默认关):启用 fakeipfilter 源(cn/!cn)并成对注入
    # fake-ip-filter + nameserver-policy。text 格式,不碰 mrs/单一源不变式。
    enable_fakeip_filter: bool = False
    # DNS 服务器列表不开放修改(口径统一是核心保证,用户改易破坏适配)

    # === 3. 代理组(5,含 333 测试新增分组策略)===
    url_test_interval: int = 300  # 秒
    url_test_tolerance: int = 50  # ms
    fallback_outlet: str = "🚀 自动优选"  # 兜底出口
    grouping_strategy: str = "auto"  # auto/standard/minimal/partial(333 测试新增)
    custom_groups: list[str] = field(default_factory=list)  # 自定义组(高级,暂仅存储)

    # === 4. 规则(2,含 333 测试新增规则模板)===
    rule_template: str = "standard"  # standard/minimal/fine(333 测试新增)
    custom_rules: list[str] = field(default_factory=list)  # 自定义规则行
    # P2(独立规格,默认关):AND() 拦截海外 UDP 443(QUIC),逼浏览器回退 TCP
    enable_quic_reject: bool = False

    # === 5. 规则集(4)===
    ruleset_source: str = "loyalsoldier"  # 仅 loyalsoldier(已收敛,见 BUG-02 修复)
    enable_apple: bool = True
    enable_icloud: bool = True
    enable_google: bool = True
    # format 恒为 text(源固定 loyalsoldier,不再支持 mrs_format 假选项)
    custom_rulesets: list[dict] = field(default_factory=list)  # 自定义规则集(B2 增强)

    # === 6. 附加(2)===
    tun_enable: bool = False
    profile: bool = True  # store-fake-ip + tracing

    # === 7. 告知(2)===
    usage: list[str] = field(default_factory=lambda: ["ai", "streaming"])  # ai/streaming/gaming
    client: str = "pc"  # pc/router/mobile

    def __post_init__(self) -> None:
        """构造后立即校验字段值合法性。

        Raises:
            ValueError: 若任何字段值不在允许范围内
        """
        errors: list[str] = []

        # log_level
        if self.log_level not in self.VALID_LOG_LEVELS:
            errors.append(
                f"log_level 无效: '{self.log_level}', 允许: {sorted(self.VALID_LOG_LEVELS)}"
            )

        # ipv6
        if self.ipv6 not in self.VALID_IPV6_MODES:
            errors.append(
                f"ipv6 无效: '{self.ipv6}', 允许: {sorted(self.VALID_IPV6_MODES)}"
            )

        # grouping_strategy
        if self.grouping_strategy not in self.VALID_GROUPING_STRATEGIES:
            errors.append(
                f"grouping_strategy 无效: '{self.grouping_strategy}', "
                f"允许: {sorted(self.VALID_GROUPING_STRATEGIES)}"
            )

        # rule_template
        if self.rule_template not in self.VALID_RULE_TEMPLATES:
            errors.append(
                f"rule_template 无效: '{self.rule_template}', 允许: {sorted(self.VALID_RULE_TEMPLATES)}"
            )

        # ruleset_source
        if self.ruleset_source not in self.VALID_RULESET_SOURCES:
            errors.append(
                f"ruleset_source 无效: '{self.ruleset_source}', 允许: {sorted(self.VALID_RULESET_SOURCES)}"
            )

        # dns_cache_algorithm
        if self.dns_cache_algorithm not in self.VALID_DNS_CACHE_ALGORITHMS:
            errors.append(
                f"dns_cache_algorithm 无效: '{self.dns_cache_algorithm}', "
                f"允许: {sorted(self.VALID_DNS_CACHE_ALGORITHMS)}"
            )

        # fake_ip_ttl
        if self.fake_ip_ttl <= 0:
            errors.append(f"fake_ip_ttl 无效: {self.fake_ip_ttl}, 必须 > 0")

        # client
        if self.client not in self.VALID_CLIENTS:
            errors.append(
                f"client 无效: '{self.client}', 允许: {sorted(self.VALID_CLIENTS)}"
            )

        # mixed_port
        if not (1 <= self.mixed_port <= 65535):
            errors.append(f"mixed_port 无效: {self.mixed_port}, 必须在 1-65535 之间")

        # url_test_interval
        if self.url_test_interval <= 0:
            errors.append(f"url_test_interval 无效: {self.url_test_interval}, 必须 > 0")

        # url_test_tolerance
        if self.url_test_tolerance <= 0:
            errors.append(f"url_test_tolerance 无效: {self.url_test_tolerance}, 必须 > 0")

        if errors:
            raise ValueError("Prefs 校验失败:\n" + "\n".join(f"  - {e}" for e in errors))

    # === 便捷方法 ===

    @classmethod
    def smart(cls) -> "Prefs":
        """创建智能模式实例(全默认,advanced_mode=False)。"""
        return cls()

    def is_smart(self) -> bool:
        """是否为智能模式。"""
        return not self.advanced_mode

    def effective_ipv6(self, has_ipv6_nodes: bool = False) -> bool:
        """计算 ipv6 有效值(auto 依节点画像)。"""
        if self.ipv6 == "auto":
            return has_ipv6_nodes
        return self.ipv6 == "true"
