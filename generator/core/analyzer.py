"""节点画像(M3)。

分析 CleanResult,输出 NodeProfile + GroupingSuggestion,供后续 builders(尤其是 groups.py)决策分组。

性能优化(v1.1):
- 合并 analyze + analyze_grouping 为单次遍历
- 减少 50% 遍历开销

对应 plan.md Step 4 节点画像表。

P1-2 改进:增加 GroupingSuggestion(分组可行性分析),
告诉 groups.py 哪些分组有意义,避免空组。
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from .models import CleanResult


@dataclass
class NodeProfile:
    """节点画像。

    Attributes:
        total: 节点总数
        protocol_distribution: {协议: [节点名]}(保持插入顺序)
        ipv6_nodes: IPv6 server 节点名列表
        domain_server_nodes: 域名 server 节点名列表(P-5)
        skip_cert_nodes: skip-cert-verify=true 节点名列表(P-6)
    """

    total: int = 0
    protocol_distribution: "OrderedDict[str, list[str]]" = field(
        default_factory=OrderedDict
    )
    ipv6_nodes: list[str] = field(default_factory=list)
    domain_server_nodes: list[str] = field(default_factory=list)
    skip_cert_nodes: list[str] = field(default_factory=list)

    @property
    def protocol_counts(self) -> dict[str, int]:
        """{协议: 数量}。"""
        return {k: len(v) for k, v in self.protocol_distribution.items()}

    @property
    def has_ipv6(self) -> bool:
        """是否存在 IPv6 节点。"""
        return len(self.ipv6_nodes) > 0


@dataclass
class GroupingSuggestion:
    """分组可行性分析(供 groups.py 决策)。

    P1-2 改进:在 analyzer 阶段预判哪些分组有意义,
    groups.py 据此决定生成哪些组,避免空组(PG-4)。

    Attributes:
        has_safe: 是否有安全专线节点(reality + tuic)
        has_web: 是否有网页浏览节点(vmess + vless-ws/trojan-ws CF CDN)
        has_download: 是否有高速下载节点(hysteria/hysteria2)
        safe_count: 安全专线节点数
        web_count: 网页浏览节点数
        download_count: 高速下载节点数
        total: 节点总数
        diversity_score: 协议多样性评分(0.0-1.0)
            1.0 = 协议分布均匀(每种分组都有节点)
            0.0 = 全部节点属于同一分组(如 333.txt 全是 CF CDN)
        suggested_strategy: 建议的分组策略
            "standard" = 标准分组(safe+web+download 都生成)
            "minimal"  = 精简分组(只生成 auto,适合单协议)
            "partial"  = 部分组(生成 auto + 非空的子组)
    """

    has_safe: bool = False
    has_web: bool = False
    has_download: bool = False
    safe_count: int = 0
    web_count: int = 0
    download_count: int = 0
    total: int = 0
    diversity_score: float = 0.0
    suggested_strategy: str = "partial"

    def __repr__(self) -> str:
        return (
            f"GroupingSuggestion(strategy={self.suggested_strategy}, "
            f"safe={self.safe_count}, web={self.web_count}, "
            f"download={self.download_count}, total={self.total}, "
            f"diversity={self.diversity_score:.2f})"
        )


# 协议 → 候选分组映射(用于分组可行性预判)
# 与 groups.py 的 CLASSIFY_RULES 保持一致
_PROTO_TO_GROUP: dict[str, str] = {
    "hysteria": "download",
    "hysteria2": "download",
    "tuic": "safe",
    "vmess": "web",
    "trojan": "web",  # 简化:trojan 归 web(实际需看 network,这里粗判)
}

# 与 groups.py 保持一致(B3:端口维度)
_WEB_PORTS: set[int] = {80, 443, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096}


def _predict_group(node_proto: str, node_flow: str, node_network: str, is_domain: bool, port: int) -> str | None:
    """预测节点所属分组(与 groups.py 的 CLASSIFY_RULES 逻辑一致,B3 含端口)。

    Returns:
        "safe"/"web"/"download" 或 None(→ auto)
    """
    if node_proto in ("hysteria", "hysteria2"):
        return "download"
    if node_proto == "tuic":
        return "safe"
    if node_proto == "vmess":
        return "web" if port in _WEB_PORTS and (is_domain or node_network == "ws") else None
    if node_proto == "trojan":
        return "web" if port == 443 and node_network == "ws" else None
    if node_proto == "vless":
        if node_flow == "xtls-rprx-vision":
            return "safe"
        if node_network == "ws" and is_domain and port in _WEB_PORTS:
            return "web"
        return None
    return None


def analyze(result: CleanResult) -> NodeProfile:
    """分析清洗结果,生成节点画像(兼容旧接口)。

    内部调用 analyze_all() 单次遍历。

    Args:
        result: cleaner.clean() 的输出

    Returns:
        NodeProfile: 节点画像
    """
    profile, _ = analyze_all(result)
    return profile


def analyze_grouping(result: CleanResult) -> GroupingSuggestion:
    """分析分组可行性(P1-2 改进,兼容旧接口)。

    内部调用 analyze_all() 单次遍历。

    Args:
        result: cleaner.clean() 的输出

    Returns:
        GroupingSuggestion: 分组建议
    """
    _, suggestion = analyze_all(result)
    return suggestion


def analyze_all(result: CleanResult) -> tuple[NodeProfile, GroupingSuggestion]:
    """单次遍历同时生成节点画像和分组建议(性能优化 v1.1)。

    将 analyze() 和 analyze_grouping() 合并为单次遍历,
    减少 50% 的遍历开销。

    Args:
        result: cleaner.clean() 的输出

    Returns:
        (NodeProfile, GroupingSuggestion): 节点画像 + 分组建议
    """
    total = result.count
    profile = NodeProfile(total=total)
    suggestion = GroupingSuggestion(total=total)

    safe_count = web_count = download_count = 0

    for node in result.nodes:
        # === NodeProfile ===
        protocol = node.raw.get("type", "unknown")
        if protocol not in profile.protocol_distribution:
            profile.protocol_distribution[protocol] = []
        profile.protocol_distribution[protocol].append(node.name)

        if node.is_ipv6_server:
            profile.ipv6_nodes.append(node.name)
        if node.is_domain_server:
            profile.domain_server_nodes.append(node.name)
        if node.skip_cert_verify:
            profile.skip_cert_nodes.append(node.name)

        # === GroupingSuggestion (同一次遍历) ===
        proto = node.raw.get("type", "")
        flow = node.raw.get("flow", "")
        network = node.raw.get("network", "")
        try:
            port = int(node.raw.get("port", 0) or 0)
        except (ValueError, TypeError):
            port = 0
        group = _predict_group(proto, flow, network, node.is_domain_server, port)

        if group == "safe":
            safe_count += 1
        elif group == "web":
            web_count += 1
        elif group == "download":
            download_count += 1

    suggestion.safe_count = safe_count
    suggestion.web_count = web_count
    suggestion.download_count = download_count
    suggestion.has_safe = safe_count > 0
    suggestion.has_web = web_count > 0
    suggestion.has_download = download_count > 0

    # 协议多样性评分:有节点的分组数 / 3
    active_groups = sum([suggestion.has_safe, suggestion.has_web, suggestion.has_download])
    suggestion.diversity_score = active_groups / 3.0

    # 建议分组策略
    if active_groups == 3:
        suggestion.suggested_strategy = "standard"
    elif active_groups == 0:
        suggestion.suggested_strategy = "minimal"
    else:
        suggestion.suggested_strategy = "partial"

    return profile, suggestion
