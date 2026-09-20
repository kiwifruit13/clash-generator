"""proxy-groups 段生成器(M4 三位一体之三)。

对应 plan.md Step 4 + mihomo-spec.md 第七节 PG-1~PG-4 红线。

基于节点画像动态分组:
- 🚀 节点选择(select):总入口
- 🚀 自动优选(url-test):全部节点,自动淘汰不可达
- 🔒 安全专线(url-test):vless-reality + tuic(抗风控,用于 AI)
- 🌐 网页浏览(url-test):vmess + vless-ws/trojan-ws CF CDN(流媒体)
- ⚡ 高速下载(url-test):hysteria/hysteria2(UDP 加速)

P0-1 改进:协议特性表驱动分类(替代 if-elif 硬编码)。
新增协议只需在 CLASSIFY_RULES 表中添加规则,无需改 _classify_nodes 逻辑。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..models import CleanResult, Node
from ..prefs import Prefs

# 策略组名常量(供 rules.py 引用,确保命名一致)
GROUP_SELECT = "🚀 节点选择"
GROUP_AUTO = "🚀 自动优选"
GROUP_SAFE = "🔒 安全专线"
GROUP_WEB = "🌐 网页浏览"
GROUP_DOWNLOAD = "⚡ 高速下载"


@dataclass
class NodeContext:
    """节点分类上下文(供条件函数访问节点特征)。

    将节点原始 dict 的字段抽取为强类型属性,
    使条件函数不依赖 dict 键名,更健壮。
    """

    network: str           # network 字段(ws/grpc/h2 等)
    flow: str              # flow 字段(xtls-rprx-vision 等)
    port: int              # 服务端口(B3 增强:区分 CF CDN 端口与自建)
    is_domain_server: bool # server 是域名(P-5)
    is_ipv6_server: bool   # server 是 IPv6


# B3 增强:常见 CDN/Web 端口(用于区分托管端口与自建高位端口)
WEB_PORTS: set[int] = {80, 443, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096}


# 协议分类规则表(数据驱动,按顺序匹配,先匹配先归类)
# 新增协议只需在此表添加规则,无需改 _classify_nodes 逻辑
# (协议, 目标分组, 条件函数) — 条件返回 True 则归入该分组
CLASSIFY_RULES: list[tuple[str, str, Callable[[NodeContext], bool]]] = [
    # === 高速下载组:UDP 加速协议 ===
    ("hysteria",   GROUP_DOWNLOAD, lambda ctx: True),
    ("hysteria2",  GROUP_DOWNLOAD, lambda ctx: True),

    # === 安全专线组:抗风控协议(reality + tuic)===
    ("tuic",       GROUP_SAFE, lambda ctx: True),
    ("vless",      GROUP_SAFE, lambda ctx: ctx.flow == "xtls-rprx-vision"),

    # === 网页浏览组:CF CDN 节点(端口在 Web 集内,且 域名 server 或 ws) ===
    ("vmess",      GROUP_WEB, lambda ctx: ctx.port in WEB_PORTS and (ctx.is_domain_server or ctx.network == "ws")),
    ("trojan",     GROUP_WEB, lambda ctx: ctx.port == 443 and ctx.network == "ws"),
    ("vless",      GROUP_WEB, lambda ctx: ctx.network == "ws" and ctx.is_domain_server and ctx.port in WEB_PORTS),

    # 其余协议/条件不匹配的节点 → 自动归入 GROUP_AUTO(在 _classify_nodes 中处理)
]


def _build_context(node: Node) -> NodeContext:
    """从 Node 构建 NodeContext。"""
    raw = node.raw
    # port 防御性转换(非数字字符串→0;真正非法留待 checker G-1 报错)
    try:
        port = int(raw.get("port", 0) or 0)
    except (ValueError, TypeError):
        port = 0
    return NodeContext(
        network=str(raw.get("network", "")),
        flow=str(raw.get("flow", "")),
        port=port,
        is_domain_server=node.is_domain_server,
        is_ipv6_server=node.is_ipv6_server,
    )


def _classify_node(node: Node) -> str | None:
    """分类单个节点,返回目标分组名。

    按 CLASSIFY_RULES 表顺序匹配,第一个匹配的规则生效。
    未匹配任何规则返回 None(归入 GROUP_AUTO)。

    Args:
        node: 归一化后的节点

    Returns:
        分组名(GROUP_SAFE/GROUP_WEB/GROUP_DOWNLOAD)或 None(→ GROUP_AUTO)
    """
    proto = node.raw.get("type", "")
    ctx = _build_context(node)

    for rule_proto, group, condition in CLASSIFY_RULES:
        if proto == rule_proto and condition(ctx):
            return group

    return None  # 未匹配 → GROUP_AUTO


def _classify_nodes(result: CleanResult) -> dict[str, list[str]]:
    """按协议+特征细分节点(表驱动)。

    Returns:
        dict: {
            "safe": [安全专线节点名],      # vless-reality + tuic
            "web": [网页浏览节点名],       # vmess + vless-ws/trojan-ws CF CDN
            "download": [高速下载节点名],  # hysteria/hysteria2
            "all": [全部节点名],
        }
    """
    safe_nodes: list[str] = []
    web_nodes: list[str] = []
    download_nodes: list[str] = []
    all_names: list[str] = []

    group_map = {
        GROUP_SAFE: safe_nodes,
        GROUP_WEB: web_nodes,
        GROUP_DOWNLOAD: download_nodes,
    }

    for node in result.nodes:
        all_names.append(node.name)
        target = _classify_node(node)
        if target and target in group_map:
            group_map[target].append(node.name)
        # target 为 None 的节点只进 all_names(→ GROUP_AUTO)

    return {
        "safe": safe_nodes,
        "web": web_nodes,
        "download": download_nodes,
        "all": all_names,
    }


def build(result: CleanResult, prefs: Prefs) -> list[dict]:
    """基于清洗结果生成 proxy-groups 段。

    空组处理策略(PG-4 红线):
    - 若某分组为空,则不生成该组(避免空 url-test 组)
    - GROUP_SELECT 和 GROUP_AUTO 始终生成(核心入口)
    - 空组的引用会从 GROUP_SELECT 的 proxies 列表中移除

    Args:
        result: cleaner.clean() 的输出
        prefs: 用户偏好(url-test 参数 + 分组策略)

    Returns:
        list[dict]: proxy-groups 列表
    """
    # url-test 参数从 prefs 动态生成(PG-3: 必填 url + interval)
    url_test_params = {
        "url": "http://www.gstatic.com/generate_204",
        "interval": prefs.url_test_interval,
        "tolerance": prefs.url_test_tolerance,
        "lazy": True,
    }

    classified = _classify_nodes(result)

    # 判断哪些分组非空,空的不生成
    has_safe = bool(classified["safe"])
    has_web = bool(classified["web"])
    has_download = bool(classified["download"])

    # 分组策略(BUG-03 修复):auto → 依画像建议映射(minimal/partial/standard)。
    #   partial/standard 均生成非空子组(等同原非 minimal 行为);minimal 仅 select+auto。
    if prefs.grouping_strategy == "auto":
        from ..analyzer import analyze_grouping
        is_minimal = analyze_grouping(result).suggested_strategy == "minimal"
    else:
        is_minimal = prefs.grouping_strategy == "minimal"

    # GROUP_SELECT 的可选子组(仅包含非空的,且非 minimal 模式)
    select_options: list[str] = [GROUP_AUTO]
    if not is_minimal:
        if has_safe:
            select_options.append(GROUP_SAFE)
        if has_web:
            select_options.append(GROUP_WEB)
        if has_download:
            select_options.append(GROUP_DOWNLOAD)
    select_options.extend(["DIRECT", "REJECT"])

    groups: list[dict] = [
        # PG-1: select 类型,手动选择总入口
        {
            "name": GROUP_SELECT,
            "type": "select",
            "proxies": select_options,
        },
        # PG-1: url-test 类型,自动测速(始终生成,核心组)
        # PG-3: 必填 url + interval
        {
            "name": GROUP_AUTO,
            "type": "url-test",
            **url_test_params,
            "proxies": classified["all"],  # 全部节点,自动淘汰不可达
        },
    ]

    # 仅生成非空的子组(避免 PG-4 空组红线);minimal 模式跳过所有子组
    if not is_minimal:
        if has_safe:
            groups.append({
                "name": GROUP_SAFE,
                "type": "url-test",
                **url_test_params,
                "proxies": classified["safe"],
            })
        if has_web:
            groups.append({
                "name": GROUP_WEB,
                "type": "url-test",
                **url_test_params,
                "proxies": classified["web"],
            })
        if has_download:
            groups.append({
                "name": GROUP_DOWNLOAD,
                "type": "url-test",
                **url_test_params,
                "proxies": classified["download"],
            })

    return groups


def get_group_names() -> set[str]:
    """返回所有策略组名(供跨段命名校验用)。"""
    return {GROUP_SELECT, GROUP_AUTO, GROUP_SAFE, GROUP_WEB, GROUP_DOWNLOAD}
