"""数据模型:节点、清洗结果、警告。

对应 mihomo-spec.md 第六节 P-1~P-6 红线。

性能优化(v1.1):
- 使用 slots=True 减少 dataclass 内存占用(每个实例节省约 40-50%)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Warning:
    """清洗警告项。

    Attributes:
        level: 严重度('🔴' 硬红线 / '🟠' 软红线 / '🟡' 约定)
        message: 警告描述
        node_name: 关联节点名;None 表示全局警告
    """

    level: str
    message: str
    node_name: str | None = None


@dataclass(slots=True)
class Node:
    """单个代理节点(归一化后)。

    Attributes:
        name: 节点名(已确保唯一)
        raw: 归一化后的完整节点 dict(字段名连字符、port 整数)
        is_domain_server: server 是域名(非 IP),对应 P-5
        is_ipv6_server: server 是 IPv6 地址
        skip_cert_verify: skip-cert-verify=true,对应 P-6
    """

    name: str
    raw: dict[str, Any]
    is_domain_server: bool = False
    is_ipv6_server: bool = False
    skip_cert_verify: bool = False


@dataclass(slots=True)
class CleanResult:
    """输入清洗结果。

    Attributes:
        nodes: 归一化后的节点列表(已剔除 P-2 缺必填字段的无效节点)
        warnings: 清洗过程产生的警告
        excluded_names: 因缺必填认证字段而被剔除的节点名列表(BUG-07 修复)
    """

    nodes: list[Node] = field(default_factory=list)
    warnings: list[Warning] = field(default_factory=list)
    excluded_names: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        """节点数量。"""
        return len(self.nodes)

    @property
    def has_errors(self) -> bool:
        """是否存在硬红线错误(🔴)。"""
        return any(w.level == "🔴" for w in self.warnings)

    @property
    def domain_server_names(self) -> list[str]:
        """使用域名 server 的节点名列表(P-5)。"""
        return [n.name for n in self.nodes if n.is_domain_server]

    @property
    def skip_cert_names(self) -> list[str]:
        """skip-cert-verify=true 的节点名列表(P-6)。"""
        return [n.name for n in self.nodes if n.skip_cert_verify]
