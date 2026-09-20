"""输入清洗(Step 0)。

职责:
1. 读取用户 proxies 文件(SafeLoader + 5MB 限制)
2. 字段名归一化(P-1: auth_str→auth-str 等)
3. 类型归一化(G-1: port 字符串→整数)
4. 锚点自动展开(PyYAML safe_load 自动处理)
5. 节点名唯一性(P-4: 重名追加 (#2) 后缀)
6. 域名 server 标记(P-5)
7. skip-cert-verify 汇总(P-6)
8. 协议必填字段校验(P-2,P1-1 改进)

性能优化(v1.1):
- 使用 ThreadPoolExecutor 并行处理节点归一化
- 单节点处理函数合并字段名 + 类型归一化

对应 mihomo-spec.md:
- 第六节 P-1 字段归一化映射表
- 第六节 P-2 协议必填认证字段
- 第一节 G-1 YAML 类型严格性
- 第一节 G-2 锚点展开
- 第六节 P-4 节点名唯一性
- 第六节 P-5 域名 server
- 第六节 P-6 skip-cert-verify
"""

from __future__ import annotations

import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

from typing import Any

from .models import CleanResult, Node, Warning

# P-1: 字段名归一化映射表(下划线/拼写错 → 连字符)
# 依据:mihomo-spec.md 第六节 P-1
FIELD_NORMALIZE: dict[str, str] = {
    "auth_str": "auth-str",
    "recv_window_conn": "recv-window-conn",
    "recv_window": "recv-window",
    "client-figerprint": "client-fingerprint",  # 拼写修正
}

# G-1: 需要转为整数的字段(port 字符串→整数)
INT_FIELDS: set[str] = {"port", "alterId", "interval", "tolerance", "mtu"}

# G3 简化安全:文件大小限制(5MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# P-2: 协议必填认证字段表(依据 mihomo-spec.md 第六节 P-2)
# 缺少这些字段的节点将无法启动,mihomo -t 会报错
PROTOCOL_REQUIRED_FIELDS: dict[str, set[str]] = {
    "ss":        {"password"},
    "vmess":     {"uuid"},
    "vless":     {"uuid"},
    "trojan":    {"password"},
    "hysteria":  {"auth-str"},
    "hysteria2": {"password"},
    "tuic":      {"uuid", "password"},
    "snell":     {"psk"},
    "anytls":    {"password"},
    "wireguard": {"private-key", "public-key"},
}


def _normalize_field_names(node: dict) -> dict:
    """P-1 + G-3:递归归一化字段名(下划线→连字符, 修正拼写)。

    递归处理嵌套 dict(如 ws-opts、reality-opts、ws-opts.headers)。
    """
    result = {}
    for key, value in node.items():
        new_key = FIELD_NORMALIZE.get(key, key)
        if isinstance(value, dict):
            value = _normalize_field_names(value)
        result[new_key] = value
    return result


def _normalize_types(node: dict) -> dict:
    """G-1:类型归一化(port 字符串→整数)。

    其余布尔/数值字段在 chromego.txt 中已为正确 YAML 类型,
    若用户输入异常(如 "true" 字符串),留给校验器(checker.py)报错。
    """
    for field_name in INT_FIELDS:
        if field_name in node and isinstance(node[field_name], str):
            try:
                node[field_name] = int(node[field_name])
            except ValueError:
                pass  # 留给校验器报错
    return node


def _process_single_node(raw: dict, index: int) -> tuple[Node | None, list[Warning], int]:
    """单节点处理(可在多线程中并行执行)。

    合并了字段名归一化 + 类型归一化 + 节点创建 + 派生标记。

    Args:
        raw: 原始节点字典
        index: 节点索引(用于结果排序)

    Returns:
        (Node | None, warnings, index): 有效节点或 None(缺必填字段被剔除)
        + 该节点的警告列表 + 索引
    """
    warnings: list[Warning] = []
    name = raw.get("name", "<未命名>")

    # P-1 + G-3: 字段名归一化 + G-1: 类型归一化
    normalized = _normalize_types(_normalize_field_names(raw))

    # P-2: 协议必填字段校验
    proto = normalized.get("type", "")
    required = PROTOCOL_REQUIRED_FIELDS.get(proto)
    invalid = False  # BUG-07: 缺必填字段的节点视为无效,后续从 nodes 剔除
    if required:
        missing = required - set(normalized.keys())
        if missing:
            invalid = True
            missing_str = ", ".join(sorted(missing))
            warnings.append(
                Warning(
                    level="🔴",
                    message=f"{proto} 节点缺少必填字段:{missing_str}(已剔除)",
                    node_name=name,
                )
            )

    # P-5: 域名 server 标记
    server = str(normalized.get("server", ""))
    is_domain = bool(server) and not _is_ip_address(server)
    is_ipv6 = _is_ipv6(server)

    # P-6: skip-cert-verify 汇总
    skip_cert = bool(normalized.get("skip-cert-verify", False))

    node = Node(
        name=name,
        raw=normalized,
        is_domain_server=is_domain,
        is_ipv6_server=is_ipv6,
        skip_cert_verify=skip_cert,
    )

    # BUG-07: 无效节点返回 None,由 clean() 剔除并记录
    return (None if invalid else node), warnings, index


def _is_ip_address(server: str) -> bool:
    """判断 server 是否为 IP 地址(IPv4 或 IPv6)。"""
    try:
        ipaddress.ip_address(server)
        return True
    except ValueError:
        return False


def _is_ipv6(server: str) -> bool:
    """判断 server 是否为 IPv6 地址。"""
    try:
        return ipaddress.ip_address(server).version == 6
    except ValueError:
        return False


def _deduplicate_names(
    nodes: list[dict], warnings: list[Warning]
) -> list[dict]:
    """P-4:节点名唯一性, 重名追加 (#2) 后缀。"""
    seen: dict[str, int] = {}
    for node in nodes:
        name = node.get("name", "")
        if name in seen:
            seen[name] += 1
            new_name = f"{name} (#{seen[name]})"
            node["name"] = new_name
            warnings.append(
                Warning(
                    level="🟡",
                    message=f'节点名重复:"{name}" → 重命名为 "{new_name}"',
                    node_name=new_name,
                )
            )
        else:
            seen[name] = 1
    return nodes


def _strip_trailing_commas(text: str) -> str:
    """移除 JSON/类 JSON 中的尾随逗号(即 } 或 ] 前的逗号)。

    用状态机跳过字符串字面量与转义,避免破坏字符串内部的逗号/引号。
    例: '{"a":1,}' -> '{"a":1}' ; '[1,2,]' -> '[1,2]'

    Args:
        text: 待修复的文本

    Returns:
        移除尾随逗号后的文本
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    esc = False
    pending_ws = ""  # 逗号与其后 }/] 之间的空白
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            out.append(pending_ws)  # 保留字符串前的空白
            out.append(ch)
            pending_ws = ""
            in_str = True
            i += 1
            continue
        if ch in " \t\r\n":
            pending_ws += ch
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                # 尾随逗号:丢弃逗号及其后到 }/] 的空白
                i = j
                pending_ws = ""
            else:
                out.append(ch)
                i += 1
            continue
        # 普通字符
        out.append(pending_ws)
        out.append(ch)
        pending_ws = ""
        i += 1
    return "".join(out)


def _load_config(path: Path) -> Any:
    """按内容鲁棒解析配置(不依赖扩展名)。

    B1/鲁棒性增强:无论 `.json`/`.yaml`/`.yml`/`.txt`,一律按级联尝试:
      1. 严格 json.loads(纯 JSON);
      2. 修复尾随逗号后再 json.loads(容忍手写类 JSON);
      3. yaml.safe_load 兜底(YAML 是 JSON 的超集,容忍单引号/未加引号键/尾随逗号)。
    均以 utf-8-sig 读取(自动去 BOM)。

    Args:
        path: 配置文件路径

    Returns:
        Any: 解析结果(顶层对象或列表)
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        content = f.read()

    # 仅当内容明显是 JSON/类 JSON(以 { 或 [ 开头)时才走 JSON 级联,否则直走 YAML
    text = content.lstrip(" \t\r\n")
    if text[:1] in ("{", "["):
        # 1) 严格 JSON
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        # 2) 修复尾随逗号后再严格 JSON
        try:
            return json.loads(_strip_trailing_commas(content))
        except json.JSONDecodeError:
            pass
    # 3) YAML 兜底(YAML 是 JSON 超集,兼容性最广)
    return yaml.safe_load(content)


def clean(input_path: str | Path) -> CleanResult:
    """主入口:读取并清洗 proxies 文件。

    性能优化(v1.1):
    - 使用 ThreadPoolExecutor 并行处理节点归一化
    - 结果按原始顺序排序(保序)

    Args:
        input_path: 用户 proxies 文件路径(如 chromego.txt)

    Returns:
        CleanResult: 清洗后的节点列表 + 警告

    Raises:
        FileNotFoundError: 文件不存在
        ValueError: 文件过大或 YAML 格式错误
    """
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在:{path}")

    # G3: 文件大小限制
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError(
            f"文件过大({size} bytes > {MAX_FILE_SIZE} bytes),可能非正常 proxies 文件"
        )

    # 读取并解析 YAML/JSON(B1 增强;SafeLoader 防实体爆炸;JSON 为 YAML 子集)
    data = _load_config(path)

    if not isinstance(data, dict) or "proxies" not in data:
        raise ValueError("文件格式错误:顶层缺少 proxies 字段")

    raw_nodes = data["proxies"]
    if not isinstance(raw_nodes, list):
        raise ValueError("proxies 字段必须为列表")

    result = CleanResult()

    # P-4: 节点名去重
    raw_nodes = _deduplicate_names(raw_nodes, result.warnings)

    # ===== 性能优化:多线程并行处理 =====
    node_count = len(raw_nodes)
    # 线程数:节点数少时用 1 线程(单线程更快);多时用 CPU 核心数的一半
    if node_count <= 20:
        max_workers = 1
    else:
        import os
        max_workers = min(os.cpu_count() or 4, 8)  # 最多 8 线程,避免过度开销

    # 并行处理所有节点
    processed_results: list[tuple[int, Node, list[Warning]]] = []

    if max_workers > 1:
        # 多线程模式
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_process_single_node, raw, i): i
                for i, raw in enumerate(raw_nodes)
            }
            for future in as_completed(futures):
                node, node_warnings, index = future.result()
                processed_results.append((index, node, node_warnings))
    else:
        # 单线程模式(保序,更简单)
        for i, raw in enumerate(raw_nodes):
            node, node_warnings, _ = _process_single_node(raw, i)
            processed_results.append((i, node, node_warnings))

    # 按原始顺序排序并合并结果
    processed_results.sort(key=lambda x: x[0])

    for _, node, node_warnings in processed_results:
        if node is None:
            # BUG-07: 缺必填字段的无效节点被剔除;名字从 🔴 警告中提取
            for w in node_warnings:
                if w.level == "🔴":
                    result.excluded_names.append(w.node_name or "<未命名>")
        else:
            result.nodes.append(node)
        result.warnings.extend(node_warnings)

    # P-5: 域名 server 警告
    if result.domain_server_names:
        names = result.domain_server_names
        preview = ", ".join(names[:5]) + ("..." if len(names) > 5 else "")
        result.warnings.append(
            Warning(
                level="🟠",
                message=f"{len(names)} 个节点使用域名 server(可能解析异常):{preview}",
            )
        )

    # P-6: skip-cert-verify 警告
    if result.skip_cert_names:
        names = result.skip_cert_names
        preview = ", ".join(names[:5]) + ("..." if len(names) > 5 else "")
        result.warnings.append(
            Warning(
                level="🟠",
                message=f"{len(names)} 个节点 skip-cert-verify=true(证书验证关闭):{preview}",
            )
        )

    return result


def to_yaml(result: CleanResult) -> str:
    """将清洗结果导出为规范 YAML(用于验证或预览)。

    使用 block style + 保持插入顺序 + allow_unicode(中文节点名)。
    """
    data = {"proxies": [node.raw for node in result.nodes]}
    return yaml.dump(
        data,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )
