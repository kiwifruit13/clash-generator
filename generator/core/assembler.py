"""组装器(Step 7)。

职责:
1. 合并 7 模块(YAML key 合并)
2. 跨段命名一致性校验(modular-breakdown.md 约束2)
3. 输出 final.yaml

对应 plan.md Step 7 + modular-breakdown.md 约束1/2/3。
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .cleaner import clean
from .prefs import Prefs
from .builders import basic, dns, groups, providers, rules, sniffer

# 内置策略(PG-2/R-4 检查时排除)
BUILT_IN = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}


def _check_cross_section_consistency(
    proxies_list: list[dict],
    groups_list: list[dict],
    rules_list: list[str],
    providers_cfg: dict,
    dns_cfg: dict,
) -> list[str]:
    """跨段命名一致性校验(modular-breakdown.md 约束2)。

    Returns:
        list[str]: 错误列表(空表示无错误)
    """
    errors: list[str] = []
    node_names = {p.get("name", "") for p in proxies_list}
    group_names = {g["name"] for g in groups_list}
    provider_names = set(providers_cfg.keys())

    # rules 出口必须在 groups 或内置策略中
    for rule in rules_list:
        parts = rule.split(",")
        if len(parts) >= 3:
            outlet = parts[2].strip()
            if outlet not in BUILT_IN and outlet not in group_names:
                errors.append(f"rules 出口 '{outlet}' 未在 proxy-groups 定义:{rule}")

    # rules 的 RULE-SET 引用必须在 providers 中定义
    for rule in rules_list:
        if rule.startswith("RULE-SET,"):
            parts = rule.split(",")
            if len(parts) >= 2 and parts[1] not in provider_names:
                errors.append(f"rules 引用 RULE-SET,{parts[1]} 未在 rule-providers 定义")

    # proxy-groups 引用的节点/组必须存在
    for g in groups_list:
        for proxy in g.get("proxies", []):
            if proxy not in node_names and proxy not in group_names and proxy not in BUILT_IN:
                errors.append(f"proxy-group '{g['name']}' 引用不存在的节点/组:{proxy}")

    # nameserver-policy 的 rule-set:xxx 必须在 providers 中定义
    for key in dns_cfg.get("nameserver-policy", {}):
        if key.startswith("rule-set:"):
            sets = key.split(":", 1)[1].split(",")
            for s in sets:
                s = s.strip()
                if s not in provider_names:
                    errors.append(f"nameserver-policy 引用 rule-set:{s} 未在 rule-providers 定义")

    return errors


def assemble(
    input_path: str | Path,
    prefs: Prefs | None = None,
    clean_result=None,
) -> tuple[str, list[str]]:
    """组装完整配置。

    Args:
        input_path: 用户 proxies 文件路径
        prefs: 用户偏好(None=智能模式默认)
        clean_result: 可选的已清洗结果(C1 修复,BUG-04: 避免重复 clean);None则内部清洗

    Returns:
        tuple: (final_yaml_str, errors)
        errors 为空表示跨段校验通过

    Raises:
        ValueError: 清洗后无任何有效节点(全部被剔除或缺 proxies)
    """
    if prefs is None:
        prefs = Prefs.smart()

    # Step 0: 清洗输入(支持复用已清洗结果,BUG-04)
    if clean_result is None:
        result = clean(input_path)
    else:
        result = clean_result
    proxies_list = [node.raw for node in result.nodes]

    # BUG-07: 无有效节点时明确失败,不产出空配置
    if not result.nodes:
        detail = "、".join(result.excluded_names[:10]) if result.excluded_names else ""
        raise ValueError(f"无有效节点:所有节点均缺必填认证字段被剔除{(':' + detail) if detail else ''}")

    # ipv6 auto 模式(B4 三档判定):依"是否有 IPv6 server" && "OS 是否支持"
    if prefs.ipv6 == "auto":
        has_ipv6 = any(node.is_ipv6_server for node in result.nodes)
        os_ipv6 = True  # B4 启发式:默认假设宿主 OS 支持 IPv6
        ipv6_on = has_ipv6 and os_ipv6
        # 临时覆盖 prefs 的 ipv6 字段(不修改原对象,用副本)
        from dataclasses import replace
        prefs = replace(prefs, ipv6="true" if ipv6_on else "false")
    else:
        ipv6_on = prefs.ipv6 == "true"

    # Step 1-6: 生成 6 模块(全部接受 prefs)
    basic_cfg = basic.build(prefs)
    dns_cfg = dns.build(prefs, ipv6_on=ipv6_on)
    sniffer_cfg = sniffer.build(prefs)
    providers_cfg = providers.build(prefs)
    groups_list = groups.build(result, prefs)
    # rules 需要知道哪些组存在(空组容错:fallback 到 GROUP_AUTO)
    available_groups = {g["name"] for g in groups_list}
    rules_list = rules.build(available_groups, prefs, ipv6_on=ipv6_on)

    # Step 7: 跨段命名一致性校验
    errors = _check_cross_section_consistency(
        proxies_list, groups_list, rules_list, providers_cfg, dns_cfg
    )

    # 合并 7 模块(顶层基础字段 + 6 个子段)
    final_cfg = {
        **basic_cfg,  # 顶层基础字段(mixed-port/mode/log-level 等)
        "dns": dns_cfg,
        "sniffer": sniffer_cfg,
        "proxies": proxies_list,
        "proxy-groups": groups_list,
        "rules": rules_list,
        "rule-providers": providers_cfg,
    }

    # TUN 段(仅 prefs.tun_enable 时生成)
    if prefs.tun_enable:
        final_cfg["tun"] = {
            "enable": True,
            "stack": "mixed",  # T-2: mixed 兼容性最好
            "dns-hijack": ["any:53"],  # 层1 自动补偿
            "auto-route": True,
            "auto-redirect": True,  # Linux 专用,其他 OS 自动忽略
        }

    # profile 段(store-fake-ip + tracing)
    if prefs.profile:
        final_cfg["profile"] = {
            "store-fake-ip": True,
            "tracing": True,
        }

    # 导出 YAML(block style + 保持插入顺序 + 中文不转义)
    yaml_str = yaml.dump(
        final_cfg,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )

    return yaml_str, errors


def assemble_to_file(
    input_path: str | Path,
    output_path: str | Path,
    prefs: Prefs | None = None,
) -> list[str]:
    """组装并写入文件。

    Args:
        input_path: 用户 proxies 文件路径
        output_path: 输出 final.yaml 路径
        prefs: 用户偏好(None=智能模式默认)

    Returns:
        list[str]: 跨段校验错误列表(空表示无错误)
    """
    yaml_str, errors = assemble(input_path, prefs)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(yaml_str)
    return errors
