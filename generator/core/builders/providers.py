"""rule-providers 段生成器(M3)。

对应 plan.md Step 5 + mihomo-spec.md 第九节 RP-1~RP-7 红线。

修复 C10:显式 format: text(Loyalsoldier .txt 文件实际为 text 格式,
mihomo 默认 format: yaml,不显式写出会导致解析错误)。

性能优化(v1.1):
- 统一接口签名:build(prefs: Prefs) -> dict(移除可选参数)

prefs 支持:
- ruleset_source: loyalsoldier(默认)/sukkaw/quixoticheart
- enable_apple/icloud/google: 规则集开关
- mrs_format: 强制 mrs 格式(需源支持)
"""

from __future__ import annotations

from ..prefs import Prefs

# Loyalsoldier 规则集清单
# 依据:plan.md Step 5 + adaptation-concerns.md C10 修复方案
# 每个规则集 behavior 均为 domain(RP-2:最快,不触发 DNS)
_LOYALSOLDIER_SETS: list[str] = [
    "reject",  # 广告拦截
    "private",  # 私有网络
    "direct",  # 国内直连
    "proxy",  # 代理域名
    "apple",  # Apple 服务
    "icloud",  # iCloud
    "google",  # Google
]

_BASE_URL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release"
_INTERVAL = 86400  # 24 小时(RP-6)

# 可被 prefs 开关控制的规则集
_OPTIONAL_SETS = {"apple", "icloud", "google"}


def build(prefs: Prefs) -> dict:
    """生成 rule-providers 段。

    性能优化(v1.1):prefs 改为必填参数(原可选,默认为 Prefs.smart())。

    依据:
    - plan.md Step 5
    - mihomo-spec.md 第九节 RP-1~RP-7
    - adaptation-concerns.md C10(显式 format: text)
    - prefs: 规则集开关 + 源切换 + mrs 格式

    Args:
        prefs: 用户偏好(必填,不可为 None)

    Returns:
        dict: rule-providers 段,key 为规则集名,value 为属性 dict
    """

    # 确定格式:恒为 text(源固定 loyalsoldier;BUG-02 修复,移除 mrs_format 假联动)
    fmt = "text"

    # 依据 prefs 过滤可选规则集
    enabled_sets: list[str] = []
    for name in _LOYALSOLDIER_SETS:
        if name == "apple" and not prefs.enable_apple:
            continue
        if name == "icloud" and not prefs.enable_icloud:
            continue
        if name == "google" and not prefs.enable_google:
            continue
        enabled_sets.append(name)

    providers: dict[str, dict] = {}
    for name in enabled_sets:
        providers[name] = {
            "type": "http",  # RP-1:http/file/inline
            "behavior": "domain",  # RP-2:domain/ipcidr/classical
            "format": fmt,  # RP-3:显式 text(修复 C10)
            "url": f"{_BASE_URL}/{name}.txt",
            "path": f"./ruleset/{name}.txt",  # RP-5:统一 ./ruleset/ 相对路径
            "interval": _INTERVAL,  # RP-6:秒
        }

    # B2 增强:合并用户自定义规则集(声明式外链,纯追加到 providers)
    if prefs.custom_rulesets:
        for item in prefs.custom_rulesets:
            name = str(item.get("name", "")).strip()
            url = str(item.get("url", "")).strip()
            if not name or not url:
                continue  # 缺 name/url 的自定义项跳过(可后续加校验)
            defaults = {
                "type": "http",
                "behavior": item.get("behavior", "domain"),
                "format": item.get("format", "text"),
                "url": url,
                "path": f"./ruleset/{name}.txt",
                "interval": item.get("interval", _INTERVAL),
            }
            # 不允许与内置规则集重名(防覆盖)
            if name not in providers:
                providers[name] = defaults
    return providers
