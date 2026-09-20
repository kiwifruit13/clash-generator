"""basic 段生成器(M3)。

对应 plan.md Step 6 + mihomo-spec.md 第二节顶层字段红线。

输出依赖 prefs(智能模式默认值 = 原固定模板),包含:
- mixed-port / allow-lan / bind-address / mode / log-level
- ipv6 / unified-delay / tcp-concurrent
- external-controller / secret
"""

from __future__ import annotations

from ..prefs import Prefs


def build(prefs: Prefs) -> dict:
    """生成 basic 段。

    依据:
    - plan.md Step 6
    - mihomo-spec.md 第二节(mode/log-level enum 红线)
    - prefs: 用户偏好(智能模式默认 = 原固定模板)

    Args:
        prefs: 用户偏好(基础组 6 选项)

    Returns:
        dict: 顶层基础字段
    """
    return {
        "mixed-port": prefs.mixed_port,
        "allow-lan": prefs.allow_lan,
        "bind-address": "*",
        "mode": "rule",  # G-2 红线:仅 rule/global/direct(不开放修改)
        "log-level": prefs.log_level,  # G-2 红线:仅 silent/error/warning/info/debug
        # ipv6: auto 依节点画像(此处无画像信息,保持 False;assembler 会用 effective_ipv6 覆盖)
        "ipv6": prefs.ipv6 == "true",
        "unified-delay": True,
        "tcp-concurrent": True,
        "external-controller": prefs.external_controller,
        "secret": prefs.secret,
        # geodata 配置(修复 GeoSite.dat 下载/格式问题)
        # 关键:必须用 MetaCubeX/meta-rules-dat(非 Loyalsoldier/v2ray-rules-dat)
        # 原因:Mihomo 使用 meta 格式的 .dat 文件,v2ray 格式可能导致解码失败
        "geodata-mode": True,  # 使用 .dat 格式(非 mmdb)
        "geo-auto-update": True,  # 自动更新 geodata
        "geo-update-interval": 168,  # 7 天更新一次(小时)
        "geox-url": {
            # 优先使用 jsDelivr CDN(国内访问友好)
            "geosite": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
            "geoip": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
            # mmdb 用于 GEOIP 规则(若使用 .dat 格式则不强制需要)
            "mmdb": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
        },
    }
