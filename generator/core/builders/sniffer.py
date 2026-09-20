"""sniffer 段生成器(M4 三位一体之二)。

对应 plan.md Step 3 + mihomo-spec.md 第四节 S-1~S-5 红线。

关键改进(对照 ChromeGO.yaml):
- C3 修复:补 QUIC 协议嗅探
- S-3: 显式 override-destination: true(默认 true,但显式写出防漂移)
- S-4: fake-ip 模式必须开 sniffer(由 dns 段 enhanced-mode: fake-ip 触发)
- S-5: parse-pure-ip: true(纯 IP 流量强制嗅探)
- TUN 开启时强制启用 sniffer(层1 自动补偿)
"""

from __future__ import annotations

from ..prefs import Prefs


def build(prefs: Prefs) -> dict:
    """生成 sniffer 段。

    依据:
    - plan.md Step 3
    - mihomo-spec.md 第四节 S-1~S-5
    - adaptation-concerns.md C3 修复
    - prefs: TUN 开启时强制启用(层1 自动补偿)

    Args:
        prefs: 用户偏好(TUN 联动)

    Returns:
        dict: sniffer 段配置
    """
    # S-4: fake-ip 模式必须开 sniffer;TUN 开启也强制启用(层1 补偿)
    must_enable = prefs.enhanced_mode == "fake-ip" or prefs.tun_enable

    return {
        "enable": True,  # must_enable 始终为 True(fake-ip 或 TUN 任一开则必须开)
        # S-5: 对未获取到域名的流量强制嗅探(处理直接以 IP 访问的应用)
        "parse-pure-ip": True,
        # S-3: 显式写出(默认 true,用嗅探结果覆盖目标)
        # redir-host 模式下 override-destination 无副作用,保持 true
        "override-destination": True,
        # S-1: 仅 HTTP/TLS/QUIC(禁止编造其他协议)
        "sniff": {
            "HTTP": {
                # S-2: 端口范围用 list 语法
                "ports": [80, 8080, 8880, 2052, 2082, 2086, 2095],
            },
            "TLS": {
                "ports": [443, 8443, 2053, 2083, 2087, 2096],
            },
            # C3 修复:补 QUIC 嗅探(ChromeGO.yaml 缺失)
            "QUIC": {"ports": [443]},
        },
        # 跳过可能误伤的域名(米家云)
        "skip-domain": ["Mijia Cloud"],
    }
