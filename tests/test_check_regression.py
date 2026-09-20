"""35 红线静态校验回归测试(C4)。

覆盖 D-1/D-4/D-6/R-1/R-4/R-6/RP-4 等代表性红线 + BUG-01 修复(redir-host 不误报)。
运行:uv run pytest tests/test_check_regression.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.checker import check


def _report_items(config):
    r = check(config)
    return [(i.red_line, i.level) for i in r.items]


# ---- D-1 ----
def test_d1_redir_host_is_legal():
    # BUG-01: redir-host 是合法模式,不应报 D-1/D-4
    cfg = {"dns": {"enhanced-mode": "redir-host"}, "proxies": [], "proxy-groups": [],
           "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert not any(rid == "D-1" for rid, _ in items), items


def test_d1_invalid_mode_reported():
    cfg = {"dns": {"enhanced-mode": "bogus"}, "proxies": [], "proxy-groups": [],
           "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "D-1" for rid, _ in items), items


# ---- D-4 ----
def test_d4_fakeip_missing_filter_mode_reported():
    cfg = {"dns": {"enhanced-mode": "fake-ip"}, "proxies": [], "proxy-groups": [],
           "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "D-4" for rid, _ in items), items


def test_d4_fakeip_blacklist_ok():
    cfg = {"dns": {"enhanced-mode": "fake-ip", "fake-ip-filter-mode": "blacklist"},
           "proxies": [], "proxy-groups": [], "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert not any(rid == "D-4" for rid, _ in items), items


def test_d4_redir_host_skips_filter_check():
    # BUG-01: redir-host 下无 fake-ip-filter-mode 不应报 D-4
    cfg = {"dns": {"enhanced-mode": "redir-host"}, "proxies": [], "proxy-groups": [],
           "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert not any(rid == "D-4" for rid, _ in items), items


# ---- D-6 / R-2 : rule-set 引用必须在 providers ----
def test_d6_nameserver_policy_requires_provider():
    cfg = {"dns": {"nameserver-policy": {"rule-set:nope": ["1.1.1.1"]}},
           "proxies": [], "proxy-groups": [], "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "D-6" for rid, _ in items), items


def test_r2_ruleset_reference_requires_provider():
    cfg = {"dns": {}, "proxies": [], "proxy-groups": [],
           "rules": ["RULE-SET,ghost,DIRECT"], "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "R-2" for rid, _ in items), items


# ---- R-1 : MATCH 唯一且最后 ----
def test_r1_match_must_be_unique_and_last():
    cfg = {"dns": {}, "proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"],
           "rule-providers": {}}
    assert not any(rid == "R-1" for rid, _ in _report_items(cfg))
    cfg2 = {"dns": {}, "proxies": [], "proxy-groups": [],
            "rules": ["MATCH,DIRECT", "MATCH,DIRECT"], "rule-providers": {}}
    assert any(rid == "R-1" for rid, _ in _report_items(cfg2))


# ---- R-4 : 规则出口必须存在 ----
def test_r4_outlet_must_exist():
    cfg = {"dns": {}, "proxies": [], "proxy-groups": [{"name": "G", "type": "select", "proxies": ["DIRECT"]}],
           "rules": ["DOMAIN-SUFFIX,example.com,GHOST"], "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "R-4" for rid, _ in items), items


# ---- R-6 : GEOIP 必须带 no-resolve ----
def test_r6_geoip_no_resolve():
    cfg = {"dns": {}, "proxies": [], "proxy-groups": [{"name": "G", "type": "select", "proxies": ["DIRECT"]}],
           "rules": ["GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", "MATCH,DIRECT"],
           "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "R-6" for rid, _ in items), items


# ---- RP-4 : mrs + classical 禁止;RP-3b : format/content 矛盾 ----
def test_rp4_mrs_classical_forbidden():
    cfg = {"dns": {}, "proxies": [], "proxy-groups": [],
           "rules": [],
           "rule-providers": {"x": {"type": "http", "format": "mrs", "behavior": "classical", "url": "https://a/x.mrs"}}}
    items = _report_items(cfg)
    assert any(rid == "RP-4" for rid, _ in items), items


def test_rp3b_mrs_text_url_contradiction():
    cfg = {"dns": {}, "proxies": [], "proxy-groups": [],
           "rules": [],
           "rule-providers": {"x": {"type": "http", "format": "mrs", "behavior": "domain", "url": "https://a/x.txt"}}}
    items = _report_items(cfg)
    assert any(rid == "RP-3b" for rid, _ in items), items