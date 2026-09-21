"""35 红线静态校验回归测试(C4)。

覆盖 D-1/D-4/D-6/R-1/R-4/R-6/RP-4 等代表性红线 + BUG-01 修复(redir-host 不误报)。
运行:uv run pytest tests/test_check_regression.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.checker import check, parse_rule


def _report_items(config):
    r = check(config)
    return [(i.red_line, i.level) for i in r.items]


# ---- parse_rule : 逻辑规则(AND/OR/NOT)解析(P2) ----
def test_parse_rule_logical_and():
    rule = "AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT"
    kind, refs, outlet = parse_rule(rule)
    assert kind == "LOGICAL", kind
    assert refs == [], refs
    assert outlet == "REJECT", outlet


def test_parse_rule_rule_set():
    kind, refs, outlet = parse_rule("RULE-SET,private,DIRECT")
    assert kind == "RULE-SET"
    assert refs == ["private"]
    assert outlet == "DIRECT"


def test_parse_rule_normal_rule():
    kind, refs, outlet = parse_rule("DOMAIN-SUFFIX,example.com,GHOST")
    assert kind == "OTHER"
    assert refs == []
    assert outlet == "GHOST"


def test_parse_rule_two_segment_no_outlet():
    # 2 段式非逻辑规则无显式出口,不应被当出口校验(避免 R-4 误报)
    for rule in ["DOMAIN,example.com", "RULE-SET,x", "MATCH,DIRECT"]:
        kind, refs, outlet = parse_rule(rule)
        assert outlet == "", f"{rule} 不应有显式出口, got {outlet!r}"


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


# ---- D-9 : dns 代理标签(#TAG)必须指向存在的策略组/内置 ----
def test_d9_proxy_tag_missing_reported():
    cfg = {"dns": {"nameserver": ["https://8.8.8.8/dns-query#ghost"]},
           "proxies": [], "proxy-groups": [], "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "D-9" for rid, _ in items), items


def test_d9_proxy_tag_resolves_ok():
    cfg = {"dns": {"nameserver": ["https://8.8.8.8/dns-query#默认代理"]},
           "proxies": [], "proxy-groups": [{"name": "默认代理", "type": "select", "proxies": ["DIRECT"]}],
           "rules": ["MATCH,DIRECT"], "rule-providers": {}}
    items = _report_items(cfg)
    assert not any(rid == "D-9" for rid, _ in items), items


def test_d9_proxy_tag_builtin_ok():
    # 内置策略(REJECT)也允许作为标签
    cfg = {"dns": {"fallback": ["https://1.1.1.1/dns-query#REJECT"]},
           "proxies": [], "proxy-groups": [], "rules": ["MATCH,DIRECT"], "rule-providers": {}}
    items = _report_items(cfg)
    assert not any(rid == "D-9" for rid, _ in items), items


# ---- D-10 : fakeipfilter(必须真实 IP)须成对于 fake-ip-filter ----
def test_d10_policy_without_filter_reported():
    cfg = {"dns": {"enhanced-mode": "fake-ip",
                   "nameserver-policy": {"rule-set:fakeipfilter_cn": ["1.1.1.1"]},
                   "fake-ip-filter": [], "fake-ip-filter-mode": "blacklist"},
           "proxies": [], "proxy-groups": [], "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert any(rid == "D-10" for rid, _ in items), items


def test_d10_paired_ok():
    cfg = {"dns": {"enhanced-mode": "fake-ip",
                   "nameserver-policy": {"rule-set:fakeipfilter_cn": ["1.1.1.1"]},
                   "fake-ip-filter": ["rule-set:fakeipfilter_cn"], "fake-ip-filter-mode": "blacklist"},
           "proxies": [], "proxy-groups": [], "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert not any(rid == "D-10" for rid, _ in items), items


def test_d10_redir_host_skips():
    # 非 fake-ip 模式无 fake-ip-filter 概念,不触发 D-10
    cfg = {"dns": {"enhanced-mode": "redir-host",
                   "nameserver-policy": {"rule-set:fakeipfilter_cn": ["1.1.1.1"]}},
           "proxies": [], "proxy-groups": [], "rules": [], "rule-providers": {}}
    items = _report_items(cfg)
    assert not any(rid == "D-10" for rid, _ in items), items