"""cleaner 输入鲁棒性测试(JSON 级联解析 + 尾随逗号 + BOM + txt 承载类 JSON)。

运行:uv run pytest tests/test_cleaner_robust.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from generator.core.cleaner import _strip_trailing_commas, clean


def test_json_trailing_comma_json_suffix(tmp_path):
    # 521.json 类:数组末尾尾随逗号 -> 走"修复尾随逗号再 JSON"
    p = tmp_path / "a.json"
    p.write_text('{"proxies": [{"name": "n1", "type": "ss", "server": "1.1.1.1", "port": 8388, "password": "x"},]}',
                 encoding="utf-8")
    r = clean(p)
    assert [n.name for n in r.nodes] == ["n1"]


def test_txt_containing_nonstandard_json(tmp_path):
    # .txt 内容是带尾随逗号的类 JSON -> 同样级联解析成功
    p = tmp_path / "rules.txt"
    p.write_text('{ "proxies": [ { "name": "a", "type": "trojan", "server": "2.2.2.2", "port": 443, "password": "p", "sni": "x" }, ] }',
                 encoding="utf-8")
    r = clean(p)
    assert [n.name for n in r.nodes] == ["a"]


def test_txt_containing_strict_json(tmp_path):
    # .txt 内容是严格 JSON -> 严格 json 解析
    p = tmp_path / "data.txt"
    p.write_text('{"proxies": [{"name": "s1", "type": "vmess", "server": "3.3.3.3", "port": 443, "uuid": "u"}]}',
                 encoding="utf-8")
    r = clean(p)
    assert [n.name for n in r.nodes] == ["s1"]


def test_json_with_bom(tmp_path):
    # BOM 前缀 + 尾随逗号的 JSON -> 正常解析
    p = tmp_path / "bom.json"
    p.write_bytes('\ufeff{"proxies": [{"name": "n", "type": "ss", "server": "1.2.3.4", "port": 8388, "password": "x"},]}'.encode("utf-8"))
    r = clean(p)
    assert [n.name for n in r.nodes] == ["n"]


def test_unquoted_keys_yaml_fallback(tmp_path):
    # 未加引号键/单引号的类 JSON(.txt) -> YAML 兜底
    p = tmp_path / "loose.txt"
    p.write_text("proxies:\n  - name: m1\n    type: ss\n    server: 9.9.9.9\n    port: 8388\n    password: 'z'\n",
                 encoding="utf-8")
    r = clean(p)
    assert [n.name for n in r.nodes] == ["m1"]


def test_strip_trailing_commas_keeps_string_commas():
    # 状态机:字符串内部的引号/逗号不被误删
    src = '{"k": "a,b",  "arr": [1,2,], "nested": {"x": "},", "y": 1,}}'
    ver = '{"k": "a,b",  "arr": [1,2], "nested": {"x": "},", "y": 1}}'
    assert _strip_trailing_commas(src) == ver