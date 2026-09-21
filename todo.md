# Todo：000.txt 完美适配实施计划

> 目标：把 `000.txt` 的可取特性无逻辑跳跃地并入本项目。已分两阶段。
> **第一阶段（已完成）**：自包含 dns 项。**第二阶段（本文档）**：三项"独立规格"（P1/P2/P3）。
>
> 铁律（贯穿全程）：
> 1. **不省略关键实现环节** —— 每任务显式列出：前置依赖 → 改动文件/函数 → 实现要点 → 验收标准。
> 2. **默认 = 智能模式**：`Prefs.smart()` 输出与升级后基线一致；新开关默认关 → 默认输出零变化。
> 3. **跨段一致性校验不破**（`assembler._check_cross_section_consistency` / `checker`）。
> 4. **不破坏 loyalsoldier 唯一源不变式**（除非 P3 明确 opt-in）。

---

## 第一阶段（已完成 ✅）
- [x] D1 决策矩阵（10 项：默认/参数化/独立规格）
- [x] Prefs 新增 dns 字段 + `__post_init__` 校验
- [x] dns.py 落地 `cache-algorithm` / `fake-ip-ttl` / `disable-qtype-65` / `ecs`（按 000.txt 海外模式）/ `fallback+filter`
- [x] test_prefs.py 断言更新 + 回归（27 passed）

---

## 调研落档（第二阶段前置 · 2026-09-21）
- [x] **AND() 逻辑规则**：mihomo 官方支持 NOT/OR/AND + NETWORK(TCP/UDP) + DST-PORT。社区标准 QUIC 拦截用**取非国内**：
  ```
  AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT
  ```
  本项目已用 `GEOSITE,cn` → **自包含，零新增规则集**。
- [x] **`cn_domain`/`cn!_domain`** ← MetaCubeX `meta-rules-dat`（mrs，behavior=domain）：
  `.../meta/geo/geosite/cn.mrs` 与 `geolocation-!cn.mrs`
- [x] **`fakeipfilter_cn`/`fakeipfilter_!cn`** ← 社区仓库 qichiyuhub/rule（text `.list`），须在 `fake-ip-filter` 与 `nameserver-policy` **成对维护**。
- [x] **`#默认代理` 标签**：`nameserver/fallback` 条目 `url#TAG&param`（TAG 位于 `#` 与首个 `&` 之间），有效。

---

## 第二阶段：P1 `#默认代理` 代理标签 ✅（已完成）

> 让境外 DNS 查询走代理、防污染。默认 `""` = 关，零输出变化。

- [x] **P1-1 字段**（[prefs.py](file:///c:/Users/kiwif/Documents/clash-generator-main/generator/core/prefs.py)）
  - DNS 组新增 `dns_proxy_tag: str = ""`（空=关闭）。
  - **验收**：`Prefs.smart()` 构造成功、默认空串。

- [x] **P1-2 生成**（[dns.py](file:///c:/Users/kiwif/Documents/clash-generator-main/generator/core/builders/dns.py)）
  - 当 `dns_proxy_tag` 非空时，对 `foreign_doh`（nameserver 与 fallback）条目追加 `#<tag>`。
  - **注意**：追加在既有 `&ecs=...` 之后 → 形如 `https://8.8.8.8/dns-query&ecs=223.5.5.0/24#默认代理`。与 000.txt 的 `#默认代理&disable-qtype-65` 顺序不同（其 tag 在前），需明确 tag 解析器取法为"`#` 后、首个 `&` 前" —— 校验器与此保持一致即可。
  - **验收**：tag 开时 nameserver/fallback 含 `#<tag>`；关时无。

- [x] **P1-3 跨段校验扩展**（[assembler.py](file:///c:/Users/kiwif/Documents/clash-generator-main/generator/core/assembler.py) + [checker.py](file:///c:/Users/kiwif/Documents/clash-generator-main/generator/core/checker.py)）
  - 公共解析 helper `_extract_dns_proxy_tags(urls) -> set[str]`：对每条 `#` 后取 TAG。
  - 在 assembler 与 checker 中对其校验：TAG ∈ (group_names ∪ BUILT_IN)，否则报错。
  - **关键实现环节**（防"标签过期→解析器被静默丢弃"）：必须新增此校验，不能只生成不验证。
  - **验收**：tag 指向不存在组 → 报错；指向已有组/内置 → 通过。

- [x] **P1-4 测试**（[test_prefs.py](file:///c:/Users/kiwif/Documents/clash-generator-main/tests/test_prefs.py)）
  - tag 开/关、跨段通过/报错用例。
  - **验收**：`uv run pytest tests/ -q` 全绿。

---

## 第二阶段：P2 `AND()` QUIC 拦截 ✅（已完成）

> 掐海外 UDP 443，逼浏览器回退 TCP，解决视频卡顿。使用官方标准形式，不引入第三方集。

- [x] **P2-1 字段**：prefs 新增 `enable_quic_reject: bool = False`。

- [x] **P2-2 规则解析器重构（前置，必须先做）**
  - 现有 `checker.R-2/R-4` 与 `assembler._check_cross_section_consistency` 用朴素 `split(",")[1]/[2]` 解析规则，**对 `AND,(AND,...` 会错拆**（如 `parts[1]` 拿到 `((AND`），必须先抽出公共 `_parse_rule(rule)`：
    - 识别 `AND,`/`OR,`/`NOT,` 前缀；
    - 提取其中引用的 `RULE-SET,<name>` 与外层出口（末段）。
  - 落到 checker/assembler 共用（可放 `rules.py` 或新 helper）。
  - **验收**：`_parse_rule("AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT")` 返回出口 `REJECT`、无 RULE-SET 引用。

- [x] **P2-3 规则生成**（[rules.py](file:///c:/Users/kiwif/Documents/clash-generator-main/generator/core/builders/rules.py)）
  - `enable_quic_reject` 为真时，在 **reject 之后**插入：
    `AND,(AND,(DST-PORT,443),(NETWORK,UDP)),(NOT,((GEOSITE,cn))),REJECT`（避免 R-5 `reject 应最前` 回归）。
  - **验收**：开时首条仍为 `ruLE-SET,reject,...`（R-5 不报）；关时无此规则。

- [x] **P2-4 测试**：开/关用例 + `_parse_rule` 单测 + R-5 不回归断言。

---

## 第二阶段：P3 `_cn/_!cn` 源 ✅（已完成；C 明确不启用）

> 最精细但架构代价最高。**单声明驱动成对注入**，避免半改 bug。

- [x] **P3-1 归档 opt-in 源清单**：fakeipfilter_cn / fakeipfilter_!cn ← qichiyuhub **text**。
- [x] **P3-3 成对注入机制**：同一声明驱动 `fake-ip-filter` + `nameserver-policy`，加 D-10 跨段强校验。
- [x] **P3-4 决策门**：fakeipfilter 作为 opt-in（`enable_fakeip_filter`，默认关），不加入 `VALID_RULESET_SOURCES`；**未触碰 mrs / loyalsoldier 唯一源默认不变式**。
- [ ] **P3-2 mrs 回退（C）**：`cn_domain/cn!_domain` 需重开 mrs —— **明确不启用**，避免回退 `BUG-02` 收敛决策。如需极细粒度规则分流再单独议。

---

## 依赖关系速览
```
P1-1 ─▶ P1-2 ─▶ P1-3(校验) ─▶ P1-4(测试)
P2-1 ─▶ P2-2(解析器重构,必须先) ─▶ P2-3(生成) ─▶ P2-4(测试)
P3-1 ─▶ P3-2(决策) ─▶ P3-3 ─▶ P3-4(决策门)   [独立,opt-in]
最后: 全量回归 + CLI 冒烟
```

## 待确认（已收敛）
1. P1 的 tag 落在 nameserver/fallback —— **已定**：按 000.txt 落在海外 nameserver/fallback。
2. P3-2 是否重开 mrs —— **已定**：不启用（避免回退 `BUG-02`）；fakeipfilter 走 text opt-in。