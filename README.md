# clash-generator

Clash/Mihomo 配置生成器:接受用户 `proxies:` 节点文件(如 chromego.txt),自动补全其余 6 段(basic/dns/sniffer/proxy-groups/rules/rule-providers),组装成适配度 > 7.5/10(目标 9/10)的完整 Clash YAML。

## 核心原则

1. **对 clash 核心规则不能有丝毫错误** — 35 红线静态校验 + mihomo -t -f 动态验证
2. **进阶用户知情赋能** — 提示而非拦截

## 快速开始

```powershell
# 同步依赖(使用清华源)
uv sync

# 运行(M1 骨架)
uv run python main.py

# 查看版本
uv run python main.py --version
```

## 项目结构

```
clash-generator/
├── generator/
│   ├── core/                  # 核心生成逻辑(与 GUI 解耦)
│   │   ├── builders/          # 6 模块生成器
│   │   ├── cleaner.py         # M2: 输入清洗
│   │   ├── analyzer.py        # M3: 节点画像
│   │   ├── assembler.py       # M5: 组装
│   │   ├── checker.py         # M5: 35 红线静态校验
│   │   └── verifier.py        # M6: mihomo 动态验证
│   ├── gui/                   # M7: PySide6 GUI 壳
│   │   └── widgets/           # 4 面板
│   └── templates/             # 固定配置模板
├── main.py                    # 入口
└── pyproject.toml             # uv 管理
```

## 里程碑路线

| # | 里程碑 | 状态 |
|---|---|---|
| M1 | 项目骨架 | ✅ |
| M2 | 数据模型 + 输入清洗 | ⏳ |
| M3 | 节点画像 + 基础模块 | ⏳ |
| M4 | 三位一体模块(dns/sniffer/rules/groups) | ⏳ |
| M5 | 组装器 + 35 红线静态校验 | ⏳ |
| M6 | 动态验证(mihomo -t) | ⏳ |
| M7 | GUI 壳 | ⏳ |
| M8 | 端到端验收 | ⏳ |

## 设计文档

详见 `../tasks/` 目录:
- `mihomo-spec.md` — 35 红线真理源(官方 wiki 核验)
- `plan.md` — 7 步生成流程 + YAML 骨架
- `tech-stack.md` — 技术栈与项目结构
- `options-risk-matrix.md` — 进阶选项风险矩阵

## 依赖

- Python >= 3.10
- PySide6 ~= 6.6.0 (GUI)
- PyYAML ~= 6.0.1 (YAML 解析)
- PyInstaller ~= 6.3.0 (dev,后续 exe 打包)
