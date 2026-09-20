# clash-generator

Clash/Mihomo 配置生成器：接受用户代理节点文件（`proxies:`），自动补全其余段（basic/dns/sniffer/proxy-groups/rules/rule-providers），组装成**适配度 10/10** 的完整 Clash YAML，并提供 Windows GUI 与 CLI。

## 能力

- **多格式鲁棒输入**：支持 `.yaml` / `.yml` / `.json` / `.txt`；内部级联解析（严格 JSON → 去尾随逗号再 JSON → YAML 兜底），容忍手写不规范 JSON（含尾随逗号、BOM、单引号、未加引号键）。
- **35 红线静态校验 + `mihomo -t` 动态验证**：对 clash 核心规则零错误承诺。
- **智能/进阶双模式**：智能模式用内置最佳实践；进阶模式开放选项（`enhanced-mode` 支持 fake-ip/redir-host、`custom_rulesets` 自定义规则集、`grouping_strategy`、`rule_template`、IPv6 三档判定 + v6 兜底规则等），全程"提示而非拦截"。
- **P-2 校验**：缺必填认证字段的节点自动剔除并记录，杜绝无效节点静默出口。

## 核心原则

1. **对 clash 核心规则不能有丝毫错误** — 35 红线静态校验 + `mihomo -t -f` 动态验证
2. **进阶用户知情赋能** — 提示而非拦截；硬红线导出二次确认

## 快速开始

```powershell
# 1) 同步依赖(单 .venv + uv.lock 锁版本,已配清华镜像)
uv sync

# 2a) 启动 GUI
uv run python main.py

# 2b) CLI 生成(final.yaml 默认写当前目录;存在硬红线时默认不写盘,--force 覆盖)
uv run python main.py --cli --input proxies.txt --output final.yaml

# 3) 运行测试(pytest 回归)
uv run pytest tests/
```

## 项目结构

```
clash-generator/
├── generator/
│   ├── core/                  # 核心生成逻辑(与 GUI 解耦)
│   │   ├── builders/          # 6 模块生成器(basic/dns/sniffer/providers/groups/rules)
│   │   ├── cleaner.py         # 输入清洗 + 多格式鲁棒解析 + P-2 剔除
│   │   ├── analyzer.py        # 节点画像 + 分组建议
│   │   ├── assembler.py       # 组装 7 段 + 跨段命名一致性校验
│   │   ├── checker.py         # 35 红线静态校验
│   │   ├── verifier.py        # mihomo 动态验证(-t)
│   │   ├── prefs.py           # 用户偏好(智能/进阶双模式)
│   │   └── models.py          # 节点/清洗结果等数据模型
│   └── gui/                   # PySide6 GUI
│       ├── main_window.py     # 主窗(信号路由)
│       ├── workers.py         # QThread 后台流水线
│       ├── state.py           # 会话状态
│       └── widgets/           # 导入/偏好/预览/报告 4 面板
├── tests/                     # pytest 回归 + M1-M8 端到端脚本
├── assets/                    # 图标 + 版本信息
├── main.py                    # 入口(GUI/CLI/--version)
├── build.spec                 # PyInstaller 配置
├── build.bat                  # 一键打包(uv sync 单 venv)
├── GIT_WORKFLOW_TEMPLATE.md   # Git Flow 分支流程模板
├── pyproject.toml             # uv 管理(依赖 + dev)
└── uv.lock                    # 依赖锁定
```

## 里程碑

| # | 里程碑 | 状态 |
|---|---|---|
| M1-M8 | 骨架→清洗→画像→构建→组装→校验→动态验证→端到端 | ✅ 完成 |
| S13 | 打包(greenfield 单文件 EXE) | ✅ `release\ClashGenerator.exe`(≈40MB) |
| 部署 | 发布 GitHub | ✅ `main`/`develop`/`release/v1.0.0` + tag `v1.0.0` |

## 打包

```powershell
build.bat          # 完整打包(uv sync 单 .venv → PyInstaller)
build.bat /fast    # 复用已有 .venv,跳过同步
```

产物：`release\ClashGenerator.exe`（绿色免安装，双击即用）。

## 设计文档

详见 `../tasks/` 目录（项目决策与实现记录）：
- `mihomo-spec.md` — 35 红线真理源（官方 wiki 核验）
- `plan.md` — 7 步生成流程
- `tech-stack.md` — 技术栈与架构
- `options-risk-matrix.md` — 进阶选项风险矩阵
- `todo-bugs.md` / `todo.md` — 全链路审查缺陷清单与修复/增强计划

## 依赖

- Python >= 3.10
- PySide6 ~= 6.6.0（GUI）
- PyYAML ~= 6.0.1（YAML/JSON 解析）
- dev：PyInstaller ~= 6.3.0（打包）、pytest >= 9.1.1（回归测试）