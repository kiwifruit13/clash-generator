"""动态验证器(M6)。

调用本地 mihomo -t -f final.yaml 进行真实启动测试。
解析输出,定位错误。

对应 scheme-gap-analysis.md G4 简化方案:
- 不内置 mihomo 内核(用户需自行安装并加入 PATH)
- 调用 mihomo -t -f 进行语法 + 配置测试
- 解析输出,提取错误位置

mihomo 安装:https://github.com/MetaCubeX/mihomo/releases
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


def find_mihomo() -> str | None:
    """查找 mihomo 可执行文件。

    搜索顺序:
    1. 标准 PATH (mihomo/mihomo.exe/clash-meta/clash-meta.exe)
    2. Clash Party 常见安装路径 (E:\\VPN\\clash\\resources\\sidecar\\ 等)
    3. 常见 Clash 客户端路径

    Returns:
        mihomo 路径,未找到返回 None
    """
    # 1. PATH 搜索
    path_names = ("mihomo", "mihomo.exe", "clash-meta", "clash-meta.exe")
    for name in path_names:
        path = shutil.which(name)
        if path:
            return path

    # 2. Clash Party / Clash Verge / Mihomo Party 常见安装路径
    known_paths = [
        # Clash Party (桌面快捷方式解析出的路径)
        r"E:\VPN\clash\resources\sidecar\mihomo.exe",
        r"E:\VPN\clash\resources\sidecar\mihomo-smart.exe",
        r"E:\VPN\clash\resources\sidecar\mihomo-alpha.exe",
        # 常见安装盘符
        r"D:\VPN\clash\resources\sidecar\mihomo.exe",
        r"D:\Clash\resources\sidecar\mihomo.exe",
        # Clash Verge / Verge Rev
        r"C:\Program Files\Clash Verge\resources\mihomo.exe",
        r"C:\Program Files\Clash Verge Rev\resources\mihomo.exe",
        r"%LOCALAPPDATA%\Programs\Clash Verge\resources\mihomo.exe",
        # 用户目录安装
        str(Path.home() / "AppData" / "Roaming" / "clash-verge" / "mihomo.exe"),
        str(Path.home() / "scoop" / "shims" / "mihomo.exe"),
        str(Path.home() / "scoop" / "apps" / "mihomo" / "current" / "mihomo.exe"),
        # 便携版路径
        str(Path.home() / "tools" / "mihomo" / "mihomo.exe"),
    ]
    import os
    for p in known_paths:
        p_expanded = os.path.expandvars(p)
        if Path(p_expanded).is_file():
            return str(Path(p_expanded).resolve())

    return None


def verify(
    config_path: str | Path,
    timeout: int = 30,
    geodata_dir: str | Path | None = None,
) -> "VerifyResult":
    """调用 mihomo -t -f 验证配置。

    Args:
        config_path: final.yaml 路径
        timeout: 超时秒数(默认 30)
        geodata_dir: geodata 目录(含 GeoSite.dat/GeoIP.dat);None=不指定,
            mihomo 会尝试从默认路径加载或按 geox-url 下载

    Returns:
        VerifyResult: 验证结果
    """
    mihomo = find_mihomo()
    if not mihomo:
        return VerifyResult(
            success=False,
            output="",
            error="mihomo 未安装或不在 PATH 中。请从 https://github.com/MetaCubeX/mihomo/releases 下载并加入 PATH。",
        )

    # 构建命令:有 geodata_dir 时加 -d 指定工作目录
    cmd = [mihomo, "-t", "-f", str(config_path)]
    if geodata_dir:
        cmd.extend(["-d", str(geodata_dir)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout or "") + (result.stderr or "")

        # mihomo -t 成功标志(更鲁棒):
        # 同时满足: 1) returncode=0 或 输出含 "test is successful"
        success_markers = (
            result.returncode == 0,
            "test is successful" in output,
            "Test successful" in output,
        )
        if any(success_markers):
            return VerifyResult(success=True, output=output, error="")

        # 失败时解析错误位置
        errors = _parse_errors(output)
        return VerifyResult(
            success=False,
            output=output,
            error=errors or "mihomo -t 测试失败(未找到明确错误信息)",
        )

    except subprocess.TimeoutExpired:
        return VerifyResult(
            success=False, output="", error=f"mihomo -t 超时({timeout}s)"
        )
    except FileNotFoundError:
        return VerifyResult(
            success=False, output="", error="mihomo 可执行文件不存在"
        )
    except Exception as e:
        return VerifyResult(success=False, output="", error=f"mihomo 调用异常:{e}")


def _parse_errors(output: str) -> str:
    """从 mihomo 输出中解析错误信息。

    mihomo 错误格式示例:
        level=fatal msg="..." 或
        FATAL[xxx] ...
    """
    # 匹配 level=fatal/error msg="..."
    fatal_matches = re.findall(
        r'level=(?:fatal|error)\s+msg="([^"]+)"', output
    )
    if fatal_matches:
        return "\n".join(f"- {m}" for m in fatal_matches)

    # 匹配 FATAL[...] ...
    fatal_lines = [
        line for line in output.splitlines()
        if line.startswith("FATAL") or "fatal" in line.lower()
    ]
    if fatal_lines:
        return "\n".join(fatal_lines[:10])

    return ""


class VerifyResult:
    """验证结果。"""

    def __init__(self, success: bool, output: str, error: str):
        self.success = success
        self.output = output
        self.error = error

    def __repr__(self) -> str:
        status = "✅ 通过" if self.success else "❌ 失败"
        return f"VerifyResult({status})"
