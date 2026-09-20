# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 配置 — Clash Generator 绿色免安装版。

特性：
  - 单文件 EXE，无需安装，双击即用
  - 无控制台窗口（纯 GUI）
  - 内嵌应用图标

使用：
  pyinstaller build.spec
"""

from pathlib import Path

project_root = Path(SPECPATH)
icon_path = project_root / "assets" / "app.ico"
version_path = project_root / "assets" / "version.txt"

# 隐式导入（PySide6 动态加载的模块）
hidden_imports = [
    "yaml",
    "generator",
    "generator.core",
    "generator.core.builders",
    "generator.core.builders.basic",
    "generator.core.builders.dns",
    "generator.core.builders.groups",
    "generator.core.builders.providers",
    "generator.core.builders.rules",
    "generator.core.builders.sniffer",
    "generator.core.analyzer",
    "generator.core.assembler",
    "generator.core.checker",
    "generator.core.cleaner",
    "generator.core.models",
    "generator.core.prefs",
    "generator.core.verifier",
    "generator.gui",
    "generator.gui.widgets",
    "generator.gui.widgets.import_panel",
    "generator.gui.widgets.prefs_panel",
    "generator.gui.widgets.preview_panel",
    "generator.gui.widgets.report_panel",
    "generator.gui.app",
    "generator.gui.main_window",
    "generator.gui.state",
    "generator.gui.workers",
]

a = Analysis(
    ['main.py'],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(project_root / "assets" / "app.ico"), "assets"),
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtMultimedia",
        "PySide6.QtSql",
        "PySide6.QtNetwork",
        "PySide6.QtOpenGL",
        "PySide6.QtOpenGLWidgets",
        "PySide6.QtQuick",
        "PySide6.QtQuickControls2",
        "PySide6.QtCharts",
        "PySide6.QtDataVisualization",
        "PySide6.QtMultimediaWidgets",
        "PySide6.QtPositioning",
        "PySide6.QtPrintSupport",
        "PySide6.QtTest",
        "PySide6.QtTextToSpeech",
        "PySide6.Qt3DCore",
        "PySide6.Qt3DRender",
        "PySide6.Qt3DAnimation",
        "PySide6.Qt3DInput",
        "PySide6.Qt3DLogic",
        "PySide6.Qt3DExtras",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ClashGenerator",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(icon_path),
    version=str(version_path),
)
