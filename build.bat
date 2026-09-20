@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM ============================================================
REM  Clash Generator — 绿色免安装版打包脚本
REM ============================================================
REM  功能: uv sync 单 venv(.venv) → PyInstaller 打包
REM  产物: release\ClashGenerator.exe(绿色免安装,双击即用)
REM  要求: 已安装 uv(https://docs.astral.sh/uv/)
REM
REM  D9 约定: 复用单一 .venv + uv.lock 锁版本,不再创建第二个 .build_venv。
REM
REM  使用:
REM    build.bat          完整打包(uv sync 同步依赖)
REM    build.bat /fast    快速打包(跳过依赖同步,复用已有 .venv)
REM ============================================================

cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║       Clash Generator — Windows 便携版打包          ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

REM === 检查 uv ===
where uv >nul 2>&1
if errorlevel 1 (
    echo  [错误] 未找到 uv,请先安装: https://docs.astral.sh/uv/getting-started/installation/
    pause
    exit /b 1
)
echo  [环境] uv 已就绪

REM === 检查资源文件 ===
if not exist "assets\app.ico" (
    echo  [错误] 缺少图标文件: assets\app.ico
    pause
    exit /b 1
)
if not exist "assets\version.txt" (
    echo  [错误] 缺少版本信息文件: assets\version.txt
    pause
    exit /b 1
)
if not exist "build.spec" (
    echo  [错误] 缺少 PyInstaller 配置: build.spec
    pause
    exit /b 1
)
echo  [环境] 资源与配置完整

REM === 步骤 1: 同步依赖(单 .venv,依 uv.lock) ===
echo.
echo  [1/4] 同步依赖 uv sync(单 .venv)...

if /i "%~1"=="/fast" (
    echo        /fast 模式: 跳过依赖同步,复用现有 .venv
    if not exist ".venv\Scripts\pyinstaller.exe" (
        echo  [错误] .venv 缺少 pyinstaller,请先不带 /fast 完整打包一次
        pause
        exit /b 1
    )
    goto :skip_sync
)

uv sync
if errorlevel 1 (
    echo  [错误] uv sync 失败,请检查网络或 uv.lock
    pause
    exit /b 1
)
echo        依赖同步完成.venv = 单 venv

:skip_sync
if not exist ".venv\Scripts\pyinstaller.exe" (
    echo  [错误] .venv 未找到 pyinstaller(dev 依赖),请检查 pyproject.toml 的 dependency-groups
    pause
    exit /b 1
)

REM === 步骤 2: 清理旧产物 ===
echo.
echo  [2/4] 清理旧产物...
if exist "dist"    rmdir /s /q "dist" 2>nul
if exist "build"   rmdir /s /q "build" 2>nul
if exist "release" rmdir /s /q "release" 2>nul
echo        清理完成

REM === 步骤 3: PyInstaller 打包 ===
echo.
echo  [3/4] 开始打包(可能需要 2-5 分钟)...
".venv\Scripts\pyinstaller.exe" build.spec --clean --noconfirm
if errorlevel 1 (
    echo  [错误] 打包失败,请查看上方日志
    pause
    exit /b 1
)

REM === 步骤 4: 验证 + 发布 ===
echo.
echo  [4/4] 验证产物...
set "EXE_PATH=dist\ClashGenerator.exe"
if not exist "%EXE_PATH%" (
    echo  [错误] 产物未生成
    pause
    exit /b 1
)
for %%F in ("%EXE_PATH%") do set "EXE_SIZE=%%~zF"
mkdir release 2>nul
copy /y "%EXE_PATH%" "release\ClashGenerator.exe" >nul
set /a SIZE_MB=EXE_SIZE/1048576

echo.
echo  [验证] 检查 EXE 版本信息...
powershell -NoProfile -Command "
    $f = Get-Item 'release\ClashGenerator.exe';
    $vi = $f.VersionInfo;
    $ok = $true;
    if (-not $vi.FileVersion) { Write-Host '  [警告] FileVersion 缺失'; $ok=$false }
    else { Write-Host ('  FileVersion:     ' + $vi.FileVersion) }
    if (-not $vi.ProductName) { Write-Host '  [警告] ProductName 缺失'; $ok=$false }
    else { Write-Host ('  ProductName:     ' + $vi.ProductName) }
    if (-not $vi.FileDescription) { Write-Host '  [警告] FileDescription 缺失'; $ok=$false }
    else { Write-Host ('  FileDescription: ' + $vi.FileDescription) }
    if ($ok) { Write-Host '  [OK] 版本信息完整' }
"

REM === 完成 ===
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                  ✅ 打包成功！                        ║
echo  ╠══════════════════════════════════════════════════════╣
echo  ║  产物路径: release\ClashGenerator.exe
echo  ║  文件大小: %SIZE_MB% MB
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  📋 使用说明:
echo     1. 双击 release\ClashGenerator.exe 即可运行
echo     2. 首次运行若出现 SmartScreen: 点击 "更多信息" → "仍要运行"
echo     3. 将 proxies 文件拖入窗口或点击"导入"按钮
echo     4. 点击"生成"按钮输出最终 Clash 配置
echo.

endlocal