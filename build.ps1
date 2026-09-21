# =====================================================================
#  Clash Generator - Windows portable build script (PowerShell)
# =====================================================================
#  Replaces the broken build.bat (multi-line powershell-in-batch and
#  UTF-8/emu encoding made it fail to actually produce the exe).
#
#  Usage:
#    powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
#    powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Fast
#
#  -Fast: skip `uv sync` (reuse existing .venv, no network).
#  Output: release\ClashGenerator.exe
# =====================================================================

param(
    [switch]$Fast
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

Write-Host '========================================'
Write-Host '  Clash Generator - Windows build'
Write-Host '========================================'
Write-Host ''

# ---- check prerequisites -----------------------------------------
$versionFile = Join-Path $root 'assets\version.txt'
$iconFile    = Join-Path $root 'assets\app.ico'
$specFile    = Join-Path $root 'build.spec'
$pyinstaller = Join-Path $root '.venv\Scripts\pyinstaller.exe'

foreach ($f in @($versionFile, $iconFile, $specFile)) {
    if (-not (Test-Path $f)) {
        Write-Host "[ERROR] missing required file: $f" -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path $pyinstaller)) {
    Write-Host "[ERROR] pyinstaller not found in .venv. Run without -Fast first (uv sync installs dev deps)." -ForegroundColor Red
    exit 1
}

# ---- step 0: sync deps (unless -Fast) ----------------------------
if (-not $Fast) {
    Write-Host '[1/5] uv sync (single .venv)...'
    uv sync
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] uv sync failed." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host '[1/5] skipping uv sync (-Fast)'
}

# ---- step 1: clean old artifacts ----------------------------------
Write-Host '[2/5] cleaning dist / build / release ...'
foreach ($d in @('dist', 'build', 'release')) {
    $p = Join-Path $root $d
    if (Test-Path $p) {
        Remove-Item -Recurse -Force $p
        Write-Host "    removed $d"
    }
}

# ---- step 2: PyInstaller build ------------------------------------
Write-Host '[3/5] running PyInstaller (build.spec) ...'
& $pyinstaller build.spec --clean --noconfirm
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] PyInstaller build failed (exit $LASTEXITCODE)." -ForegroundColor Red
    exit 1
}

# ---- step 3: collect + verify artifact ----------------------------
Write-Host '[4/5] collecting artifact ...'
$exe = Join-Path $root 'dist\ClashGenerator.exe'
if (-not (Test-Path $exe)) {
    Write-Host '[ERROR] dist\ClashGenerator.exe was not produced.' -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path (Join-Path $root 'release') | Out-Null
Copy-Item $exe (Join-Path $root 'release\ClashGenerator.exe') -Force

$sizeBytes = (Get-Item $exe).Length
$sizeMB    = [math]::Round($sizeBytes / 1MB, 1)
Write-Host ("release\ClashGenerator.exe  {0} MB" -f $sizeMB)

# ---- step 4: verify version info -----------------------------------
Write-Host '[5/5] verifying version info ...'
$vi = (Get-Item (Join-Path $root 'release\ClashGenerator.exe')).VersionInfo
if ($vi.FileVersion)  { Write-Host ("    FileVersion:      {0}" -f $vi.FileVersion) }  else { Write-Host '    [WARN] FileVersion missing' }
if ($vi.ProductName)  { Write-Host ("    ProductName:      {0}" -f $vi.ProductName) }  else { Write-Host '    [WARN] ProductName missing' }
if ($vi.FileDescription) { Write-Host ("    FileDescription: {0}" -f $vi.FileDescription) } else { Write-Host '    [WARN] FileDescription missing' }

Write-Host ''
Write-Host '========================================'
Write-Host '  BUILD OK -> release\ClashGenerator.exe'
Write-Host '========================================'