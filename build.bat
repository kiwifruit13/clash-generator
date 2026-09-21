@echo off
REM ============================================================
REM  Clash Generator - Windows portable build entry (wrapper)
REM  Delegates to build.ps1 (the correct implementation).
REM  The old multi-line powershell-in-batch version failed to
REM  produce the exe and is replaced by this thin wrapper.
REM
REM  Usage:
REM    build.bat            full build (uv sync + PyInstaller)
REM    build.bat -Fast      reuse .venv, no network
REM  Output: release\ClashGenerator.exe
REM ============================================================

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" %*
exit /b %ERRORLEVEL%