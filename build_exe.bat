@echo off
chcp 65001 >nul 2>&1
title Build DPI Bypass EXE
setlocal

rem Build a portable single-file EXE for the architecture of the Python
rem interpreter that runs this script. PyInstaller does not cross-compile,
rem so x64 and ARM64 each require a native build.
rem
rem Hardenings against Defender ML false positives (Behavior:*!ml):
rem   --version-file  embeds CompanyName / FileDescription / ProductName
rem   --manifest      declares asInvoker (no UAC) + PerMonitorV2 DPI
rem   --noupx         no runtime decompression

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"

where py >nul 2>&1
if %errorlevel% neq 0 (
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        echo Python bulunamadi. python.org/downloads adresinden yukleyin.
        exit /b 1
    )
    set PY=python
) else (
    set PY=py
)

for /f "tokens=*" %%A in ('%PY% -c "import platform; print(platform.machine().lower())"') do set ARCH=%%A
if "%ARCH%"=="amd64"  set SUFFIX=x64
if "%ARCH%"=="x86_64" set SUFFIX=x64
if "%ARCH%"=="arm64"  set SUFFIX=arm64
if "%ARCH%"=="aarch64" set SUFFIX=arm64
if not defined SUFFIX (
    echo Desteklenmeyen mimari: %ARCH%
    exit /b 1
)

set APPNAME=DPI_Bypass_Proxy_%SUFFIX%
echo Mimari: %ARCH%  ^|  EXE: %APPNAME%.exe

%PY% -m pip install --upgrade pyinstaller >nul
if %errorlevel% neq 0 (
    echo PyInstaller kurulumu basarisiz.
    exit /b 1
)

if exist "%APPNAME%.exe" del /Q "%APPNAME%.exe"
if exist "%APPNAME%"     rmdir /S /Q "%APPNAME%"

%PY% -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --noupx ^
    --clean ^
    --name "%APPNAME%" ^
    --version-file "version_info.txt" ^
    --manifest "app.manifest" ^
    dpi_bypass_gui.py
if %errorlevel% neq 0 (
    echo Build basarisiz.
    exit /b 1
)

move /Y "dist\%APPNAME%.exe" "%APPNAME%.exe" >nul
rmdir /S /Q build 2>nul
rmdir /S /Q dist  2>nul
del /Q "%APPNAME%.spec" 2>nul

echo.
echo Tamam: %APPNAME%.exe  (tek dosya, tasinabilir)
endlocal
