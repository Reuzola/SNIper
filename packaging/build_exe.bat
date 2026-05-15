@echo off
chcp 65001 >nul 2>&1
title Build SNIper EXE
setlocal

rem Build a portable single-file EXE for the architecture of the Python
rem interpreter that runs this script. PyInstaller does not cross-compile,
rem so x64 and ARM64 each require a native build.
rem
rem Project layout (this script lives in packaging\):
rem     SNIper_vX.Y.Z\
rem       +- src\SNIper_gui.py        <- PyInstaller entry point
rem       +- packaging\build_exe.bat  <- this script
rem       +- packaging\version_info.txt
rem       +- packaging\app.manifest
rem   The finished EXE is dropped at the project root next to README.md.
rem
rem Hardenings against Defender ML false positives (Behavior:*!ml):
rem   --version-file  embeds CompanyName / FileDescription / ProductName
rem   --manifest      declares asInvoker (no UAC) + PerMonitorV2 DPI
rem   --noupx         no runtime decompression

set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"
rem Project root is the parent of packaging\
for %%I in ("%SCRIPT_DIR%..") do set PROJECT_ROOT=%%~fI

where py >nul 2>&1
if %errorlevel% neq 0 (
    where python >nul 2>&1
    if %errorlevel% neq 0 (
        echo Python not found. Install it from python.org/downloads.
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
    echo Unsupported architecture: %ARCH%
    exit /b 1
)

set APPNAME=SNIper_%SUFFIX%
echo Architecture: %ARCH%  ^|  EXE: %APPNAME%.exe

%PY% -m pip install --upgrade pyinstaller >nul
if %errorlevel% neq 0 (
    echo PyInstaller installation failed.
    exit /b 1
)

if exist "%PROJECT_ROOT%\%APPNAME%.exe" del /Q "%PROJECT_ROOT%\%APPNAME%.exe"

%PY% -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --noupx ^
    --clean ^
    --name "%APPNAME%" ^
    --version-file "version_info.txt" ^
    --manifest "app.manifest" ^
    "..\src\SNIper_gui.py"
if %errorlevel% neq 0 (
    echo Build failed.
    exit /b 1
)

move /Y "dist\%APPNAME%.exe" "%PROJECT_ROOT%\%APPNAME%.exe" >nul
rmdir /S /Q build 2>nul
rmdir /S /Q dist  2>nul
del /Q "%APPNAME%.spec" 2>nul

echo.
echo Done: %APPNAME%.exe  (single file, portable)  ->  %PROJECT_ROOT%\%APPNAME%.exe
endlocal
