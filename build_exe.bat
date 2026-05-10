@echo off
chcp 65001 >nul 2>&1
title Build DPI Bypass EXE
setlocal

REM Build a portable single-file EXE for the architecture of the Python
REM interpreter that runs this script. Run on x64 Windows for the x64 EXE,
REM run on ARM64 Windows for the ARM64 EXE — PyInstaller does not
REM cross-compile, so each architecture must be built natively.

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

REM Detect architecture from the Python interpreter (not the OS) so that
REM running an x64 Python on an ARM64 host produces an x64 binary.
for /f "tokens=*" %%A in ('%PY% -c "import platform; print(platform.machine().lower())"') do set ARCH=%%A
if "%ARCH%"=="amd64"  set SUFFIX=x64
if "%ARCH%"=="x86_64" set SUFFIX=x64
if "%ARCH%"=="arm64"  set SUFFIX=arm64
if "%ARCH%"=="aarch64" set SUFFIX=arm64
if not defined SUFFIX (
    echo Desteklenmeyen mimari: %ARCH%
    exit /b 1
)

echo Mimari: %ARCH%  ^|  EXE: DPI_Bypass_Proxy_%SUFFIX%.exe

%PY% -m pip install --upgrade pyinstaller >nul
if %errorlevel% neq 0 (
    echo PyInstaller kurulumu basarisiz.
    exit /b 1
)

%PY% -m PyInstaller --onefile --noconsole --clean ^
    --name "DPI_Bypass_Proxy_%SUFFIX%" ^
    dpi_bypass_gui.py
if %errorlevel% neq 0 (
    echo Build basarisiz.
    exit /b 1
)

REM Move the EXE to the project root and remove PyInstaller's scratch
REM directories and spec file so the source tree stays clean.
move /Y "dist\DPI_Bypass_Proxy_%SUFFIX%.exe" "DPI_Bypass_Proxy_%SUFFIX%.exe" >nul
rmdir /S /Q build 2>nul
rmdir /S /Q dist  2>nul
del /Q "DPI_Bypass_Proxy_%SUFFIX%.spec" 2>nul

echo.
echo Tamam: DPI_Bypass_Proxy_%SUFFIX%.exe
endlocal
