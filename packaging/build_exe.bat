@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
title Build SNIper EXE

rem ===========================================================================
rem  Build a portable single-file EXE for the architecture of the Python
rem  interpreter that runs this script. PyInstaller does not cross-compile,
rem  so x64 and ARM64 each require a native build on a machine of that arch.
rem
rem  Layout (this script lives in packaging\):
rem      SNIper_vX.Y.Z\
rem        +- src\SNIper_gui.py          <- PyInstaller entry point
rem        +- packaging\build_exe.bat    <- this script
rem        +- packaging\version_info.txt
rem        +- packaging\app.manifest
rem  The finished EXE (SNIper_<arch>.exe) is dropped at the project root.
rem
rem  This script is intentionally verbose and verifies the produced EXE's
rem  PE architecture so a wrong-arch build can never silently ship.
rem ===========================================================================

rem ---- Resolve paths (pushd/popd canonicalises, no ".." guesswork) ----------
set "PKG_DIR=%~dp0"
pushd "%~dp0.." 2>nul || (echo [ERROR] Cannot locate project root.& goto :fail)
set "PROJECT_ROOT=%CD%"
popd
set "ENTRY=%PROJECT_ROOT%\src\SNIper_gui.py"
set "ICON=%PKG_DIR%SNIper.ico"

echo Project root : %PROJECT_ROOT%
echo Entry script : %ENTRY%
echo Packaging    : %PKG_DIR%
echo Icon         : %ICON%

if not exist "%ENTRY%" (
    echo [ERROR] Entry script not found: %ENTRY%
    goto :fail
)

rem ---- Soft warning if running elevated (PyInstaller dislikes admin) --------
net session >nul 2>&1 && echo [NOTE] Running as Administrator - PyInstaller recommends a normal terminal.

rem ---- Pick the Python interpreter -----------------------------------------
where py >nul 2>&1 && (set "PY=py") || (set "PY=python")
where %PY% >nul 2>&1 || (
    echo [ERROR] Python not found. Install it from python.org/downloads.
    goto :fail
)

rem ---- Identify the interpreter (catch the Microsoft Store stub) -----------
rem  A bare "python" on PATH can be the Microsoft Store stub, which does not
rem  run code -- it just opens the Store page. Resolving sys.executable both
rem  proves a real interpreter answered and shows which Python is in use.
set "PY_EXE="
for /f "delims=" %%E in ('%PY% -c "import sys;print(sys.executable)" 2^>nul') do set "PY_EXE=%%E"
if not defined PY_EXE (
    echo [ERROR] "%PY%" did not run Python - it produced no interpreter path.
    echo         This is usually the Microsoft Store stub. Install the real
    echo         Python from python.org/downloads and re-run this script.
    goto :fail
)
set "PY_VER="
for /f "delims=" %%V in ('%PY% -c "import sys;print(sys.version.split()[0])" 2^>nul') do set "PY_VER=%%V"
echo Python exe   : %PY_EXE%
echo Python ver   : %PY_VER%

rem  PyInstaller embeds this interpreter's runtime in the EXE. Python 3.13+
rem  dropped Windows 8.1 and needs Windows 10 1809, which would raise the
rem  EXE's OS floor above the documented Windows 10 1607 minimum.
for /f "tokens=1,2 delims=." %%a in ("%PY_VER%") do (set "PY_MAJOR=%%a" & set "PY_MINOR=%%b")
if "%PY_MAJOR%"=="3" if defined PY_MINOR if %PY_MINOR% GEQ 13 (
    echo [NOTE] Python %PY_VER% bundles a runtime that needs Windows 10 1809+.
    echo        Build with Python 3.10-3.12 to keep the Windows 10 1607 floor.
)

rem ---- Detect architecture --------------------------------------------------
rem  Only 64-bit targets are supported. 32-bit Windows is detected explicitly
rem  so the user gets a clear reason rather than a generic "unsupported arch"
rem  message that they might mistake for a script bug.
for /f "tokens=*" %%A in ('%PY% -c "import platform;print(platform.machine().lower())"') do set "ARCH=%%A"
set "SUFFIX="
if /i "%ARCH%"=="amd64"   set "SUFFIX=x64"
if /i "%ARCH%"=="x86_64"  set "SUFFIX=x64"
if /i "%ARCH%"=="arm64"   set "SUFFIX=arm64"
if /i "%ARCH%"=="aarch64" set "SUFFIX=arm64"
if /i "%ARCH%"=="x86"     set "IS_X86=1"
if /i "%ARCH%"=="i386"    set "IS_X86=1"
if /i "%ARCH%"=="i686"    set "IS_X86=1"
if /i "%ARCH%"=="win32"   set "IS_X86=1"
if defined IS_X86 (
    echo [ERROR] 32-bit Windows ^(x86^) is not supported.
    echo         Detected python machine = %ARCH%.
    echo         SNIper ships only x64 and ARM64 builds. Install a 64-bit
    echo         Python on a 64-bit Windows host and re-run this script.
    goto :fail
)
if not defined SUFFIX (
    echo [ERROR] Unsupported architecture: %ARCH%
    echo         Supported targets: amd64/x86_64 ^(x64^), arm64/aarch64 ^(ARM64^).
    goto :fail
)
set "APPNAME=SNIper_%SUFFIX%"
echo Interpreter  : %PY%  ^(python machine = %ARCH%^)
echo Target EXE   : %APPNAME%.exe
echo.

rem ---- Ensure PyInstaller is available -------------------------------------
%PY% -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller not found - installing ...
    rem  Pin the major version: a future PyInstaller 7.x could change CLI
    rem  flags or hooks and break this build without warning.
    %PY% -m pip install "pyinstaller>=6.0,<7.0"
    if errorlevel 1 (
        echo [ERROR] PyInstaller installation failed.
        goto :fail
    )
)
for /f "tokens=*" %%V in ('%PY% -m PyInstaller --version 2^>nul') do set "PYI_VER=%%V"
echo PyInstaller  : %PYI_VER%
echo.

rem ---- Build (all artifacts kept inside packaging\) ------------------------
if exist "%PROJECT_ROOT%\%APPNAME%.exe" del /Q "%PROJECT_ROOT%\%APPNAME%.exe"
rem  Remove a stale checksum file left by an older build of this script.
del /Q "%PROJECT_ROOT%\%APPNAME%.exe.sha256" 2>nul

%PY% -m PyInstaller ^
    --onefile ^
    --noconsole ^
    --noupx ^
    --clean ^
    --noconfirm ^
    --name "%APPNAME%" ^
    --distpath "%PKG_DIR%dist" ^
    --workpath "%PKG_DIR%build" ^
    --specpath "%PKG_DIR%." ^
    --version-file "%PKG_DIR%version_info.txt" ^
    --manifest "%PKG_DIR%app.manifest" ^
    --icon "%ICON%" ^
    --add-data "%ICON%;." ^
    "%ENTRY%"
if errorlevel 1 (
    echo [ERROR] PyInstaller build failed - see the output above.
    goto :fail
)

if not exist "%PKG_DIR%dist\%APPNAME%.exe" (
    echo [ERROR] Build reported success but "%APPNAME%.exe" was not produced.
    goto :fail
)

move /Y "%PKG_DIR%dist\%APPNAME%.exe" "%PROJECT_ROOT%\%APPNAME%.exe" >nul
rmdir /S /Q "%PKG_DIR%build" 2>nul
rmdir /S /Q "%PKG_DIR%dist"  2>nul
del /Q "%PKG_DIR%%APPNAME%.spec" 2>nul

set "FINAL=%PROJECT_ROOT%\%APPNAME%.exe"

rem ---- Verify the produced EXE's real PE architecture ----------------------
set "EXE_ARCH=unknown"
for /f "tokens=*" %%M in ('%PY% -c "import struct,sys;f=open(sys.argv[1],'rb');f.seek(0x3C);o=struct.unpack('<I',f.read(4))[0];f.seek(o+4);print({0x8664:'x64',0xAA64:'arm64',0x14c:'x86'}.get(struct.unpack('<H',f.read(2))[0],'unknown'))" "%FINAL%"') do set "EXE_ARCH=%%M"

rem ---- SHA-256 of the finished EXE -----------------------------------------
rem  The EXE is unsigned; printing its checksum lets the builder publish it
rem  for users to verify. Shown in the summary below only -- no file is
rem  written, so the project root stays clean.
set "SHA256="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%FINAL%" SHA256 2^>nul') do if not defined SHA256 set "SHA256=%%H"

echo.
echo ============================================================
echo  Done: %FINAL%
echo  EXE architecture : %EXE_ARCH%
echo  This machine     : %SUFFIX%
if defined SHA256 (
    echo  SHA-256          : %SHA256%
) else (
    echo  SHA-256          : ^(certutil unavailable - checksum skipped^)
)
if /i not "%EXE_ARCH%"=="%SUFFIX%" (
    echo  [WARNING] Architecture mismatch - this EXE will show
    echo            "This app can't run on your PC" on a %SUFFIX% machine.
) else (
    echo  Architecture OK - safe to run on this machine.
)
echo ============================================================
echo.
pause
endlocal
goto :eof

:fail
echo.
echo Build did NOT complete. Read the messages above for the cause.
echo.
pause
endlocal
exit /b 1
