@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
title Build SNIper EXE

rem ===========================================================================
rem  Build a portable single-file EXE for the architecture of the Python
rem  interpreter that runs this script, using Nuitka. Nuitka compiles Python to
rem  C, so it does not cross-compile: x64 and ARM64 each require a native build
rem  on a machine of that arch.
rem
rem  Layout (this script lives in packaging\):
rem      SNIper_vX.Y.Z\
rem        +- src\run_sniper.py          <- build / application entry point
rem        +- src\sniper\               <- the package (logic lives here)
rem        +- packaging\build_exe.bat    <- this script
rem        +- packaging\SNIper.ico
rem        +- packaging\app.manifest     <- reference only; Nuitka generates its
rem                                          own manifest (asInvoker is default;
rem                                          DPI awareness is set at runtime by
rem                                          ctypes in sniper\ui.py).
rem  The finished EXE (SNIper_<arch>.exe) is dropped at the project root.
rem
rem  Unlike PyInstaller (which shipped a prebuilt bootloader and needed no C
rem  compiler), Nuitka requires a working C toolchain (MSVC or MinGW64). This
rem  script preflights both Nuitka and the compiler so a missing prerequisite
rem  stops early with an actionable message instead of failing deep inside
rem  compilation. The first build compiles C and is slower; repeat builds of
rem  unchanged sources reuse Nuitka's compiler cache (ccache) and are faster.
rem
rem  This script is intentionally verbose and verifies the produced EXE's
rem  PE architecture so a wrong-arch build can never silently ship.
rem ===========================================================================

rem ---- Resolve paths (pushd/popd canonicalises, no ".." guesswork) ----------
set "PKG_DIR=%~dp0"
pushd "%~dp0.." 2>nul || (echo [ERROR] Cannot locate project root.& goto :fail)
set "PROJECT_ROOT=%CD%"
popd
set "ENTRY=%PROJECT_ROOT%\src\run_sniper.py"
set "ICON=%PKG_DIR%SNIper.ico"
set "BUILD_DIR=%PKG_DIR%nuitka-build"

echo Project root : %PROJECT_ROOT%
echo Entry script : %ENTRY%
echo Packaging    : %PKG_DIR%
echo Icon         : %ICON%

if not exist "%ENTRY%" (
    echo [ERROR] Entry script not found: %ENTRY%
    goto :fail
)
if not exist "%ICON%" (
    echo [ERROR] Icon not found: %ICON%
    goto :fail
)

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

rem  Nuitka links the compiled binary against this interpreter's runtime DLL.
rem  Python 3.13+ dropped Windows 8.1 and needs Windows 10 1809, which would
rem  raise the EXE's OS floor above the documented Windows 10 1607 minimum.
for /f "tokens=1,2 delims=." %%a in ("%PY_VER%") do (set "PY_MAJOR=%%a" & set "PY_MINOR=%%b")
if "%PY_MAJOR%"=="3" if defined PY_MINOR if %PY_MINOR% GEQ 13 (
    echo [NOTE] Python %PY_VER% bundles a runtime that needs Windows 10 1809+.
    echo        Build with Python 3.10-3.12 to keep the Windows 10 1607 floor.
)

rem ---- Version: single source of truth is src\sniper\__init__.py -----------
rem  Derive the embedded file/product version from __version__ so the PE
rem  metadata can never drift from the package. Falls back to 1.1.6.0.
set "APP_VERSION="
for /f "delims=" %%V in ('%PY% -c "import sys;sys.path.insert(0,r'%PROJECT_ROOT%\src');import sniper;print(sniper.__version__)" 2^>nul') do set "APP_VERSION=%%V"
if defined APP_VERSION (set "FILE_VERSION=%APP_VERSION%.0") else (set "FILE_VERSION=1.1.6.0")
echo App version  : %FILE_VERSION%

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

rem ---- Preflight: Nuitka ----------------------------------------------------
%PY% -m nuitka --version >nul 2>&1
if errorlevel 1 (
    echo Nuitka not found - installing ...
    rem  Pin the major version: a future Nuitka 3.x could change CLI flags and
    rem  break this build without warning.
    %PY% -m pip install "nuitka>=2.0,<3.0"
    if errorlevel 1 (
        echo [ERROR] Nuitka installation failed.
        echo         Install it manually, then re-run this script:
        echo             %PY% -m pip install "nuitka^>=2.0,^<3.0"
        goto :fail
    )
)
set "NUITKA_VER="
for /f "tokens=*" %%V in ('%PY% -m nuitka --version 2^>nul') do if not defined NUITKA_VER set "NUITKA_VER=%%V"
echo Nuitka       : %NUITKA_VER%

rem ---- Preflight: C toolchain (Nuitka compiles to C; PyInstaller did not) ---
rem  Without this check Nuitka would either fail deep in compilation or block
rem  interactively asking to download MinGW64. Detect MSVC (on PATH, or via
rem  vswhere -- the same locator Nuitka uses) or MinGW64 gcc up front.
call :check_compiler
if not defined COMPILER_OK (
    echo [ERROR] No C compiler found. Nuitka compiles Python to C and needs a
    echo         C toolchain on this machine ^(PyInstaller did not^).
    echo         Install ONE of:
    echo           - Visual Studio Build Tools with the
    echo             "Desktop development with C++" workload ^(recommended^), or
    echo           - MinGW64 ^(gcc^) on PATH.
    echo         Then re-run this script.
    goto :fail
)
echo Compiler     : %COMPILER_DESC%
echo.

rem ---- zlib1.dll: transitive Tcl dependency of _tkinter (ARCH-CONDITIONAL) ---
rem  Dependency chain (confirmed with dumpbin /dependents):
rem      _tkinter.pyd -> tcl86t.dll -> zlib1.dll
rem  This transitive DLL must be in the bundle or the compiled GUI aborts at
rem  import with a _tkinter LoadLibraryExW error (Windows error 126) -- and
rem  silently, since the console is disabled. HOW it gets bundled differs by
rem  architecture, so we gate on the SUFFIX decided above (one source of truth,
rem  no second arch test):
rem    * x64  : Nuitka runs Dependency Walker (depends.exe, which is x86_64-only)
rem             and detects + bundles zlib1.dll on its own. Adding it again as a
rem             data file makes Nuitka abort with "data file 'zlib1.dll'
rem             conflicts with dll 'zlib1.dll'", so we must NOT include it here.
rem    * ARM64: there is no native depends.exe and Nuitka's fallback misses the
rem             transitive edge, so we include zlib1.dll explicitly, sourced from
rem             THIS interpreter's own DLLs dir (no hardcoded path; sys.base_prefix
rem             handles a venv). Tcl/Tk ship with CPython, so this adds no
rem             third-party runtime dependency.
rem  ZLIB_INCLUDE holds the whole flag (empty on x64); it expands into the Nuitka
rem  command below. Kept at top level (not in the if-block) so %ZLIB_DLL% set by
rem  the for loop reads back correctly without delayed expansion.
set "ZLIB_INCLUDE="
if /i not "%SUFFIX%"=="arm64" (
    echo zlib1.dll    : bundled by Nuitka's own DLL detection ^(%SUFFIX%^)
    goto :zlib_after
)
set "ZLIB_DLL="
for /f "delims=" %%Z in ('%PY% -c "import os,sys;p=os.path.join(sys.base_prefix,'DLLs','zlib1.dll');print(p if os.path.isfile(p) else '')" 2^>nul') do set "ZLIB_DLL=%%Z"
if not defined ZLIB_DLL (
    echo [ERROR] zlib1.dll not found in this interpreter's DLLs directory:
    echo             %PY_EXE%
    echo         On ARM64 _tkinter needs it bundled explicitly ^(via tcl86t.dll^);
    echo         without it the compiled GUI cannot start. Use a standard CPython
    echo         for Windows ^(python.org^) that ships Tcl/Tk, then re-run.
    goto :fail
)
set ZLIB_INCLUDE=--include-data-files="%ZLIB_DLL%=zlib1.dll"
echo zlib1.dll    : %ZLIB_DLL%  ^(ARM64 explicit include^)
:zlib_after
echo.

rem ---- Build (all intermediate artifacts kept inside packaging\nuitka-build) -
if exist "%PROJECT_ROOT%\%APPNAME%.exe" del /Q "%PROJECT_ROOT%\%APPNAME%.exe"
rem  Remove a stale checksum file left by an older build of this script.
del /Q "%PROJECT_ROOT%\%APPNAME%.exe.sha256" 2>nul
if exist "%BUILD_DIR%" rmdir /S /Q "%BUILD_DIR%" 2>nul

rem  Flag notes:
rem   --mode=onefile             single self-extracting EXE, no sidecar files.
rem   --enable-plugin=tk-inter   bundle Tcl/Tk so the tkinter GUI runs.
rem   --windows-console-mode=disable   GUI app: create no console window.
rem   --windows-icon-from-ico    the EXE's own icon (Explorer file icon, taskbar).
rem   --include-data-files       embed SNIper.ico beside the package so
rem                              sniper.resources finds it at runtime (title bar,
rem                              Alt-Tab, tray); the "=sniper/SNIper.ico" target
rem                              must match the first candidate in resources.py.
rem   %ZLIB_INCLUDE%             a second --include-data-files for zlib1.dll, but
rem                              ONLY on ARM64 (empty on x64). See the arch note
rem                              above for why x64 must omit it.
rem   --company-name/...         version metadata embedded in the PE so Explorer
rem                              and Defender see real, non-blank info. Nuitka
rem                              derives InternalName/OriginalFilename from the
rem                              output basename, so we name the binary SNIper.exe
rem                              (InternalName "SNIper", OriginalFilename
rem                              "SNIper.exe") and rename it to SNIper_<arch>.exe
rem                              on disk afterwards, exactly as the old build did.
rem   --assume-yes-for-downloads let Nuitka fetch its helper tools (ccache for
rem                              build caching, dependency walker) non-interactively.
rem  (Note: we deliberately do NOT pass --remove-output. It deletes the
rem  intermediate .dist tree immediately after packaging, which races with
rem  Defender scanning the freshly built files; a locked .dist then makes Nuitka
rem  exit non-zero and fail the build even though the EXE was produced. Instead
rem  we move the finished EXE out first and clean the build dir ourselves below,
rem  tolerating a transient lock.)
%PY% -m nuitka ^
    --mode=onefile ^
    --enable-plugin=tk-inter ^
    --windows-console-mode=disable ^
    --windows-icon-from-ico="%ICON%" ^
    --include-data-files="%ICON%=sniper/SNIper.ico" ^
    %ZLIB_INCLUDE% ^
    --company-name=SNIper ^
    --product-name=SNIper ^
    --file-version=%FILE_VERSION% ^
    --product-version=%FILE_VERSION% ^
    --file-description="SNIper - lightweight SNI-based DPI bypass proxy (user-space, no admin)" ^
    --copyright="Released under the MIT License." ^
    --output-filename=SNIper.exe ^
    --output-dir="%BUILD_DIR%" ^
    --assume-yes-for-downloads ^
    "%ENTRY%"
if errorlevel 1 (
    echo [ERROR] Nuitka build failed - see the output above.
    goto :fail
)

if not exist "%BUILD_DIR%\SNIper.exe" (
    echo [ERROR] Build reported success but "SNIper.exe" was not produced.
    goto :fail
)

rem  Move the finished EXE out of the build tree FIRST, then clean up. Cleanup
rem  is best-effort: Defender can briefly lock just-built files, so a failed
rem  delete must never fail the build (the EXE is already safe). Retry once.
move /Y "%BUILD_DIR%\SNIper.exe" "%PROJECT_ROOT%\%APPNAME%.exe" >nul
rmdir /S /Q "%BUILD_DIR%" 2>nul
if exist "%BUILD_DIR%" (
    ping -n 3 127.0.0.1 >nul 2>&1
    rmdir /S /Q "%BUILD_DIR%" 2>nul
)

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

rem ---------------------------------------------------------------------------
rem  :check_compiler  -- sets COMPILER_OK=1 and COMPILER_DESC when a usable C
rem  toolchain is found: MSVC on PATH, MSVC located via vswhere, or MinGW64 gcc
rem  on PATH. Written flat (no nested parentheses around variables it both sets
rem  and reads) so it is correct without delayed expansion.
rem ---------------------------------------------------------------------------
:check_compiler
set "COMPILER_OK="
set "COMPILER_DESC="
where cl >nul 2>&1
if not errorlevel 1 (
    set "COMPILER_DESC=MSVC (cl on PATH)"
    set "COMPILER_OK=1"
    goto :eof
)
rem  MSVC is normally off PATH outside a Developer Command Prompt; ask vswhere
rem  whether a VC++ toolset is installed (works for x64 and ARM64 hosts).
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :check_gcc
set "VSINSTALL="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath 2^>nul`) do set "VSINSTALL=%%i"
if not defined VSINSTALL goto :check_gcc
if exist "%VSINSTALL%\VC\Tools\MSVC" (
    set "COMPILER_DESC=MSVC (%VSINSTALL%)"
    set "COMPILER_OK=1"
    goto :eof
)
:check_gcc
where gcc >nul 2>&1
if not errorlevel 1 (
    set "COMPILER_DESC=MinGW64 (gcc on PATH)"
    set "COMPILER_OK=1"
)
goto :eof

:fail
echo.
echo Build did NOT complete. Read the messages above for the cause.
echo.
pause
endlocal
exit /b 1
