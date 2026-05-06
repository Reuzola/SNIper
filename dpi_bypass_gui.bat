@echo off
chcp 65001 >nul 2>&1
title DPI Bypass Proxy

set LOGFILE=%~dp0error_log.txt
echo. > "%LOGFILE%"

where py >nul 2>&1
if %errorlevel% == 0 (
    py "%~dp0dpi_bypass_gui.py" 2>>"%LOGFILE%"
    goto done
)

where python3 >nul 2>&1
if %errorlevel% == 0 (
    python3 "%~dp0dpi_bypass_gui.py" 2>>"%LOGFILE%"
    goto done
)

where python >nul 2>&1
if %errorlevel% == 0 (
    python "%~dp0dpi_bypass_gui.py" 2>>"%LOGFILE%"
    goto done
)

echo Python not found >> "%LOGFILE%"

:done
