@echo off
chcp 65001 >nul 2>&1
title DPI Bypass Proxy

:: py launcher dene (Windows'ta en guvenilir yol)
where py >nul 2>&1
if %errorlevel% == 0 (
    py "%~dp0dpi_bypass.py"
    goto done
)

:: python3 dene
where python3 >nul 2>&1
if %errorlevel% == 0 (
    python3 "%~dp0dpi_bypass.py"
    goto done
)

:: python dene
where python >nul 2>&1
if %errorlevel% == 0 (
    python "%~dp0dpi_bypass.py"
    goto done
)

echo Python bulunamadi! python.org/downloads adresinden yukleyin.
pause
exit /b 1

:done
echo.
echo Proxy kapatildi.
timeout /t 3 >nul
