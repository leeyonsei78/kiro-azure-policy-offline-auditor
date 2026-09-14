@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul

rem ============================================================
rem  Azure Policy Offline Auditor (ISMS-P) - Windows launcher
rem  Double-click to start the web UI and open the browser.
rem  Offline use only - no internet required.
rem
rem  Python detection order:
rem   1) bundled embeddable Python (python\python.exe)
rem   2) system py launcher / python
rem  If none found, shows guidance to run setup-python.bat.
rem ============================================================

cd /d "%~dp0"

set "PORT=8080"
set "HOST=127.0.0.1"
set "PYEXE="

rem --- 1) bundled embeddable Python ---
if exist "%~dp0python\python.exe" (
  set "PYEXE=%~dp0python\python.exe"
  echo [INFO] Using bundled Python: python\python.exe
)

rem --- 2) system py launcher ---
if not defined PYEXE (
  where py >nul 2>nul && set "PYEXE=py -3"
)

rem --- 3) system python ---
if not defined PYEXE (
  where python >nul 2>nul && set "PYEXE=python"
)

if not defined PYEXE (
  echo.
  echo ============================================================
  echo   [NOTICE] Python not found on this PC.
  echo ============================================================
  echo   Offline option ^(no install needed^):
  echo    1^) On an internet PC, run setup-python.bat in this folder.
  echo       ^(downloads embeddable Python into the python\ folder^)
  echo    2^) Copy this whole folder to the offline PC via USB.
  echo    3^) Double-click run.bat again on the offline PC.
  echo.
  echo   Or install Python 3.8+ ^(check "Add Python to PATH"^):
  echo       https://www.python.org/downloads/
  echo ============================================================
  echo.
  pause
  exit /b 1
)

echo.
echo ============================================================
echo   Azure Policy Offline Auditor (ISMS-P)
echo ============================================================
set "URL=http://%HOST%:%PORT%/"
echo   Web URL : %URL%
echo   Stop    : press Ctrl+C in this window (or close it)
echo   Offline use only - no external network
echo ============================================================
echo.

rem --- try to open the browser (best-effort; ignore if it fails) ---
start "" "%URL%" 2>nul

rem --- run web server (this window is the server console) ---
echo (If the browser did not open, manually open: %URL% )
echo.
%PYEXE% -m auditor --web --host %HOST% --port %PORT%

echo.
echo Server stopped.
pause
