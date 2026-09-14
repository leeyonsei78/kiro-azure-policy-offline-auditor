@echo off
setlocal
chcp 437 >nul

rem ============================================================
rem  Prepare embeddable Python (run ONCE on an internet-connected PC)
rem
rem  Downloads Windows embeddable Python (no install needed) into
rem  the .\python\ subfolder so this whole folder can be copied to
rem  an offline PC and run.bat works WITHOUT installing Python.
rem
rem  Run this on a PC WITH internet. Not needed on the offline PC.
rem ============================================================

cd /d "%~dp0"

set "PYVER=3.11.9"
set "ARCH=amd64"
set "ZIP=python-%PYVER%-embed-%ARCH%.zip"
set "URL=https://www.python.org/ftp/python/%PYVER%/%ZIP%"
set "DEST=%~dp0python"

echo ============================================================
echo   Preparing embeddable Python %PYVER% (%ARCH%)
echo   Target: %DEST%
echo ============================================================

if exist "%DEST%\python.exe" (
  echo [INFO] python\python.exe already exists. Delete the python folder to re-download.
  pause
  exit /b 0
)

echo [1/3] Downloading: %URL%
where curl >nul 2>nul
if %errorlevel%==0 (
  curl -L -o "%~dp0%ZIP%" "%URL%"
) else (
  powershell -NoProfile -Command "Invoke-WebRequest -Uri '%URL%' -OutFile '%ZIP%' -UseBasicParsing"
)
if not exist "%~dp0%ZIP%" (
  echo [ERROR] Download failed. Check internet/proxy, or download the URL above
  echo         in a browser, save it as %ZIP% in this folder, then run again.
  pause
  exit /b 1
)

echo [2/3] Extracting to python\
powershell -NoProfile -Command "Expand-Archive -Path '%ZIP%' -DestinationPath 'python' -Force"
if not exist "%DEST%\python.exe" (
  echo [ERROR] Extraction failed.
  pause
  exit /b 1
)

echo [3/3] Enabling parent-folder imports (add "..") to ._pth
powershell -NoProfile -Command "Get-ChildItem 'python\python*._pth' | ForEach-Object { if (-not (Select-String -Path $_.FullName -SimpleMatch '..' -Quiet)) { Add-Content -Path $_.FullName -Value '..' } }"

del "%~dp0%ZIP%" >nul 2>nul

echo.
echo ============================================================
echo   Done. Copy this whole folder to the offline PC and
echo   double-click run.bat
echo ============================================================
pause
