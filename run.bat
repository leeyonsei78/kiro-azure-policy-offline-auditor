@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

rem ============================================================
rem  Azure 정책 오프라인 보안검토 (ISMS-P) - Windows 실행 스크립트
rem  이 파일을 더블클릭하면 웹 UI가 켜지고 브라우저가 열립니다.
rem  폐쇄망 전용 - 인터넷 불필요.
rem
rem  [Python 탐지 순서]
rem   1) 폴더 안에 동봉된 임베디드 Python (python\python.exe)  <- Python 미설치 환경용
rem   2) 시스템에 설치된 py 런처 / python
rem   둘 다 없으면 setup-python.bat 안내를 표시합니다.
rem ============================================================

cd /d "%~dp0"

set "PORT=8080"
set "HOST=127.0.0.1"
set "PYEXE="

rem --- 1) 동봉된 임베디드 Python 우선 ---
if exist "%~dp0python\python.exe" (
  set "PYEXE=%~dp0python\python.exe"
  echo [정보] 동봉된 임베디드 Python을 사용합니다.
)

rem --- 2) 시스템 py 런처 ---
if not defined PYEXE (
  where py >nul 2>nul && set "PYEXE=py -3"
)

rem --- 3) 시스템 python ---
if not defined PYEXE (
  where python >nul 2>nul && set "PYEXE=python"
)

if not defined PYEXE (
  echo.
  echo ============================================================
  echo   [알림] Python을 찾을 수 없습니다.
  echo ============================================================
  echo   이 PC에는 Python이 설치되어 있지 않습니다.
  echo.
  echo   [폐쇄망 권장 방법 - 설치 불필요]
  echo    1) 인터넷이 되는 PC에서 이 폴더의 setup-python.bat 을 실행하세요.
  echo       (임베디드 Python을 자동으로 내려받아 python\ 폴더에 넣습니다)
  echo    2) 이 폴더 전체를 USB 등으로 폐쇄망 PC에 복사하세요.
  echo    3) 폐쇄망 PC에서 run.bat 을 다시 더블클릭하세요.
  echo.
  echo   [또는] Python 3.8+ 를 직접 설치 ("Add Python to PATH" 체크)
  echo       https://www.python.org/downloads/
  echo ============================================================
  echo.
  pause
  exit /b 1
)

echo.
echo ============================================================
echo   Azure 정책 오프라인 보안검토 (ISMS-P)
echo ============================================================
echo   웹 주소 : http://%HOST%:%PORT%
echo   종료    : 이 창에서 Ctrl+C  (또는 창 닫기)
echo   폐쇄망 전용 - 외부 네트워크 연결 없음
echo ============================================================
echo.

rem --- 3초 뒤 기본 브라우저로 접속 (서버 기동 시간 확보) ---
start "" /b cmd /c "timeout /t 3 >nul & start "" http://%HOST%:%PORT%"

rem --- 웹 서버 실행 (이 창이 서버 콘솔이 됩니다) ---
%PYEXE% -m auditor --web --host %HOST% --port %PORT%

echo.
echo 서버가 종료되었습니다.
pause
