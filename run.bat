@echo off
chcp 65001 >nul
setlocal

rem ============================================================
rem  Azure 정책 오프라인 보안검토 (ISMS-P) - Windows 실행 스크립트
rem  이 파일을 더블클릭하면 웹 UI가 켜지고 브라우저가 열립니다.
rem  폐쇄망 전용 - 인터넷/추가 설치 불필요 (Python 3.8+ 만 필요)
rem ============================================================

cd /d "%~dp0"

set "PORT=8080"
set "HOST=127.0.0.1"

rem --- Python 실행기 찾기 (py 런처 우선, 없으면 python) ---
set "PYEXE="
where py >nul 2>nul && set "PYEXE=py -3"
if not defined PYEXE (
  where python >nul 2>nul && set "PYEXE=python"
)

if not defined PYEXE (
  echo.
  echo [오류] Python을 찾을 수 없습니다.
  echo   - Python 3.8 이상을 설치하세요: https://www.python.org/downloads/
  echo   - 설치 시 "Add Python to PATH" 옵션을 반드시 체크하세요.
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
