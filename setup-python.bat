@echo off
chcp 65001 >nul
setlocal

rem ============================================================
rem  임베디드 Python 준비 스크립트 (인터넷 되는 PC에서 1회만 실행)
rem
rem  이 스크립트는 Windows용 임베디드 Python(설치 불필요 버전)을
rem  내려받아 이 폴더의 python\ 하위에 풀어 둡니다.
rem  이후 이 폴더 전체를 폐쇄망 PC로 복사하면, 폐쇄망에서
rem  Python 설치 없이 run.bat 만으로 프로그램이 실행됩니다.
rem
rem  ※ 이 스크립트는 '인터넷이 되는 PC'에서 실행하세요.
rem     폐쇄망 PC에서는 실행할 필요가 없습니다(이미 python\ 가 포함됨).
rem ============================================================

cd /d "%~dp0"

rem --- 받을 임베디드 Python 버전 (필요 시 변경) ---
set "PYVER=3.11.9"
set "ARCH=amd64"
set "ZIP=python-%PYVER%-embed-%ARCH%.zip"
set "URL=https://www.python.org/ftp/python/%PYVER%/%ZIP%"
set "DEST=%~dp0python"

echo ============================================================
echo   임베디드 Python %PYVER% (%ARCH%) 준비
echo   대상 폴더: %DEST%
echo ============================================================

if exist "%DEST%\python.exe" (
  echo [정보] python\python.exe 가 이미 있습니다. 다시 받으려면 python 폴더를 지우고 실행하세요.
  pause
  exit /b 0
)

echo [1/3] 다운로드: %URL%
where curl >nul 2>nul
if %errorlevel%==0 (
  curl -L -o "%~dp0%ZIP%" "%URL%"
) else (
  powershell -NoProfile -Command "try{ Invoke-WebRequest -Uri '%URL%' -OutFile '%~dp0%ZIP%' -UseBasicParsing } catch { exit 1 }"
)
if not exist "%~dp0%ZIP%" (
  echo [오류] 다운로드 실패. 인터넷 연결/프록시를 확인하거나, 위 URL을 브라우저로 받아
  echo        이 폴더에 %ZIP% 로 저장한 뒤 다시 실행하세요.
  pause
  exit /b 1
)

echo [2/3] 압축 해제 -^> python\
powershell -NoProfile -Command "Expand-Archive -Path '%~dp0%ZIP%' -DestinationPath '%DEST%' -Force"
if not exist "%DEST%\python.exe" (
  echo [오류] 압축 해제 실패.
  pause
  exit /b 1
)

echo [3/3] import 경로 설정 (._pth 에 상위 폴더 추가)
rem 임베디드 Python은 기본적으로 상위 폴더의 패키지를 import하지 않는다.
rem python*._pth 파일에 상위 폴더(..)를 추가해 auditor 패키지를 찾게 한다.
for %%F in ("%DEST%\python*._pth") do (
  findstr /c:".." "%%F" >nul 2>nul || echo ..>>"%%F"
)

del "%~dp0%ZIP%" >nul 2>nul

echo.
echo ============================================================
echo   완료! 이제 이 폴더 전체를 폐쇄망 PC로 복사한 뒤
echo   run.bat 을 더블클릭하면 됩니다.
echo ============================================================
pause
