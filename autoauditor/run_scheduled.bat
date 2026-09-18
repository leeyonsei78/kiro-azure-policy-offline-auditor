@echo off
REM ============================================================
REM  클라우드 보안 자동 점검 - 범용 스케줄 실행 (Windows)
REM  작업 스케줄러(Task Scheduler)에 등록해 주기 실행합니다.
REM ============================================================
REM  [준비]
REM   1) Python 3.9+ 설치
REM   2) 클라우드 CLI 로그인(읽기 전용 권장): aws configure  또는  az login
REM   3) 아래 환경변수 설정(비밀값은 시스템 환경변수로 관리 권장)
REM
REM  [환경변수 예시 - 시스템 환경변수 또는 이 파일에서 set]
REM   set AUTOAUDITOR_PLATFORM=aws
REM   set AUTOAUDITOR_SLACK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ
REM   set AUTOAUDITOR_ALERT_MIN_SEVERITY=HIGH
REM   set AUTOAUDITOR_OUTPUT_DIR=C:\autoaudit
REM   set AUTOAUDITOR_REMEDIATION=suggest
REM
REM  [작업 스케줄러 등록 예시] 매시간:
REM   schtasks /Create /SC HOURLY /TN "CloudSecAudit" ^
REM     /TR "\"C:\kiro-azure-policy-offline-auditor\autoauditor\run_scheduled.bat\""
REM ============================================================
setlocal

REM 프로젝트 루트(이 배치의 상위 폴더)로 이동
cd /d "%~dp0.."

set PY=python
where %PY% >nul 2>nul
if errorlevel 1 set PY=py

echo [%date% %time%] 자동 점검 시작
%PY% -m autoauditor %*
set RC=%ERRORLEVEL%
echo [%date% %time%] 종료 코드 %RC%  ^(0=정상, 1=CRITICAL/HIGH 또는 침해 존재^)
endlocal & exit /b %RC%
