@echo off
REM Deploy the cloud-sec-auto-auditor Lambda with AWS SAM (Windows).
REM English comments only (cp949-safe).
REM
REM Prereqs:
REM   - AWS SAM CLI installed
REM   - AWS credentials configured (aws configure) with deploy permissions
REM
REM Usage:
REM   deploy.bat "https://hooks.slack.com/services/XXX/YYY/ZZZ" "rate(1 hour)"
setlocal

cd /d "%~dp0"

set "SLACK_WEBHOOK=%~1"
set "SCHEDULE=%~2"
if "%SCHEDULE%"=="" set "SCHEDULE=rate(1 hour)"

if "%SLACK_WEBHOOK%"=="" (
  echo Usage: deploy.bat ^<SLACK_WEBHOOK_URL^> [SCHEDULE]
  echo Example: deploy.bat https://hooks.slack.com/services/XXX/YYY/ZZZ "rate^(1 hour^)"
  exit /b 1
)

echo [1/2] sam build
call sam build
if errorlevel 1 (
  echo sam build failed.
  exit /b 1
)

echo [2/2] sam deploy
call sam deploy --no-confirm-changeset --parameter-overrides SlackWebhook="%SLACK_WEBHOOK%" Platform=aws AlertMinSeverity=HIGH Remediation=suggest DryRun=true Schedule="%SCHEDULE%"
if errorlevel 1 (
  echo sam deploy failed.
  exit /b 1
)

echo Done. Function cloud-sec-auto-auditor will run on schedule: %SCHEDULE%
echo Tip: run once now -^> aws lambda invoke --function-name cloud-sec-auto-auditor out.json
endlocal
