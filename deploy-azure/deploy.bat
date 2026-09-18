@echo off
REM Deploy the cloud-sec auto-auditor as an Azure Function (Timer trigger), Windows.
REM English comments only (cp949-safe).
REM
REM Prereqs:
REM   - Azure CLI installed and logged in:  az login
REM     (and: az account set --subscription <SUB_ID>)
REM   - Azure Functions Core Tools (func) installed
REM
REM Usage:
REM   deploy.bat <SLACK_WEBHOOK_URL> [RESOURCE_GROUP] [LOCATION] [APP_NAME]
setlocal enabledelayedexpansion

cd /d "%~dp0"
set "PROJECT_ROOT=%~dp0.."

set "SLACK_WEBHOOK=%~1"
set "RG=%~2"
if "%RG%"=="" set "RG=rg-cloudsec-autoaudit"
set "LOCATION=%~3"
if "%LOCATION%"=="" set "LOCATION=koreacentral"
set "APP_NAME=%~4"
if "%APP_NAME%"=="" set "APP_NAME=cloudsec-autoaudit-%RANDOM%"
set "STORAGE=stcsaa%RANDOM%%RANDOM%"

if "%SLACK_WEBHOOK%"=="" (
  echo Usage: deploy.bat ^<SLACK_WEBHOOK_URL^> [RESOURCE_GROUP] [LOCATION] [APP_NAME]
  exit /b 1
)

for /f "delims=" %%i in ('az account show --query id -o tsv') do set "SUB_ID=%%i"
echo Subscription: %SUB_ID%   ResourceGroup: %RG%   App: %APP_NAME%

echo [1/6] Resource group
call az group create -n "%RG%" -l "%LOCATION%" -o none

echo [2/6] Storage account
call az storage account create -n "%STORAGE%" -g "%RG%" -l "%LOCATION%" --sku Standard_LRS -o none

echo [3/6] Function app
call az functionapp create -n "%APP_NAME%" -g "%RG%" --storage-account "%STORAGE%" --consumption-plan-location "%LOCATION%" --runtime python --runtime-version 3.11 --functions-version 4 --os-type Linux -o none

echo [4/6] Managed identity + Reader role
call az functionapp identity assign -n "%APP_NAME%" -g "%RG%" -o none
for /f "delims=" %%i in ('az functionapp identity show -n "%APP_NAME%" -g "%RG%" --query principalId -o tsv') do set "PRINCIPAL_ID=%%i"
call az role assignment create --assignee "%PRINCIPAL_ID%" --role "Reader" --scope "/subscriptions/%SUB_ID%" -o none
call az role assignment create --assignee "%PRINCIPAL_ID%" --role "Security Reader" --scope "/subscriptions/%SUB_ID%" -o none

echo [5/6] App settings
call az functionapp config appsettings set -n "%APP_NAME%" -g "%RG%" --settings AUTOAUDITOR_PLATFORM=azure AUTOAUDITOR_SLACK_WEBHOOK="%SLACK_WEBHOOK%" AUTOAUDITOR_ALERT_MIN_SEVERITY=HIGH AUTOAUDITOR_REMEDIATION=suggest AUTOAUDITOR_DRY_RUN=true AZURE_SUBSCRIPTION_ID="%SUB_ID%" -o none

echo [6/6] Publish code
if exist ".\auditor" rmdir /s /q ".\auditor"
if exist ".\autoauditor" rmdir /s /q ".\autoauditor"
xcopy /e /i /q "%PROJECT_ROOT%\auditor" ".\auditor" >nul
xcopy /e /i /q "%PROJECT_ROOT%\autoauditor" ".\autoauditor" >nul
call func azure functionapp publish "%APP_NAME%" --python

echo Done. Function app: %APP_NAME%  ^(hourly schedule^)
endlocal
