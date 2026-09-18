#!/usr/bin/env bash
# Deploy the cloud-sec auto-auditor as an Azure Function (Timer trigger), Linux/mac.
# English comments only (cp949-safe on Windows). Run from the deploy-azure/ directory.
#
# Prereqs:
#   - Azure CLI:            https://learn.microsoft.com/cli/azure/install-azure-cli
#   - Azure Functions Core Tools (func):
#                           https://learn.microsoft.com/azure/azure-functions/functions-run-local
#   - Logged in:            az login    (and: az account set --subscription <SUB_ID>)
#
# Usage:
#   ./deploy.sh <SLACK_WEBHOOK_URL> [RESOURCE_GROUP] [LOCATION] [APP_NAME]
#   Example: ./deploy.sh "https://hooks.slack.com/services/XXX/YYY/ZZZ"
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SLACK_WEBHOOK="${1:-}"
RG="${2:-rg-cloudsec-autoaudit}"
LOCATION="${3:-koreacentral}"
# Function app name must be globally unique; append a short random suffix if not given.
APP_NAME="${4:-cloudsec-autoaudit-$RANDOM}"
# Storage account name: lowercase alphanumeric, <=24 chars.
STORAGE="stcsaa$(date +%s | tail -c 8)"

if [ -z "$SLACK_WEBHOOK" ]; then
  echo "Usage: ./deploy.sh <SLACK_WEBHOOK_URL> [RESOURCE_GROUP] [LOCATION] [APP_NAME]"
  exit 1
fi

SUB_ID="$(az account show --query id -o tsv)"
echo "Subscription: $SUB_ID   ResourceGroup: $RG   App: $APP_NAME"

echo "[1/6] Resource group"
az group create -n "$RG" -l "$LOCATION" -o none

echo "[2/6] Storage account (required by Functions)"
az storage account create -n "$STORAGE" -g "$RG" -l "$LOCATION" --sku Standard_LRS -o none

echo "[3/6] Function app (Python 3.11, consumption plan)"
az functionapp create -n "$APP_NAME" -g "$RG" \
  --storage-account "$STORAGE" \
  --consumption-plan-location "$LOCATION" \
  --runtime python --runtime-version 3.11 --functions-version 4 --os-type Linux -o none

echo "[4/6] Managed identity + Reader role (real collection)"
az functionapp identity assign -n "$APP_NAME" -g "$RG" -o none
PRINCIPAL_ID="$(az functionapp identity show -n "$APP_NAME" -g "$RG" --query principalId -o tsv)"
az role assignment create --assignee "$PRINCIPAL_ID" --role "Reader" \
  --scope "/subscriptions/$SUB_ID" -o none || true
# Security Reader lets it read Defender alerts (best-effort).
az role assignment create --assignee "$PRINCIPAL_ID" --role "Security Reader" \
  --scope "/subscriptions/$SUB_ID" -o none || true

echo "[5/6] App settings (Slack, platform, subscription)"
az functionapp config appsettings set -n "$APP_NAME" -g "$RG" --settings \
  AUTOAUDITOR_PLATFORM=azure \
  AUTOAUDITOR_SLACK_WEBHOOK="$SLACK_WEBHOOK" \
  AUTOAUDITOR_ALERT_MIN_SEVERITY=HIGH \
  AUTOAUDITOR_REMEDIATION=suggest \
  AUTOAUDITOR_DRY_RUN=true \
  AZURE_SUBSCRIPTION_ID="$SUB_ID" -o none

echo "[6/6] Publish code (bundling auditor/ + autoauditor/)"
# Copy the two packages next to the function so imports resolve after publish.
rm -rf ./auditor ./autoauditor
cp -r "$PROJECT_ROOT/auditor" ./auditor
cp -r "$PROJECT_ROOT/autoauditor" ./autoauditor
func azure functionapp publish "$APP_NAME" --python

echo "Done. Function app: $APP_NAME  (schedule: hourly, see AutoAudit/function.json)"
echo "Tip: Slack alerts fire on HIGH+ issues or intrusion. Check logs in the Azure Portal."
