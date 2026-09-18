#!/usr/bin/env bash
# Deploy the cloud-sec-auto-auditor Lambda with AWS SAM (Linux/mac).
# English comments only (cp949-safe). Run from the deploy/ directory or project root.
#
# Prereqs:
#   - AWS SAM CLI installed:  https://docs.aws.amazon.com/serverless-application-model/
#   - AWS credentials configured (aws configure) with deploy permissions
#     (CloudFormation, Lambda, IAM, S3, Events)
#
# Usage:
#   ./deploy.sh "https://hooks.slack.com/services/XXX/YYY/ZZZ" "rate(1 hour)"
#   (2nd arg optional; defaults to rate(1 hour))
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

SLACK_WEBHOOK="${1:-}"
SCHEDULE="${2:-rate(1 hour)}"

if [ -z "$SLACK_WEBHOOK" ]; then
  echo "Usage: ./deploy.sh <SLACK_WEBHOOK_URL> [SCHEDULE]"
  echo "Example: ./deploy.sh https://hooks.slack.com/services/XXX/YYY/ZZZ \"rate(1 hour)\""
  exit 1
fi

echo "[1/2] sam build"
sam build

echo "[2/2] sam deploy"
sam deploy \
  --no-confirm-changeset \
  --parameter-overrides \
    SlackWebhook="$SLACK_WEBHOOK" \
    Platform=aws \
    AlertMinSeverity=HIGH \
    Remediation=suggest \
    DryRun=true \
    Schedule="$SCHEDULE"

echo "Done. Function 'cloud-sec-auto-auditor' will run on schedule: $SCHEDULE"
echo "Tip: run once now ->  aws lambda invoke --function-name cloud-sec-auto-auditor /tmp/out.json && cat /tmp/out.json"
