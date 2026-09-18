#!/usr/bin/env bash
# ============================================================
#  클라우드 보안 자동 점검 - 범용 스케줄 실행 스크립트 (Linux/mac)
# ============================================================
#  cron 등에 등록해 주기적으로 자동 점검을 수행합니다.
#  이 스크립트는 프로젝트 루트(auditor/, autoauditor/ 가 있는 폴더)에서 실행됩니다.
#
#  [준비]
#   1) Python 3.9+ 설치 (표준 라이브러리만 사용 — 추가 설치 불필요)
#   2) 점검 대상 클라우드 CLI 로그인(읽기 전용 권한 권장):
#        AWS:   aws configure   (또는 aws sso login)
#        Azure: az login
#   3) 아래 환경변수 설정(비밀값은 코드/스크립트에 넣지 말고 여기서 export):
#
#  [환경변수 예시]
#   export AUTOAUDITOR_PLATFORM=aws
#   export AUTOAUDITOR_SLACK_WEBHOOK="https://hooks.slack.com/services/XXX/YYY/ZZZ"
#   export AUTOAUDITOR_ALERT_MIN_SEVERITY=HIGH
#   export AUTOAUDITOR_OUTPUT_DIR="/var/log/autoaudit"
#   export AUTOAUDITOR_REMEDIATION=suggest      # off | suggest(반자동, 기본) | auto
#   export AUTOAUDITOR_DRY_RUN=true             # auto라도 true면 실제 변경 안 함
#   export AUTOAUDITOR_PROTECT_TAGS="prod-critical,dns"   # 차단 금지 키워드
#
#  [cron 등록 예시] 매시간 실행:
#   0 * * * * cd /opt/kiro-azure-policy-offline-auditor && \
#             AUTOAUDITOR_PLATFORM=aws AUTOAUDITOR_SLACK_WEBHOOK="..." \
#             ./autoauditor/run_scheduled.sh >> /var/log/autoaudit/cron.log 2>&1
# ============================================================
set -u

# 프로젝트 루트로 이동(이 스크립트의 상위 폴더)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || exit 2

PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 자동 점검 시작 (platform=${AUTOAUDITOR_PLATFORM:-aws})"
"$PY" -m autoauditor "$@"
RC=$?
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 종료 코드 $RC (0=정상, 1=CRITICAL/HIGH 또는 침해 존재)"
exit $RC
