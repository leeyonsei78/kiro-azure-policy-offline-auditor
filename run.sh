#!/usr/bin/env bash
# ============================================================
#  Azure 정책 오프라인 보안검토 (ISMS-P) - macOS/Linux 실행 스크립트
#  ./run.sh 로 실행하면 웹 UI가 켜지고 브라우저가 열립니다.
#  폐쇄망 전용 - 인터넷/추가 설치 불필요 (Python 3.8+ 만 필요)
# ============================================================
set -e
cd "$(dirname "$0")"

HOST="127.0.0.1"
PORT="8080"

# Python 실행기 찾기
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "[오류] Python을 찾을 수 없습니다. Python 3.8+ 를 설치하세요." >&2
  exit 1
fi

echo "============================================================"
echo "  Azure 정책 오프라인 보안검토 (ISMS-P)"
echo "  웹 주소 : http://$HOST:$PORT   (종료: Ctrl+C)"
echo "  폐쇄망 전용 - 외부 네트워크 연결 없음"
echo "============================================================"

# 3초 뒤 브라우저 열기(백그라운드)
( sleep 3
  if command -v open >/dev/null 2>&1; then open "http://$HOST:$PORT"        # macOS
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "http://$HOST:$PORT"  # Linux
  fi ) >/dev/null 2>&1 &

exec "$PY" -m auditor --web --host "$HOST" --port "$PORT"
