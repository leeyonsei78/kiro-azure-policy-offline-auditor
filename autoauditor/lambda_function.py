"""AWS Lambda 핸들러 (EventBridge 스케줄 트리거용).

EventBridge 규칙(예: rate(1 hour))으로 이 함수를 주기 호출하면, 자동 점검 1회를
수행하고 심각/침해 시 Slack으로 알린다.

배포 메모:
  - 런타임: python3.12 (표준 라이브러리만 사용하므로 추가 의존성 불필요)
  - 코드에 auditor/ 와 autoauditor/ 두 패키지를 함께 포함해 업로드
  - Lambda는 파일시스템 쓰기가 /tmp 만 가능 → 환경변수 AUTOAUDITOR_OUTPUT_DIR=/tmp/out
  - aws CLI가 Lambda 기본 런타임에 없음 → 실제 수집은 boto3 기반 수집기로 대체하거나,
    (권장) 이 함수에는 이미 수집된 데이터/이벤트를 전달하거나 use_mock으로 데모.
    * 실제 운영에서 CLI 수집이 필요하면 컨테이너 이미지에 aws CLI를 포함해 배포.
  - 필요한 IAM: 읽기 전용 조회 권한(점검 대상) + (auto 차단 시) 해당 리소스 수정 권한

환경변수는 config.py 참고. Slack Webhook은 AUTOAUDITOR_SLACK_WEBHOOK 로 주입.
"""

from __future__ import annotations

import json
import os

from .config import Config
from .orchestrator import run_once


def handler(event, context=None):
    """Lambda 진입점. event로 config_text/threat_text를 넘길 수도 있다(선택)."""
    # Lambda는 /tmp 만 쓰기 가능 — 기본 출력 폴더 보정
    os.environ.setdefault("AUTOAUDITOR_OUTPUT_DIR", "/tmp/autoaudit_out")

    cfg = Config.from_env()

    config_text = None
    threat_text = None
    if isinstance(event, dict):
        config_text = event.get("config_text")
        threat_text = event.get("threat_text")
        if event.get("mock"):
            cfg.use_mock = True

    result = run_once(cfg, config_text=config_text, threat_text=threat_text)

    # 리포트 파일 경로는 /tmp라 호출 후 사라짐 → 요약만 반환(상세는 Slack/로그로)
    summary = {
        "timestamp": result["timestamp"],
        "platform": result["platform"],
        "score": result["score"],
        "grade": result["grade"],
        "findings": result["findings"],
        "severity_counts": result["severity_counts"],
        "threats": result["threats"],
        "remediations_planned": result["remediations_planned"],
        "notify": result["notify"],
    }
    print(json.dumps(summary, ensure_ascii=False))
    return {"statusCode": 200, "body": json.dumps(summary, ensure_ascii=False)}
