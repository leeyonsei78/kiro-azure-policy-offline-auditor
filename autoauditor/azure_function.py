"""Azure Functions 핸들러 (Timer Trigger 스케줄 실행용).

Azure Functions의 Timer Trigger(예: 매시간)로 이 함수를 주기 호출하면, 자동 점검 1회를
수행하고 심각/침해 시 Slack으로 알린다. AWS의 lambda_function.handler에 대응한다.

배포 메모:
  - 런타임: Python 3.11 (Azure Functions v4)
  - 코드에 auditor/ 와 autoauditor/ 패키지를 함께 포함
  - 함수 앱은 쓰기 가능한 임시 폴더가 다르므로 출력 폴더를 /tmp 또는 D:\\local\\Temp 로
    (환경변수 AUTOAUDITOR_OUTPUT_DIR) — 리포트 파일은 요약 확인용이며 Slack으로도 전송
  - 실제 수집: Azure SDK(azure-identity + azure-mgmt-*)가 있으면 collector_azure_sdk 사용,
    없으면 목업. Function App에 Managed Identity + 구독 Reader 역할을 부여해야 실제 수집됨.
  - requirements.txt 에 azure SDK를 선언하면 배포 시 자동 설치됨.

환경변수는 config.py 참고. Slack Webhook은 AUTOAUDITOR_SLACK_WEBHOOK 로 주입.
"""

from __future__ import annotations

import json
import logging
import os

from .config import Config
from .orchestrator import run_once


def main(mytimer=None):
    """Azure Functions Timer Trigger 진입점.

    function.json 의 bindings 이름(mytimer)과 맞춰 둔다. 인자는 사용하지 않아도 된다.
    """
    # 함수 앱의 쓰기 가능한 임시 경로로 출력 폴더 보정
    default_tmp = os.environ.get("TEMP") or os.environ.get("TMP") or "/tmp"
    os.environ.setdefault("AUTOAUDITOR_OUTPUT_DIR", os.path.join(default_tmp, "autoaudit_out"))
    # 플랫폼 기본값을 azure 로(환경변수로 덮어쓸 수 있음)
    os.environ.setdefault("AUTOAUDITOR_PLATFORM", "azure")

    cfg = Config.from_env()
    result = run_once(cfg)

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
    logging.info("autoauditor summary: %s", json.dumps(summary, ensure_ascii=False))
    return json.dumps(summary, ensure_ascii=False)
