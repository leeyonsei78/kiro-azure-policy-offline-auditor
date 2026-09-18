"""자동 점검 CLI 진입점.

사용 예:
  python -m autoauditor                      # 환경변수 설정으로 1회 실행
  python -m autoauditor --platform azure --mock
  python -m autoauditor --config-file out.json  # 이미 수집한 구성 텍스트로 분석만

환경변수(config.py 참고): AUTOAUDITOR_PLATFORM, AUTOAUDITOR_SLACK_WEBHOOK,
AUTOAUDITOR_REMEDIATION, AUTOAUDITOR_DRY_RUN, AUTOAUDITOR_PROTECT_TAGS 등.
CLI 인자는 환경변수보다 우선한다.
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import Config, REMEDIATION_OFF, REMEDIATION_SUGGEST, REMEDIATION_AUTO
from .orchestrator import run_once


def _build_config(args) -> Config:
    cfg = Config.from_env()
    if args.platform:
        cfg.platform = args.platform
    if args.slack_webhook:
        cfg.slack_webhook = args.slack_webhook
    if args.min_severity:
        cfg.alert_min_severity = args.min_severity.upper()
    if args.output_dir:
        cfg.output_dir = args.output_dir
    if args.remediation:
        cfg.remediation = args.remediation
    if args.no_dry_run:
        cfg.dry_run = False
    if args.protect:
        cfg.protect_tags = [x.strip() for x in args.protect.split(",") if x.strip()]
    if args.mock:
        cfg.use_mock = True
    return cfg


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="autoauditor",
        description="클라우드 보안 자동 점검(수집→분석→침해탐지→알림→리포트→대응)")
    p.add_argument("--platform", choices=["aws", "azure"], help="점검 대상 클라우드")
    p.add_argument("--slack-webhook", help="Slack Incoming Webhook URL(미지정 시 환경변수/알림 생략)")
    p.add_argument("--min-severity", help="알림 최소 심각도(CRITICAL/HIGH/MEDIUM/LOW)")
    p.add_argument("--output-dir", help="리포트 저장 폴더")
    p.add_argument("--remediation", choices=[REMEDIATION_OFF, REMEDIATION_SUGGEST, REMEDIATION_AUTO],
                   help="대응 모드(off/suggest/auto). 기본 suggest(반자동)")
    p.add_argument("--no-dry-run", action="store_true",
                   help="(auto 모드에서) 실제 실행 허용. 주의: 실제 변경 발생")
    p.add_argument("--protect", help="차단 금지(화이트리스트) 키워드, 쉼표구분")
    p.add_argument("--mock", action="store_true", help="CLI 대신 목업 데이터로 실행(데모/테스트)")
    p.add_argument("--config-file", help="이미 수집한 구성 텍스트 파일(수집 단계 건너뜀)")
    p.add_argument("--threat-file", help="위협 로그/경고 텍스트 파일(침해 탐지용)")
    args = p.parse_args(argv)

    cfg = _build_config(args)

    # auto + 실제실행은 명시적 --no-dry-run 없이는 안전하게 dry_run 유지
    if cfg.remediation == REMEDIATION_AUTO and cfg.dry_run:
        print("[안내] 대응 모드=auto 이지만 dry-run 상태입니다. 실제 변경은 수행되지 않습니다."
              " 실제 실행하려면 --no-dry-run 을 명시하세요.", file=sys.stderr)

    config_text = None
    if args.config_file:
        with open(args.config_file, "r", encoding="utf-8") as f:
            config_text = f.read()
    threat_text = None
    if args.threat_file:
        with open(args.threat_file, "r", encoding="utf-8") as f:
            threat_text = f.read()

    result = run_once(cfg, config_text=config_text, threat_text=threat_text)

    # 요약 출력(스케줄러 로그에 남음)
    print(json.dumps({
        "timestamp": result["timestamp"],
        "platform": result["platform"],
        "collect_source": result["collect_source"],
        "score": result["score"],
        "grade": result["grade"],
        "findings": result["findings"],
        "severity_counts": result["severity_counts"],
        "threats": result["threats"],
        "remediations_planned": result["remediations_planned"],
        "notify": result["notify"],
        "reports": {k: v for k, v in result["reports"].items() if not k.endswith("_error")},
    }, ensure_ascii=False, indent=2))

    # 종료코드: CRITICAL/HIGH 이슈나 침해가 있으면 1(모니터링 연동 편의)
    sev = result["severity_counts"]
    threats_total = result["threats"].get("total", 0)
    if sev.get("CRITICAL") or sev.get("HIGH") or threats_total:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
