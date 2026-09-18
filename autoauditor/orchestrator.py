"""자동 점검 오케스트레이터.

한 번의 실행(run_once)에서 전체 파이프라인을 수행한다:
  1) 수집(collector)      — 클라우드 구성 정보(+ 선택적으로 위협 로그)
  2) 분석(auditor.engine) — 취약 구성·위험 점수·복합 위험
  3) 침해 탐지(threat)    — GuardDuty/Defender/로그 상관분석
  4) 대응 계획(remediation) — 차단/대응 명령 생성(기본 반자동)
  5) 알림(notifier)       — 심각/복합/침해 시 Slack 전송
  6) 리포트 저장(report)  — 텍스트/HTML/엑셀을 output_dir에 타임스탬프로 보관
결과 요약 dict를 반환한다(스케줄러/Lambda가 로깅에 사용).

표준 라이브러리만 사용. threat_text가 없으면 침해 탐지는 수집 텍스트에 대해 수행한다.
"""

from __future__ import annotations

import datetime
import json
import os

from auditor.engine import analyze, build_statistics
from auditor import report as report_mod

from . import collector, threat, remediation, notifier
from .config import Config


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def _save_reports(rep, out_dir: str, stamp: str) -> dict:
    """텍스트/HTML/엑셀 리포트를 저장하고 경로를 반환. 실패해도 파이프라인 유지."""
    os.makedirs(out_dir, exist_ok=True)
    saved = {}
    base = f"autoaudit_{stamp}"
    try:
        p = os.path.join(out_dir, base + ".txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(report_mod.format_text(rep))
        saved["text"] = p
    except Exception as e:  # noqa: BLE001
        saved["text_error"] = str(e)
    try:
        p = os.path.join(out_dir, base + ".html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(report_mod.format_html(rep))
        saved["html"] = p
    except Exception as e:  # noqa: BLE001
        saved["html_error"] = str(e)
    try:
        p = os.path.join(out_dir, base + ".xlsx")
        with open(p, "wb") as f:
            f.write(report_mod.format_xlsx(rep))
        saved["xlsx"] = p
    except Exception as e:  # noqa: BLE001
        saved["xlsx_error"] = str(e)
    return saved


def run_once(cfg: Config | None = None, *, config_text: str | None = None,
             threat_text: str | None = None) -> dict:
    """자동 점검 1회 실행.

    config_text: 이미 수집된 구성 텍스트가 있으면 그대로 사용(수집 단계 건너뜀).
    threat_text: 위협 로그/경고 텍스트(없으면 config_text에 대해 침해 탐지).
    """
    cfg = cfg or Config.from_env()
    stamp = _ts()

    # 1) 수집
    if config_text is None:
        col = collector.collect(cfg.platform, use_mock=cfg.use_mock)
        config_text = col["text"]
        source = col["source"]
        ran = col["ran"]
    else:
        source, ran = "provided", 0

    # 2) 분석(취약 구성)
    rep = analyze(config_text)
    rd = rep.to_dict()
    rd["statistics"] = build_statistics(rd)

    # 3) 침해 탐지
    ev = threat.detect(threat_text or config_text, platform=cfg.platform,
                       login_fail_threshold=cfg.login_fail_threshold)
    threat_summary = threat.summarize(ev)

    # 4) 대응 계획(차단/조치 명령)
    rem = remediation.plan(rd, ev, cfg)

    # 5) 알림(Slack)
    notify_result = notifier.notify(rd, ev, cfg, remediations=rem)

    # 6) 리포트 저장
    saved = _save_reports(rep, cfg.output_dir, stamp)

    # 침해 요약 파일도 별도 저장(감사 증적)
    try:
        os.makedirs(cfg.output_dir, exist_ok=True)
        meta = {
            "timestamp": stamp,
            "platform": cfg.platform,
            "collect_source": source,
            "commands_run": ran,
            "score": rd.get("score"),
            "grade": rd.get("grade"),
            "severity_counts": rd.get("severity_counts", {}),
            "correlations": len(rd.get("correlations", [])),
            "threats": [e.to_dict() for e in ev],
            "threat_summary": threat_summary,
            "remediations": rem,
            "notify": notify_result,
            "config": cfg.redacted(),
        }
        with open(os.path.join(cfg.output_dir, f"autoaudit_{stamp}.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        saved["json"] = os.path.join(cfg.output_dir, f"autoaudit_{stamp}.json")
    except Exception as e:  # noqa: BLE001
        saved["json_error"] = str(e)

    return {
        "ok": True,
        "timestamp": stamp,
        "platform": cfg.platform,
        "collect_source": source,
        "score": rd.get("score"),
        "grade": rd.get("grade"),
        "findings": rd.get("total_findings", 0),
        "severity_counts": rd.get("severity_counts", {}),
        "correlations": len(rd.get("correlations", [])),
        "threats": threat_summary,
        "remediation_mode": cfg.remediation,
        "remediations_planned": len(rem),
        "notify": notify_result,
        "reports": saved,
    }
