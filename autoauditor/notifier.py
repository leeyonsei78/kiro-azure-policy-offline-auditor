"""Slack 알림기.

심각한 보안 이슈·복합 위험(공격 경로)·침해 탐지가 발생하면 Slack Incoming Webhook으로
요약을 전송한다. 표준 라이브러리(urllib)만 사용한다.

- Webhook URL은 설정(환경변수)에서만 받는다(코드 하드코딩 금지).
- alert_min_severity 이상만 알림(소음 방지).
- 네트워크 실패 시 조용히 실패(파이프라인 중단 없음) + 결과 반환.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def _rank(sev: str) -> int:
    return _SEV_RANK.get((sev or "").upper(), 0)


def build_message(report_dict: dict, threat_events: list, cfg, remediations=None) -> dict:
    """Slack 메시지(payload dict) 구성. 알림 대상이 없으면 None 반환.

    report_dict: auditor 분석 결과(to_dict)
    threat_events: threat.detect() 결과(ThreatEvent 리스트)
    cfg: config.Config (alert_min_severity, platform 등)
    remediations: 생성된 차단/대응 명령 목록(선택)
    """
    min_rank = _rank(cfg.alert_min_severity)
    plat = {"aws": "AWS", "azure": "Azure"}.get(cfg.platform, cfg.platform)

    findings = report_dict.get("findings", [])
    alertable = [f for f in findings if _rank(f.get("severity")) >= min_rank]
    corr = report_dict.get("correlations", [])
    threats = [t.to_dict() if hasattr(t, "to_dict") else t for t in (threat_events or [])]
    alert_threats = [t for t in threats if _rank(t.get("severity")) >= min_rank]

    # 알릴 것이 하나도 없으면 전송 안 함
    if not alertable and not corr and not alert_threats:
        return None

    score = report_dict.get("score", "-")
    grade = report_dict.get("grade", "-")
    sev_counts = report_dict.get("severity_counts", {})
    sev_line = " · ".join(
        f"{_SEV_EMOJI.get(k, '')}{k} {sev_counts[k]}"
        for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev_counts.get(k)
    ) or "이슈 없음"

    lines = []
    header = f"*[클라우드 보안 자동점검] {plat}*  점수 {score}/100 (등급 {grade})"
    lines.append(header)
    lines.append(f"심각도: {sev_line}")

    # 침해 탐지 우선(가장 시급)
    if alert_threats:
        lines.append(f"\n:rotating_light: *침해 탐지 {len(alert_threats)}건*")
        for t in alert_threats[:5]:
            ip = f" (출발지 {t['source_ip']})" if t.get("source_ip") else ""
            lines.append(f"  {_SEV_EMOJI.get(t['severity'], '')} {t['title']}{ip}")

    # 복합 위험(공격 경로)
    if corr:
        lines.append(f"\n:warning: *복합 위험(공격 경로) {len(corr)}건*")
        for c in corr[:3]:
            lines.append(f"  • {c.get('title', '')}")

    # 조치 우선순위 TOP
    tops = report_dict.get("top_risks", [])
    if tops:
        lines.append("\n:dart: *조치 우선순위 TOP*")
        for t in tops[:5]:
            loc = ""
            # top_risks에는 location이 없을 수 있으니 findings에서 매칭 시도 생략(간결)
            lines.append(f"  {t.get('risk_score', '')}점 [{t.get('severity', '')}] {t.get('title', '')}{loc}")

    # 생성된 차단/대응 명령(반자동)
    if remediations:
        lines.append(f"\n:shield: *권장 차단/대응 {len(remediations)}건 (검토 후 실행)*")
        for r in remediations[:5]:
            lines.append(f"  • {r.get('title', '')}")
        if cfg.dry_run:
            lines.append("  _(dry-run: 실제 변경은 수행되지 않았습니다)_")

    text = "\n".join(lines)
    return {"text": text}


def send(webhook_url: str, payload: dict, timeout: int = 10) -> dict:
    """Slack Webhook으로 payload 전송. 결과 dict 반환(예외 던지지 않음)."""
    if not webhook_url:
        return {"ok": False, "skipped": True, "reason": "Slack Webhook 미설정"}
    if not payload:
        return {"ok": False, "skipped": True, "reason": "알림 대상 없음"}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {"ok": resp.status == 200, "status": resp.status, "body": body[:200]}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "reason": str(e)}
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return {"ok": False, "reason": f"전송 실패: {e}"}


def notify(report_dict: dict, threat_events: list, cfg, remediations=None) -> dict:
    """메시지 구성 + 전송을 한 번에. 결과 dict."""
    msg = build_message(report_dict, threat_events, cfg, remediations)
    if msg is None:
        return {"ok": True, "skipped": True, "reason": "알림 임계 미만(전송 안 함)"}
    return send(cfg.slack_webhook, msg)
