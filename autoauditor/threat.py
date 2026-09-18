"""침해 탐지·분석 모듈 (수동/자동 공통).

클라우드 위협 신호 소스에서 침해 징후를 탐지하고 상관분석한다:
  - AWS: GuardDuty findings, CloudTrail 이벤트(root 사용, 콘솔 로그인 실패 등)
  - Azure: Defender for Cloud 보안 경고, Activity Log(비정상 작업)
  - 공통: 로그인 실패 급증(무차별 대입), 비정상 지역/시간대 접근

입력은 JSON(각 서비스 CLI 출력)이거나 텍스트 로그이며, 표준 라이브러리만 사용한다.
반환은 ThreatEvent 리스트 — 각 이벤트에 심각도·유형·근거·권장 대응이 담긴다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict


@dataclass
class ThreatEvent:
    threat_type: str          # 예: brute_force, root_activity, guardduty_finding
    severity: str             # CRITICAL/HIGH/MEDIUM/LOW
    title: str
    description: str
    platform: str = "aws"
    source_ip: str = ""       # 관련 출발지 IP(있으면 — 차단 대상)
    principal: str = ""       # 관련 계정/주체(있으면)
    evidence: str = ""
    recommendation: str = ""
    mitre_id: str = ""
    mitre_name: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _first_ip(text: str) -> str:
    m = _IP_RE.search(text or "")
    return m.group(0) if m else ""


def _iter_objs(text: str):
    """입력 텍스트에서 JSON 배열/객체를 최대한 추출해 dict를 순회."""
    from auditor.parser import parse, iter_dicts
    parsed = parse(text)
    for obj in parsed.get("objects", []):
        for d in iter_dicts(obj):
            if isinstance(d, dict) and d:
                yield d


def _sev_from_guardduty(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"
    if s >= 7:
        return "HIGH"
    if s >= 4:
        return "MEDIUM"
    return "LOW"


def detect(text: str, platform: str = "aws", login_fail_threshold: int = 5) -> list[ThreatEvent]:
    """침해 징후 텍스트/JSON에서 ThreatEvent 목록을 산출."""
    events: list[ThreatEvent] = []
    low = (text or "").lower()

    # ── 구조(JSON) 기반 ──
    for d in _iter_objs(text):
        flat = json.dumps(d, ensure_ascii=False)
        fl = flat.lower()

        # AWS GuardDuty finding — Type이 "Category:Resource/ThreatName" 형태
        gtype = str(d.get("Type") or d.get("type") or "")
        is_gd = ("guardduty" in fl) or (
            bool(re.match(r"^[A-Za-z]+:[A-Za-z0-9]+/", gtype))
            and (d.get("Severity") is not None or d.get("severity") is not None))
        if is_gd and gtype:
            sev = _sev_from_guardduty(d.get("Severity") or d.get("severity"))
            ip = _first_ip(flat)
            events.append(ThreatEvent(
                "guardduty_finding", sev,
                f"GuardDuty 위협 탐지: {gtype}",
                "GuardDuty가 위협 활동을 탐지했습니다. 유형·대상·출발지를 확인하세요.",
                platform="aws", source_ip=ip, evidence=flat[:400],
                recommendation="해당 인스턴스/계정을 격리하고 자격증명을 회전하세요.",
                mitre_id="T1078", mitre_name="Valid Accounts",
            ))

        # Azure Defender 보안 경고
        if ("alerttype" in fl or "alertdisplayname" in fl):
            name = str(d.get("alertDisplayName") or d.get("displayName") or d.get("AlertType") or "보안 경고")
            sev = str(d.get("severity") or d.get("Severity") or "MEDIUM").upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                sev = "MEDIUM"
            events.append(ThreatEvent(
                "defender_alert", sev,
                f"Defender for Cloud 경고: {name}",
                "Defender for Cloud가 의심 활동을 탐지했습니다.",
                platform="azure", source_ip=_first_ip(flat), evidence=flat[:400],
                recommendation="경고 상세를 확인하고 영향 리소스를 격리·조치하세요.",
                mitre_id="T1078", mitre_name="Valid Accounts",
            ))

        # 루트/전역관리자 사용 (CloudTrail/ActivityLog)
        user_ident = fl
        if ("useridentity" in fl or "caller" in fl or "eventname" in fl):
            if re.search(r'"type"\s*:\s*"root"|"username"\s*:\s*"root"|arn:aws:iam::[^:]*:root', user_ident):
                events.append(ThreatEvent(
                    "root_activity", "HIGH",
                    "루트 계정 활동 탐지",
                    "루트(root) 계정으로 API/콘솔 활동이 확인되었습니다. 평상시 루트 사용은 금지입니다.",
                    platform="aws", source_ip=_first_ip(flat),
                    principal="root", evidence=flat[:400],
                    recommendation="루트 활동 원인을 즉시 확인하고, 탈취 의심 시 자격증명을 회전하세요.",
                    mitre_id="T1078.004", mitre_name="Valid Accounts: Cloud Accounts",
                ))

    # ── 텍스트 기반: 루트 계정 활동(JSON이 아닌 로그 라인에도 대응) ──
    if re.search(r'"type"\s*:\s*"root"|"username"\s*:\s*"root"|arn:aws:iam::[^:"\s]*:root|\broot\b[^\n]*\b(useridentity|console|login|api)\b',
                 low) and "root_activity" not in {e.threat_type for e in events}:
        events.append(ThreatEvent(
            "root_activity", "HIGH",
            "루트 계정 활동 탐지",
            "루트(root) 계정으로 API/콘솔 활동이 확인되었습니다. 평상시 루트 사용은 금지입니다.",
            platform="aws", source_ip=_first_ip(text), principal="root",
            evidence=_snippet(text),
            recommendation="루트 활동 원인을 즉시 확인하고, 탈취 의심 시 자격증명을 회전하세요.",
            mitre_id="T1078.004", mitre_name="Valid Accounts: Cloud Accounts",
        ))

    # ── 텍스트/집계 기반: 로그인 실패 급증(무차별 대입) ──
    #   같은 IP가 실패 로그인 이벤트를 N회 이상 → brute force 의심
    ip_counts: dict[str, int] = {}
    for line in (text or "").splitlines():
        ll = line.lower()
        # '실패/거부/무효' + '로그인/인증' 키워드가 같은 줄에 있으면 실패 로그인으로 간주
        if re.search(r"fail|denied|invalid|unauthor", ll) and \
                re.search(r"login|signin|sign-in|authentication|logon|logins", ll):
            ip = _first_ip(line)
            key = ip or "(IP미상)"
            ip_counts[key] = ip_counts.get(key, 0) + 1
    if ip_counts:
        for ip, cnt in ip_counts.items():
            if cnt >= login_fail_threshold:
                events.append(ThreatEvent(
                    "brute_force", "HIGH",
                    f"로그인 실패 급증(무차별 대입 의심): {ip} — {cnt}회",
                    f"동일 출발지에서 로그인 실패가 {cnt}회 발생했습니다(임계 {login_fail_threshold}회). "
                    "비밀번호 무차별 대입 공격일 수 있습니다.",
                    platform=platform, source_ip=("" if ip == "(IP미상)" else ip),
                    evidence=f"실패 {cnt}회 / 출발지 {ip}",
                    recommendation="해당 IP를 차단하고, 대상 계정에 MFA·계정 잠금 정책을 강화하세요.",
                    mitre_id="T1110", mitre_name="Brute Force",
                ))

    # 알려진 악성 지표 키워드(간단 룰) — 필요 시 확장
    if re.search(r"port\s*scan|malware|cryptomining|c2\b|command\s*and\s*control|exfiltration", low):
        events.append(ThreatEvent(
            "malicious_indicator", "MEDIUM",
            "악성 활동 지표 탐지(키워드)",
            "로그/경고에서 포트스캔·마이닝·C2 등 악성 활동 관련 키워드가 확인되었습니다.",
            platform=platform, source_ip=_first_ip(text),
            evidence=_snippet(text),
            recommendation="관련 리소스의 통신을 격리하고 상세 로그를 분석하세요.",
            mitre_id="T1046", mitre_name="Network Service Discovery",
        ))

    # 중복 제거(같은 유형+IP)
    seen = set()
    uniq = []
    for e in events:
        k = (e.threat_type, e.source_ip, e.title)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(e)
    return uniq


def _snippet(text: str, width: int = 160) -> str:
    t = re.sub(r"\s+", " ", (text or "").strip())
    return t[:width] + ("…" if len(t) > width else "")


def summarize(events: list[ThreatEvent]) -> dict:
    """침해 이벤트 요약(심각도별 카운트 + 차단 후보 IP)."""
    by_sev: dict[str, int] = {}
    ips: list[str] = []
    for e in events:
        by_sev[e.severity] = by_sev.get(e.severity, 0) + 1
        if e.source_ip and e.source_ip not in ips:
            ips.append(e.source_ip)
    return {"total": len(events), "by_severity": by_sev, "block_candidate_ips": ips}
