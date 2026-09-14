"""리포트 포매팅 (텍스트 / 요약). 웹·CLI 공용."""

from __future__ import annotations

from .knowledge_base import control
from .models import AuditReport

_SEV_MARK = {
    "CRITICAL": "[치명]", "HIGH": "[높음]", "MEDIUM": "[중간]", "LOW": "[낮음]", "INFO": "[정보]",
}


def format_text(report: AuditReport) -> str:
    """CLI/파일 저장용 텍스트 리포트."""
    d = report.to_dict()
    lines: list[str] = []
    lines.append("=" * 64)
    lines.append(" Azure 정책 오프라인 보안검토 리포트 (ISMS-P 기준)")
    lines.append("=" * 64)
    lines.append(f" 점수: {d['score']}/100  등급: {d['grade']}")
    lines.append(f" 입력형식: {d['input_kind']}  파싱 리소스: {d['parsed_resources']}개")
    counts = d["severity_counts"]
    csum = "  ".join(f"{k}={counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if k in counts)
    lines.append(f" 발견 이슈: {d['total_findings']}건   {csum}")
    lines.append("")

    if not report.findings:
        for n in d["notes"]:
            lines.append(f" · {n}")
        return "\n".join(lines)

    # 통제항목별 그룹
    by_code: dict[str, list] = {}
    for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
        by_code.setdefault(f.control_code, []).append(f)

    for code in sorted(by_code, key=lambda c: [int(p) for p in c.split(".")]):
        ctrl = control(code) or {}
        lines.append("-" * 64)
        lines.append(f" [{code}] {ctrl.get('domain', '')} — {ctrl.get('desc', '')}")
        lines.append("-" * 64)
        for f in by_code[code]:
            lines.append(f"  {_SEV_MARK.get(f.severity.name, '')} {f.title}")
            if f.resource:
                lines.append(f"      대상: {f.resource}")
            lines.append(f"      문제: {f.description}")
            lines.append(f"      개선: {f.recommendation}")
            if f.evidence:
                lines.append(f"      근거: {f.evidence[:160]}")
            lines.append("")
        # 참고 점검 명령
        if ctrl.get("azure_cmd"):
            lines.append("      [참고] 재점검 CLI:")
            for cmd in ctrl["azure_cmd"].splitlines():
                lines.append(f"        $ {cmd}")
            lines.append("")

    lines.append("=" * 64)
    lines.append(" ※ 본 리포트는 오프라인 규칙 기반 자동 검토 결과이며 참고용입니다.")
    lines.append("    실제 조치 전 대상 환경과 업무 요건을 확인하세요. KISA 공식 심사자료를 대체하지 않습니다.")
    return "\n".join(lines)
