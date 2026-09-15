"""리포트 포매팅 (텍스트 / CSV / HTML). 웹·CLI 공용.

각 이슈(Finding)는 platform(aws/azure)을 가지며, 리포트 전반에서 플랫폼을 구별해 표시한다.
재점검 CLI·판단기준·개선안은 control_for(code, platform)로 플랫폼에 맞춰 가져온다.
"""

from __future__ import annotations

from .knowledge_base import control_for
from .models import AuditReport

_SEV_MARK = {
    "CRITICAL": "[치명]", "HIGH": "[높음]", "MEDIUM": "[중간]", "LOW": "[낮음]", "INFO": "[정보]",
}

_PLATFORM_LABEL = {"aws": "AWS", "azure": "Azure"}


def _plat_label(p: str) -> str:
    return _PLATFORM_LABEL.get(p, (p or "").upper())


def _platform_summary(report: AuditReport) -> str:
    pc = report.platform_counts()
    if not pc:
        return ""
    return " · ".join(f"{_plat_label(k)} {pc[k]}" for k in sorted(pc))


def format_text(report: AuditReport) -> str:
    """CLI/파일 저장용 텍스트 리포트."""
    d = report.to_dict()
    lines: list[str] = []
    lines.append("=" * 64)
    lines.append(" 클라우드 정책 오프라인 보안검토 리포트 (ISMS-P 기준, AWS/Azure)")
    lines.append("=" * 64)
    lines.append(f" 점수: {d['score']}/100  등급: {d['grade']}")
    lines.append(f" 입력형식: {d['input_kind']}  파싱 리소스: {d['parsed_resources']}개")
    counts = d["severity_counts"]
    csum = "  ".join(f"{k}={counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if k in counts)
    lines.append(f" 발견 이슈: {d['total_findings']}건   {csum}")
    psum = _platform_summary(report)
    if psum:
        lines.append(f" 플랫폼별: {psum}")
    lines.append("")

    if not report.findings:
        for n in d["notes"]:
            lines.append(f" · {n}")
        return "\n".join(lines)

    # (통제코드, 플랫폼)별 그룹 — 같은 코드라도 AWS/Azure를 분리 표기
    by_key: dict[tuple, list] = {}
    for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
        by_key.setdefault((f.control_code, f.platform), []).append(f)

    def _sort_key(k):
        code, plat = k
        return ([int(p) for p in code.split(".")], plat)

    for (code, plat) in sorted(by_key, key=_sort_key):
        ctrl = control_for(code, plat)
        lines.append("-" * 64)
        lines.append(f" [{_plat_label(plat)}] [{code}] {ctrl.get('domain', '')} — {ctrl.get('desc', '')}")
        lines.append("-" * 64)
        for f in by_key[(code, plat)]:
            lines.append(f"  {_SEV_MARK.get(f.severity.name, '')} {f.title}")
            if f.resource:
                lines.append(f"      대상: {f.resource}")
            lines.append(f"      문제: {f.description}")
            lines.append(f"      개선: {f.recommendation}")
            if getattr(f, "bad_example", ""):
                lines.append(f"      위반 예시: {f.bad_example}")
            if getattr(f, "good_example", ""):
                lines.append(f"      개선 예시: {f.good_example}")
            if f.evidence:
                lines.append(f"      근거: {f.evidence[:160]}")
            lines.append("")
        if ctrl.get("cmd"):
            lines.append(f"      [참고] {_plat_label(plat)} 재점검 CLI:")
            for cmd in ctrl["cmd"].splitlines():
                lines.append(f"        $ {cmd}")
            lines.append("")

    lines.append("=" * 64)
    lines.append(" ※ 본 리포트는 오프라인 규칙 기반 자동 검토 결과이며 참고용입니다.")
    lines.append("    실제 조치 전 대상 환경과 업무 요건을 확인하세요. KISA 공식 심사자료를 대체하지 않습니다.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV (엑셀용) — 표준 라이브러리 csv 사용, UTF-8 BOM으로 한글 깨짐 방지
# ---------------------------------------------------------------------------
_CSV_COLUMNS = [
    ("platform", "플랫폼"),
    ("control_code", "통제항목"),
    ("control_domain", "영역"),
    ("severity", "심각도"),
    ("issue_type", "이슈유형"),
    ("title", "제목"),
    ("resource", "대상리소스"),
    ("description", "문제(판단기준)"),
    ("recommendation", "개선방안"),
    ("bad_example", "위반예시"),
    ("good_example", "개선예시"),
    ("evidence", "근거"),
]


def format_csv(report: AuditReport) -> str:
    """검토 결과를 CSV 문자열로. Excel에서 바로 열 수 있도록 UTF-8 BOM을 접두한다."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([f"# 클라우드 정책 오프라인 보안검토 (ISMS-P)  점수 {report.score()}/100  등급 {report.grade()}"])
    counts = report.severity_counts()
    csum = " ".join(f"{k}={counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if k in counts)
    psum = _platform_summary(report)
    writer.writerow([f"# 발견 이슈 {len(report.findings)}건  {csum}" + (f"  |  {psum}" if psum else "")])
    writer.writerow([])
    writer.writerow([label for _, label in _CSV_COLUMNS])
    for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
        row = f.to_dict()
        row["platform"] = _plat_label(row.get("platform", ""))
        writer.writerow([str(row.get(key, "")) for key, _ in _CSV_COLUMNS])
    return "\ufeff" + buf.getvalue()


# ---------------------------------------------------------------------------
# HTML (인쇄 → PDF) — 자체완결형(인라인 CSS). 브라우저 인쇄로 PDF 저장.
# ---------------------------------------------------------------------------
def _esc(s) -> str:
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


_SEV_COLOR = {
    "CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#c9a227", "LOW": "#2980b9", "INFO": "#7f8c8d",
}
_PLAT_COLOR = {"aws": "#ff9900", "azure": "#0078d4"}


def format_html(report: AuditReport) -> str:
    """인쇄(PDF 저장)용 자체완결형 HTML 리포트."""
    d = report.to_dict()
    counts = d["severity_counts"]
    csum = " · ".join(f"{k} {counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if k in counts) or "이슈 없음"
    psum = _platform_summary(report)

    # (통제코드, 플랫폼)별 그룹
    by_key: dict[tuple, list] = {}
    for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
        by_key.setdefault((f.control_code, f.platform), []).append(f)

    def _sort_key(k):
        code, plat = k
        return ([int(p) for p in code.split(".")], plat)

    sections = []
    for (code, plat) in sorted(by_key, key=_sort_key):
        ctrl = control_for(code, plat)
        pcolor = _PLAT_COLOR.get(plat, "#555")
        rows = []
        for f in by_key[(code, plat)]:
            sev = f.severity.name
            color = _SEV_COLOR.get(sev, "#555")
            evi = f"<div class='evi'>{_esc(f.evidence[:220])}</div>" if f.evidence else ""
            res = f"<div class='res'><b>대상:</b> {_esc(f.resource)}</div>" if f.resource else ""
            bad = (f"<div class='ex bad'><b>✗ 위반 예시:</b> <code>{_esc(f.bad_example)}</code></div>"
                   if getattr(f, "bad_example", "") else "")
            good = (f"<div class='ex good'><b>✓ 개선 예시:</b> <code>{_esc(f.good_example)}</code></div>"
                    if getattr(f, "good_example", "") else "")
            rows.append(
                f"<div class='finding'>"
                f"<div class='ftop'><span class='sev' style='background:{color}'>{_esc(sev)}</span>"
                f"<span class='ftitle'>{_esc(f.title)}</span></div>"
                f"{res}"
                f"<div class='p'><b>문제:</b> {_esc(f.description)}</div>"
                f"<div class='fix'><b>개선:</b> {_esc(f.recommendation)}</div>"
                f"{bad}{good}{evi}</div>"
            )
        cmd_html = ""
        if ctrl.get("cmd"):
            cmds = "<br>".join("$ " + _esc(c) for c in ctrl["cmd"].splitlines())
            cmd_html = f"<div class='cmd'><b>[참고] {_esc(_plat_label(plat))} 재점검 CLI</b><br>{cmds}</div>"
        sections.append(
            f"<section><h2><span class='plat' style='background:{pcolor}'>{_esc(_plat_label(plat))}</span>"
            f"[{_esc(code)}] {_esc(ctrl.get('domain',''))}</h2>"
            f"<p class='desc'>{_esc(ctrl.get('desc',''))}</p>"
            f"{''.join(rows)}{cmd_html}</section>"
        )

    body_sections = "".join(sections) if sections else (
        "<section><p class='desc'>" + _esc((d["notes"] or ["탐지된 이슈가 없습니다."])[0]) + "</p></section>"
    )
    plat_meta = f" · 플랫폼: {_esc(psum)}" if psum else ""

    return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<title>클라우드 정책 오프라인 보안검토 리포트 (ISMS-P)</title>
<style>
  body{{ font-family:"Malgun Gothic","맑은 고딕",system-ui,sans-serif; color:#1a1a1a; margin:32px; font-size:13px; line-height:1.55; }}
  h1{{ font-size:20px; margin:0 0 4px; }}
  .meta{{ color:#555; font-size:12px; margin-bottom:2px; }}
  .scorebox{{ display:inline-block; border:2px solid #333; border-radius:8px; padding:8px 16px; margin:10px 0; }}
  .score{{ font-size:26px; font-weight:800; }}
  h2{{ font-size:15px; border-bottom:2px solid #333; padding-bottom:3px; margin:22px 0 6px; }}
  .plat{{ color:#fff; font-size:11px; font-weight:700; padding:1px 8px; border-radius:4px; margin-right:8px; vertical-align:middle; }}
  .desc{{ color:#555; margin:0 0 8px; }}
  .finding{{ border:1px solid #ccc; border-radius:6px; padding:8px 10px; margin:6px 0; page-break-inside:avoid; }}
  .ftop{{ display:flex; align-items:center; gap:8px; }}
  .sev{{ color:#fff; font-size:11px; font-weight:700; padding:1px 8px; border-radius:4px; }}
  .ftitle{{ font-weight:700; }}
  .res,.p,.fix{{ margin-top:3px; }}
  .fix{{ background:#f2f7ff; border-left:3px solid #2980b9; padding:4px 8px; }}
  .ex{{ margin-top:4px; padding:4px 8px; border-radius:4px; font-size:12px; }}
  .ex code{{ font-family:Consolas,monospace; word-break:break-all; }}
  .ex.bad{{ background:#fdecea; border-left:3px solid #c0392b; }}
  .ex.good{{ background:#eafaf1; border-left:3px solid #27ae60; }}
  .evi{{ font-family:Consolas,monospace; font-size:11px; color:#666; background:#f6f6f6; padding:4px 6px; margin-top:4px; word-break:break-all; }}
  .cmd{{ font-family:Consolas,monospace; font-size:11px; color:#333; background:#fafafa; border:1px dashed #bbb; padding:6px 8px; margin:6px 0; }}
  .foot{{ margin-top:24px; padding-top:8px; border-top:1px solid #ccc; color:#777; font-size:11px; }}
  .noprint{{ margin:12px 0; }}
  @media print{{ .noprint{{ display:none; }} body{{ margin:12mm; }} }}
</style></head>
<body>
  <div class="noprint" style="text-align:right">
    <button onclick="window.print()" style="padding:8px 16px;font-size:14px;cursor:pointer">🖨️ 인쇄 / PDF로 저장</button>
  </div>
  <h1>🛡️ 클라우드 정책 오프라인 보안검토 리포트</h1>
  <div class="meta">기준: ISMS-P 클라우드 인프라 통제항목 (AWS/Azure) · 오프라인 규칙 기반 자동 검토</div>
  <div class="scorebox"><span class="score">{d['score']}</span> / 100점 &nbsp; 등급 <b>{_esc(d['grade'])}</b></div>
  <div class="meta">입력형식: {_esc(d['input_kind'])} · 파싱 리소스 {d['parsed_resources']}개 · 발견 이슈 {d['total_findings']}건 ({_esc(csum)}){plat_meta}</div>
  {body_sections}
  <div class="foot">※ 본 리포트는 오프라인 규칙 기반 자동 검토 결과이며 참고용입니다. 실제 조치 전 대상 환경과 업무 요건을 확인하세요. KISA 공식 심사자료를 대체하지 않습니다.</div>
</body></html>"""
