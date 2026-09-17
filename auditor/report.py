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

    # ── 경영진용 요약: 복합 위험(공격 경로) + 조치 우선순위 TOP ──
    corr = d.get("correlations", [])
    if corr:
        lines.append("#" * 64)
        lines.append(f" [즉시 조치 권장] 복합 위험(공격 경로) {len(corr)}건")
        lines.append("#" * 64)
        for c in corr:
            lines.append(f"  ⚠️ {c['title']}")
            lines.append(f"      공격 경로: {c['attack_path']}")
            lines.append(f"      우선 조치: {c['recommendation']}")
        lines.append("")
    tops = d.get("top_risks", [])
    if tops:
        lines.append("-" * 64)
        lines.append(f" [조치 우선순위 TOP {len(tops)}] 위험 점수순")
        lines.append("-" * 64)
        for i, t in enumerate(tops, 1):
            fac = (" — " + " · ".join(t["risk_factors"])) if t.get("risk_factors") else ""
            lines.append(f"  {i}. [{t['risk_score']}점][{t['severity']}][{_plat_label(t['platform'])}] {t['title']}{fac}")
        lines.append("")
    # ── 위치별 이슈 요약(어느 위치를 먼저 조치할지) ──
    from .engine import group_by_location
    loc_groups = [g for g in group_by_location(d) if g["location"] != "(위치 미상)"]
    if loc_groups:
        lines.append("-" * 64)
        lines.append(" [위치별 이슈 요약] 위험 높은 위치 순")
        lines.append("-" * 64)
        for g in loc_groups:
            lines.append(f"  📍 {g['location']} — {g['count']}건 (최고 위험 {g['max_risk']}점)")
        lines.append("")

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
            if getattr(f, "location", ""):
                lines.append(f"      위치: {f.location}")
            if getattr(f, "mitre_id", ""):
                lines.append(f"      MITRE ATT&CK: {f.mitre_id} {f.mitre_name}")
            lines.append(f"      문제: {f.description}")
            if getattr(f, "why", ""):
                lines.append(f"      왜 문제인가: {f.why}")
            lines.append(f"      개선: {f.recommendation}")
            if getattr(f, "how_to_fix", ""):
                lines.append("      해결 방법(단계별):")
                for step in f.how_to_fix.splitlines():
                    if step.strip():
                        lines.append(f"        {step.strip()}")
            if getattr(f, "steps", ""):
                lines.append("      따라하기(포털 클릭 순서 + 실행 명령어):")
                for step in f.steps.splitlines():
                    if step.strip():
                        lines.append(f"        {step.strip()}")
            if getattr(f, "bad_example", ""):
                lines.append(f"      위반 예시: {f.bad_example}")
            if getattr(f, "good_example", ""):
                lines.append(f"      개선 예시: {f.good_example}")
            if f.evidence:
                lines.append(f"      판단 근거: {f.evidence[:400]}")
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
    ("location", "위치(구독/RG/VPC 등)"),
    ("mitre_id", "MITRE ID"),
    ("mitre_name", "MITRE 기법"),
    ("description", "문제(판단기준)"),
    ("why", "왜 문제인가"),
    ("recommendation", "개선방안"),
    ("how_to_fix", "해결 방법(단계별)"),
    ("steps", "따라하기(포털+명령어)"),
    ("bad_example", "위반예시"),
    ("good_example", "개선예시"),
    ("evidence", "판단 근거"),
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

_BAR_COLORS = ["#2980b9", "#ff9900", "#27ae60", "#8e44ad", "#c9a227", "#c0392b", "#16a2b8", "#7f8c8d"]


def _svg_donut(items, size=130):
    """인쇄용 SVG 도넛 차트(외부 라이브러리 불필요)."""
    total = sum(x["value"] for x in items)
    if not total:
        return ""
    import math
    cx = cy = size / 2
    r = size / 2 - 8
    circ = 2 * math.pi * r
    off = 0.0
    segs = []
    for i, it in enumerate(items):
        length = it["value"] / total * circ
        col = _SEV_COLOR.get(it["label"], _BAR_COLORS[i % len(_BAR_COLORS)])
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{col}" stroke-width="13" '
            f'stroke-dasharray="{length:.2f} {circ - length:.2f}" stroke-dashoffset="{-off:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"></circle>'
        )
        off += length
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">' + "".join(segs)
        + f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" font-size="22" font-weight="700" fill="#222">{total}</text>'
        + f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="11" fill="#777">건</text></svg>'
    )


def _svg_legend(items):
    out = ["<div class='clegend'>"]
    for i, it in enumerate(items):
        col = _SEV_COLOR.get(it["label"], _BAR_COLORS[i % len(_BAR_COLORS)])
        out.append(f"<span class='clg'><i style='background:{col}'></i>{_esc(it['label'])} {it['value']}</span>")
    out.append("</div>")
    return "".join(out)


def _html_hbars(items):
    mx = max((x["value"] for x in items), default=1) or 1
    rows = []
    for i, it in enumerate(items):
        w = round(it["value"] / mx * 100)
        col = _BAR_COLORS[i % len(_BAR_COLORS)]
        rows.append(
            f"<div class='chbrow'><span class='chblabel' title='{_esc(it['label'])}'>{_esc(it['label'])}</span>"
            f"<span class='chbtrack'><span class='chbfill' style='width:{w}%;background:{col}'></span></span>"
            f"<span class='chbval'>{it['value']}</span></div>"
        )
    return "<div class='chbars'>" + "".join(rows) + "</div>"


def _stats_html(stats: dict) -> str:
    """발표용 통계 차트 블록(도넛 + 가로막대)."""
    if not stats or not stats.get("total"):
        return ""

    def card(title, body):
        return f"<div class='statcard'><div class='statt'>{_esc(title)}</div>{body}</div>"

    parts = []
    if stats.get("severity"):
        parts.append(card("심각도 분포",
                           f"<div class='donutwrap'>{_svg_donut(stats['severity'])}{_svg_legend(stats['severity'])}</div>"))
    if stats.get("platform"):
        parts.append(card("플랫폼별",
                           f"<div class='donutwrap'>{_svg_donut(stats['platform'])}{_svg_legend(stats['platform'])}</div>"))
    if stats.get("domain"):
        parts.append(card("ISMS-P 영역별", _html_hbars(stats["domain"])))
    if stats.get("location"):
        parts.append(card("위치별 TOP", _html_hbars(stats["location"])))
    if stats.get("mitre"):
        parts.append(card("MITRE ATT&CK 기법별", _html_hbars(stats["mitre"])))
    if not parts:
        return ""
    return "<h2>📊 통계 요약 (발표용)</h2><div class='statgrid'>" + "".join(parts) + "</div>"


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
            evi = (f"<div class='evlabel'><b>🔎 판단 근거(입력에서 감지된 내용)</b></div>"
                   f"<div class='evi'>{_esc(f.evidence[:400])}</div>" if f.evidence else "")
            res = f"<div class='res'><b>대상:</b> {_esc(f.resource)}</div>" if f.resource else ""
            if getattr(f, "location", ""):
                res += f"<div class='loc'><b>📍 위치:</b> {_esc(f.location)}</div>"
            why = (f"<div class='why'><b>❓ 왜 문제인가요?</b><br>{_esc(getattr(f, 'why', '')).replace(chr(10), '<br>')}</div>"
                   if getattr(f, "why", "") else "")
            howto = (f"<div class='howto'><b>🛠️ 해결 방법(단계별)</b><br>{_esc(getattr(f, 'how_to_fix', '')).replace(chr(10), '<br>')}</div>"
                     if getattr(f, "how_to_fix", "") else "")
            steps = (f"<div class='steps'><b>📖 따라하기 (포털 클릭 순서 + 실행 명령어)</b><br>{_esc(getattr(f, 'steps', '')).replace(chr(10), '<br>')}</div>"
                     if getattr(f, "steps", "") else "")
            bad = (f"<div class='ex bad'><b>✗ 위반 예시:</b> <code>{_esc(f.bad_example)}</code></div>"
                   if getattr(f, "bad_example", "") else "")
            good = (f"<div class='ex good'><b>✓ 개선 예시:</b> <code>{_esc(f.good_example)}</code></div>"
                    if getattr(f, "good_example", "") else "")
            rows.append(
                f"<div class='finding'>"
                f"<div class='ftop'><span class='sev' style='background:{color}'>{_esc(sev)}</span>"
                f"<span class='ftitle'>{_esc(f.title)}</span></div>"
                f"{res}"
                + (f"<div class='mitre'>MITRE ATT&CK {_esc(f.mitre_id)} · {_esc(f.mitre_name)}</div>"
                   if getattr(f, 'mitre_id', '') else "")
                + f"<div class='p'><b>문제:</b> {_esc(f.description)}</div>"
                f"{why}"
                f"<div class='fix'><b>개선:</b> {_esc(f.recommendation)}</div>"
                f"{howto}"
                f"{steps}"
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

    # 발표용 통계 차트
    from .engine import build_statistics
    stats_html = _stats_html(d.get("statistics") or build_statistics(d))

    # 경영진용 요약: 복합 위험 + 조치 우선순위 TOP
    summary_html = ""
    corr = d.get("correlations", [])
    if corr:
        rows = "".join(
            f"<div class='corr'><div class='corrtitle'>⚠️ {_esc(c['title'])}</div>"
            f"<div><b>공격 경로:</b> {_esc(c['attack_path'])}</div>"
            f"<div class='fix'><b>우선 조치:</b> {_esc(c['recommendation'])}</div></div>"
            for c in corr
        )
        summary_html += f"<h2 style='color:#c0392b'>🚨 복합 위험(공격 경로) {len(corr)}건 — 즉시 조치 권장</h2>{rows}"
    tops = d.get("top_risks", [])
    if tops:
        trows = "".join(
            f"<tr><td>{i}</td><td><b>{t['risk_score']}</b></td><td>{_esc(t['severity'])}</td>"
            f"<td>{_esc(_plat_label(t['platform']))}</td><td>{_esc(t['title'])}</td>"
            f"<td class='fac'>{_esc(' · '.join(t.get('risk_factors', [])))}</td></tr>"
            for i, t in enumerate(tops, 1)
        )
        summary_html += (
            f"<h2>🎯 조치 우선순위 TOP {len(tops)} (위험 점수순)</h2>"
            f"<table class='toprisk'><tr><th>#</th><th>위험점수</th><th>심각도</th>"
            f"<th>플랫폼</th><th>이슈</th><th>위험요소</th></tr>{trows}</table>"
        )

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
  .why{{ margin-top:4px; background:#fdf6e3; border-left:3px solid #d6a412; padding:4px 8px; font-size:12px; line-height:1.5; }}
  .howto{{ margin-top:4px; background:#eef5ff; border-left:3px solid #2980b9; padding:4px 8px; font-size:12px; line-height:1.55; }}
  .steps{{ margin-top:4px; background:#f0f7f2; border-left:3px solid #27ae60; padding:4px 8px; font-size:11.5px; line-height:1.6; font-family:Consolas,monospace; word-break:break-all; }}
  .evlabel{{ margin-top:6px; font-size:11px; color:#555; }}
  .mitre{{ display:inline-block; font-size:11px; font-weight:700; color:#6b3fa0; background:#f0e8fb; border:1px solid #c9b3e8; padding:1px 7px; border-radius:4px; margin-top:3px; }}
  .loc{{ font-size:12px; color:#215a86; background:#eef5fb; border-left:3px solid #2980b9; padding:3px 8px; margin-top:3px; }}
  .corr{{ margin:6px 0; padding:8px 10px; background:#fdecea; border:1px solid #e0a0a0; border-left:4px solid #c0392b; border-radius:6px; }}
  .corrtitle{{ font-weight:700; color:#c0392b; margin-bottom:3px; }}
  table.toprisk{{ border-collapse:collapse; width:100%; margin:6px 0; font-size:12px; }}
  table.toprisk th,table.toprisk td{{ border:1px solid #ccc; padding:4px 8px; text-align:left; }}
  table.toprisk th{{ background:#f0f0f0; }}
  table.toprisk .fac{{ color:#777; font-size:11px; }}
  .statgrid{{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:10px; margin:6px 0 14px; }}
  .statcard{{ border:1px solid #ddd; border-radius:8px; padding:10px 12px; page-break-inside:avoid; }}
  .statt{{ font-size:12px; font-weight:700; color:#333; margin-bottom:6px; }}
  .donutwrap{{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; }}
  .clegend{{ display:flex; flex-direction:column; gap:2px; }}
  .clg{{ font-size:11px; color:#555; }}
  .clg i{{ display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:5px; vertical-align:middle; }}
  .chbars{{ display:flex; flex-direction:column; gap:4px; }}
  .chbrow{{ display:flex; align-items:center; gap:6px; font-size:11px; }}
  .chblabel{{ width:110px; color:#555; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .chbtrack{{ flex:1; background:#eee; border-radius:4px; height:13px; overflow:hidden; }}
  .chbfill{{ display:block; height:100%; border-radius:4px; }}
  .chbval{{ width:26px; text-align:right; font-weight:700; }}
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
  {stats_html}
  {summary_html}
  {body_sections}
  <div class="foot">※ 본 리포트는 오프라인 규칙 기반 자동 검토 결과이며 참고용입니다. 실제 조치 전 대상 환경과 업무 요건을 확인하세요. KISA 공식 심사자료를 대체하지 않습니다.</div>
</body></html>"""



# ---------------------------------------------------------------------------
# XLSX (진짜 엑셀) — 표준 라이브러리 zipfile만으로 생성(폐쇄망 OK).
#   .xlsx는 XML들을 담은 ZIP이므로 외부 패키지 없이 최소 스펙으로 직접 만든다.
#   각 셀은 inlineStr(t="inlineStr")로 기록해 줄바꿈·쉼표·따옴표를 안전하게 보존한다
#   → CSV에서 발생하던 셀 분리/데이터 손실 문제가 없다.
# ---------------------------------------------------------------------------
def _xl_esc(s) -> str:
    """XML 셀 값 이스케이프(제어문자 제거 + 엔티티 치환)."""
    s = "" if s is None else str(s)
    # 엑셀이 허용하지 않는 제어문자 제거(탭/개행/캐리지리턴은 유지)
    s = "".join(ch for ch in s if ch >= " " or ch in "\t\n\r")
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def _col_ref(idx: int) -> str:
    """0-기반 열 인덱스 → 엑셀 열 문자(A, B, ..., Z, AA...)."""
    ref = ""
    idx += 1
    while idx:
        idx, rem = divmod(idx - 1, 26)
        ref = chr(65 + rem) + ref
    return ref


def _sheet_xml(rows: list[list], freeze_header: bool = True) -> str:
    """행 목록(문자열 2차원 배열)을 워크시트 XML로."""
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
    if freeze_header and rows:
        out.append('<sheetViews><sheetView workbookViewId="0">'
                    '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
                    '</sheetView></sheetViews>')
    out.append("<sheetData>")
    for r, row in enumerate(rows, start=1):
        cells = []
        for c, val in enumerate(row):
            ref = f"{_col_ref(c)}{r}"
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">'
                         f'{_xl_esc(val)}</t></is></c>')
        out.append(f'<row r="{r}">{"".join(cells)}</row>')
    out.append("</sheetData></worksheet>")
    return "".join(out)


def format_xlsx(report: AuditReport) -> bytes:
    """검토 결과를 진짜 엑셀(.xlsx) 바이트로 생성.

    시트 2개: '요약'(점수/등급/건수/플랫폼), '상세'(이슈 목록 표).
    표준 라이브러리(zipfile)만 사용 — 폐쇄망에서 추가 설치 없이 동작.
    """
    import io
    import zipfile

    # --- 요약 시트 데이터 ---
    counts = report.severity_counts()
    csum = ", ".join(f"{k}={counts[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if k in counts)
    summary_rows = [
        ["항목", "값"],
        ["점수", f"{report.score()}/100"],
        ["등급", report.grade()],
        ["입력형식", report.input_kind],
        ["파싱 리소스", str(report.parsed_resources)],
        ["발견 이슈", str(len(report.findings))],
        ["심각도 분포", csum],
        ["플랫폼별", _platform_summary(report)],
        ["", ""],
        ["※ 오프라인 규칙 기반 자동 검토 결과이며 참고용. KISA 공식 심사자료를 대체하지 않음.", ""],
    ]

    # --- 상세 시트 데이터 ---
    detail_rows = [[label for _, label in _CSV_COLUMNS]]
    for f in sorted(report.findings, key=lambda x: x.severity, reverse=True):
        row = f.to_dict()
        row["platform"] = _plat_label(row.get("platform", ""))
        detail_rows.append([str(row.get(key, "")) for key, _ in _CSV_COLUMNS])

    # --- xlsx(zip) 구성 ---
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets>'
        '<sheet name="요약" sheetId="1" r:id="rId1"/>'
        '<sheet name="상세" sheetId="2" r:id="rId2"/>'
        "</sheets></workbook>"
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>'
        "</Relationships>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/worksheets/sheet1.xml", _sheet_xml(summary_rows, freeze_header=False))
        z.writestr("xl/worksheets/sheet2.xml", _sheet_xml(detail_rows, freeze_header=True))
    return buf.getvalue()
