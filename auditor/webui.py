"""로컬 웹 업로드 UI (폐쇄망 전용, 표준 라이브러리 http.server만 사용).

실행:
  python -m auditor.webui                 # http://127.0.0.1:8080
  python -m auditor.webui --port 9000 --host 0.0.0.0

엔드포인트:
  GET  /            -> 업로드/붙여넣기 UI (단일 HTML, 외부 CDN 없음)
  GET  /api/controls -> ISMS-P 통제항목 목록(참고용)
  POST /api/audit   -> {"text": "<az 출력 텍스트>"} → 검토 결과 JSON
  POST /api/export  -> {"text": "...", "format": "csv"|"html"} → 해당 포맷 텍스트(다운로드/인쇄용)

외부 네트워크·AI·AWS 연결 없음. 입력 텍스트는 메모리에서만 처리하고 저장하지 않는다.
"""

from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import analyze
from .collector_script import build_script, script_filename
from .knowledge_base import all_controls, collection_commands
from .parser import decode_bytes
from .report import format_csv, format_html, format_xlsx
from . import ir_playbook, appsec

logger = logging.getLogger(__name__)

# 업로드 크기 상한(폐쇄망 로컬이지만 방어적으로): 8MB
_MAX_BODY = 8 * 1024 * 1024


def _export_filename(uploaded_name: str, ext: str) -> str:
    """다운로드 파일명 생성. 업로드 파일명이 있으면 포함.

    업로드 O: 'audit_<파일명>_<날짜시간>.ext'
    업로드 X: 'azure-audit_<날짜시간>.ext'
    (webui의 JS _tsName/_baseFromLoaded 와 동일 규칙을 서버에서도 적용)
    """
    import datetime
    import re as _re
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    base = (uploaded_name or "").strip()
    if base:
        dot = base.rfind(".")
        if dot > 0:
            base = base[:dot]                       # 확장자 제거
        base = _re.sub(r'[\\/:*?"<>|]+', "_", base).strip()
    if base:
        return f"audit_{base}_{stamp}.{ext}"
    return f"azure-audit_{stamp}.{ext}"


INDEX_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>클라우드 전용 보안검토 (ISMS-P · AWS/Azure)</title>
<style>
  :root{ --bg:#0e1626; --panel:#152036; --panel2:#1c2942; --border:#2a3a5a; --text:#e8eefc;
    --muted:#93a3c4; --accent:#4da3ff; --crit:#ff5d6c; --high:#ff9f43; --med:#ffd43b; --low:#4dabf7; --info:#8a9bbd; }
  *{ box-sizing:border-box; }
  body{ margin:0; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Malgun Gothic",sans-serif; font-size:14px; }
  header{ padding:18px 22px; border-bottom:1px solid var(--border); background:var(--panel); }
  h1{ font-size:18px; margin:0 0 4px; }
  .sub{ color:var(--muted); font-size:13px; }
  main{ max-width:1000px; margin:0 auto; padding:20px; }
  .card{ background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:16px; margin-bottom:16px; }
  label{ display:block; font-size:13px; color:var(--muted); margin:8px 0 4px; }
  textarea{ width:100%; min-height:200px; background:#0b1220; color:var(--text); border:1px solid var(--border);
    border-radius:8px; padding:10px; font-family:ui-monospace,Consolas,monospace; font-size:12px; resize:vertical; }
  .row{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:10px; }
  .btn{ padding:9px 16px; border-radius:8px; border:1px solid var(--border); background:var(--panel2);
    color:var(--text); cursor:pointer; font-size:13px; }
  .btn.primary{ background:var(--accent); border-color:var(--accent); color:#06122a; font-weight:700; }
  .btn:hover{ filter:brightness(1.1); }
  .hint{ color:var(--muted); font-size:12px; }
  input[type=file]{ color:var(--muted); font-size:12px; }
  .scorecard{ display:flex; align-items:center; gap:18px; }
  .score{ font-size:44px; font-weight:800; line-height:1; }
  .gauge{ flex:0 0 auto; }
  .grade-A,.grade-B{ color:#37d67a; } .grade-C{ color:var(--med); } .grade-D,.grade-F{ color:var(--crit); }
  .counts span{ display:inline-block; margin-right:10px; font-size:13px; }
  .sec{ font-size:14px; margin:18px 0 8px; color:var(--accent); border-left:3px solid var(--accent); padding-left:8px; }
  .finding{ border:1px solid var(--border); border-radius:10px; padding:12px; margin-bottom:10px; background:var(--panel2); }
  .ftop{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .sev{ font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; color:#06122a; }
  .sev.CRITICAL{ background:var(--crit); } .sev.HIGH{ background:var(--high); }
  .sev.MEDIUM{ background:var(--med); } .sev.LOW{ background:var(--low); } .sev.INFO{ background:var(--info); }
  .code{ font-size:11px; color:var(--muted); border:1px solid var(--border); border-radius:6px; padding:2px 6px; }
  .platbadge{ font-size:11px; font-weight:700; color:#06122a; padding:2px 8px; border-radius:6px; }
  .ftitle{ font-weight:600; }
  .meta{ color:var(--muted); font-size:13px; margin-top:6px; line-height:1.5; }
  .meta b{ color:var(--text); }
  .fix{ margin-top:6px; padding:8px 10px; background:#10233a; border-radius:8px; border:1px solid var(--border); font-size:13px; }
  .why{ margin-top:6px; padding:8px 10px; background:#2a2410; border-left:3px solid #e0b341; border-radius:6px; font-size:13px; line-height:1.55; }
  .howto{ margin-top:6px; padding:8px 10px; background:#10233a; border-left:3px solid #4da3ff; border-radius:6px; font-size:13px; line-height:1.6; }
  .steps{ margin-top:6px; padding:8px 10px; background:#0e1f16; border-left:3px solid #37d67a; border-radius:6px; font-size:12.5px; line-height:1.65; font-family:Consolas,'D2Coding',monospace; word-break:break-all; color:#dbe7dd; }
  .steps b{ font-family:inherit; }
  .corr{ margin:6px 0; padding:10px 12px; background:#2a1518; border:1px solid #7a2a2a; border-left:4px solid #e05563; border-radius:8px; }
  .corrtitle{ font-weight:700; color:#ff9b9b; margin-bottom:4px; }
  .toprisk{ margin:6px 0; }
  .trow{ display:flex; align-items:center; gap:8px; padding:7px 10px; margin:4px 0; background:#12233a; border:1px solid var(--border); border-radius:8px; flex-wrap:wrap; }
  .trnum{ width:22px; height:22px; line-height:22px; text-align:center; border-radius:50%; background:#4da3ff; color:#04121f; font-weight:700; font-size:12px; }
  .trscore{ font-weight:700; color:#ffd166; min-width:44px; }
  .trtitle{ flex:1; font-size:13px; }
  .trfac{ font-size:11px; color:var(--muted); background:#0b1220; padding:2px 6px; border-radius:5px; }
  .mitre{ display:inline-block; font-size:11px; font-weight:700; color:#c39bff; background:#241a38; border:1px solid #4b3a6b; padding:1px 7px; border-radius:4px; margin-right:6px; }
  .loc{ font-size:12px; color:#bfe3ff; background:#0e2233; border-left:3px solid #2f6f9f; border-radius:5px; padding:4px 9px; margin-top:4px; }
  .rsbadge{ font-size:11px; font-weight:700; color:#04121f; background:#ffd166; padding:1px 7px; border-radius:4px; }
  .autostep{ display:flex; gap:12px; margin:12px 0; padding:12px; background:var(--panel2); border:1px solid var(--border); border-radius:10px; }
  .autonum{ flex:0 0 auto; width:28px; height:28px; line-height:28px; text-align:center; border-radius:50%; background:#4da3ff; color:#04121f; font-weight:800; }
  .autobody{ flex:1; font-size:13px; line-height:1.6; }
  .autobody ul{ margin:6px 0 0; padding-left:18px; }
  .autobody li{ margin:2px 0; }
  .opttbl{ border-collapse:collapse; width:100%; margin:8px 0; font-size:12px; }
  .opttbl th,.opttbl td{ border:1px solid var(--border); padding:4px 8px; text-align:left; }
  .opttbl th{ background:#0b1220; }
  .statgrid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:10px; margin:6px 0; }
  .statcard{ background:var(--panel2); border:1px solid var(--border); border-radius:10px; padding:12px; }
  .statt{ font-size:13px; font-weight:700; color:#cfe3ff; margin-bottom:8px; }
  .donutwrap{ display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .legend{ display:flex; flex-direction:column; gap:3px; }
  .legend .lg{ font-size:12px; color:var(--muted); }
  .legend .lg i{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:6px; vertical-align:middle; }
  .hbars{ display:flex; flex-direction:column; gap:5px; }
  .hbrow{ display:flex; align-items:center; gap:8px; font-size:12px; }
  .hblabel{ width:120px; color:var(--muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .hbtrack{ flex:1; background:#0b1220; border-radius:5px; height:14px; overflow:hidden; }
  .hbfill{ display:block; height:100%; border-radius:5px; }
  .hbval{ width:28px; text-align:right; font-weight:700; }
  .trendbar{ display:flex; gap:8px; flex-wrap:wrap; margin:6px 0; }
  .tb{ font-size:13px; font-weight:700; padding:4px 10px; border-radius:8px; border:1px solid var(--border); }
  .tb-new{ background:#2a1518; color:#ff9b9b; }
  .tb-keep{ background:#12233a; color:#cfe3ff; }
  .tb-score{ background:#241a38; color:#e0c8ff; }
  .tritem{ font-size:12px; padding:3px 8px; margin:2px 0; border-radius:5px; }
  .tri-new{ background:#2a1518; }
  .evlabel{ margin-top:8px; font-size:12px; color:var(--muted); }
  .exbad{ margin-top:6px; padding:6px 10px; background:#2a1518; border-left:3px solid var(--crit); border-radius:6px; font-size:12px; }
  .exgood{ margin-top:6px; padding:6px 10px; background:#0f2418; border-left:3px solid #37d67a; border-radius:6px; font-size:12px; }
  .exbad code,.exgood code{ color:#cfe3ff; word-break:break-all; }
  pre{ white-space:pre-wrap; word-break:break-all; background:#0b1220; border:1px solid var(--border);
    border-radius:6px; padding:6px 8px; font-size:11px; color:var(--muted); margin:6px 0 0; }
  .empty{ color:var(--muted); }
  .banner{ background:#10233a; border:1px solid var(--border); border-radius:8px; padding:10px 12px; font-size:12px; color:var(--muted); }
  .err{ color:var(--crit); margin-top:8px; white-space:pre-wrap; }
  .tabs{ display:flex; gap:8px; padding:0 22px; background:var(--panel); border-bottom:1px solid var(--border); }
  .tab{ padding:11px 18px; cursor:pointer; color:var(--muted); border-bottom:3px solid transparent; font-size:14px; }
  .tab.active{ color:var(--text); border-bottom-color:var(--accent); font-weight:700; }
  .toggle{ display:inline-flex; border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  .toggle button{ background:var(--panel2); color:var(--muted); border:0; padding:8px 16px; cursor:pointer; font-size:13px; }
  .toggle button.on{ color:#06122a; font-weight:700; }
  .toggle button.on[data-p="aws"]{ background:#ff9900; }
  .toggle button.on[data-p="azure"]{ background:#4da3ff; }
  .search{ width:100%; background:#0b1220; color:var(--text); border:1px solid var(--border); border-radius:8px; padding:9px 10px; font-size:13px; margin-top:10px; }
  .cmdcard{ border:1px solid var(--border); border-radius:10px; padding:12px; margin-bottom:10px; background:var(--panel2); }
  .cmdhead{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .cmdline{ display:flex; align-items:flex-start; gap:8px; margin-top:8px; }
  .cmdline pre{ flex:1; margin:0; white-space:pre-wrap; word-break:break-all; background:#0b1220; border:1px solid var(--border); border-radius:6px; padding:8px 10px; font-size:12px; color:#cfe3ff; }
  .copybtn{ flex:none; padding:6px 10px; border-radius:6px; border:1px solid var(--border); background:var(--panel); color:var(--text); cursor:pointer; font-size:12px; white-space:nowrap; }
  .copybtn:hover{ filter:brightness(1.15); }
  .crit-hint{ color:var(--muted); font-size:12px; margin-top:8px; border-left:3px solid var(--med); padding-left:8px; }
  .runwhere{ font-size:12px; color:#bfe3ff; background:#0e2233; border:1px solid #24486b; border-radius:6px; padding:5px 9px; margin:6px 0; }
  .svcbadge{ font-size:11px; color:var(--muted); background:#0b1220; border:1px solid var(--border); padding:1px 7px; border-radius:5px; }
</style>
</head>
<body>
<header>
  <h1>🛡️ 클라우드 전용 보안검토 <span class="sub">(ISMS-P · AWS/Azure)</span> <span class="sub" style="font-size:12px;opacity:.7">v1</span></h1>
  <div class="sub">AWS(<code>aws ...</code>)/Azure(<code>az ...</code>) CLI로 추출한 정책·구성 텍스트를 붙여넣거나 업로드하면, <b>인터넷·AI 없이</b> 이슈를 찾고 개선안을 제안합니다. 플랫폼은 자동으로 구별됩니다.</div>
</header>
<div class="tabs">
  <div class="tab active" id="tab-audit" onclick="switchTab('audit')">🔎 보안검토</div>
  <div class="tab" id="tab-commands" onclick="switchTab('commands')">📋 수집 명령어 가이드</div>
  <div class="tab" id="tab-auto" onclick="switchTab('auto')">⚙️ 자동화 배포 가이드</div>
  <div class="tab" id="tab-ir" onclick="switchTab('ir')">🚨 사고 대응 가이드</div>
  <div class="tab" id="tab-appsec" onclick="switchTab('appsec')">🧪 앱 보안 점검</div>
</div>
<main>
 <div id="pane-audit">
  <div class="card">
    <div class="banner">🔒 폐쇄망 전용 · 외부 전송 없음 · 입력은 서버 메모리에서만 처리되고 저장되지 않습니다.
      <br>입력 예: <code>az network nsg rule list ... -o json</code>, <code>az storage account show ...</code>, <code>az role assignment list ...</code> 등의 출력(여러 명령 출력을 이어붙여도 됨).</div>
    <label>AWS/Azure 정책·구성 텍스트 (붙여넣기)</label>
    <textarea id="input" placeholder='예) [{"name":"allow-ssh","access":"Allow","direction":"Inbound","sourceAddressPrefix":"*","destinationPortRange":"22"}]'></textarea>
    <div class="row">
      <input type="file" id="file" accept=".txt,.json,.log,.tsv" onchange="loadFile()">
      <button class="btn primary" onclick="runAudit()">보안검토 실행</button>
      <button class="btn" onclick="clearAll()">지우기</button>
      <span class="hint">파일 업로드도 로컬에서만 읽어 텍스트칸에 채웁니다(서버 전송 시에도 저장 안 함).</span>
    </div>
    <div class="hint" id="load-info" style="margin-top:6px"></div>
    <div class="err" id="err"></div>
  </div>

  <div class="card" id="result-card" style="display:none">
    <div class="scorecard">
      <div id="gauge" class="gauge"></div>
      <div>
        <div id="grade-line" style="font-size:15px;font-weight:700"></div>
        <div class="counts" id="counts"></div>
        <div class="hint" id="meta"></div>
        <div class="row" id="plat-filter" style="display:none;margin-top:8px"></div>
        <div class="row" id="view-mode" style="margin-top:6px">
          <span class="hint" style="margin-right:6px">보기:</span>
          <button class="btn" data-v="control" onclick="setViewMode('control')">📋 통제항목별</button>
          <button class="btn" data-v="location" onclick="setViewMode('location')">📍 위치별</button>
          <button class="btn" data-v="risk" onclick="setViewMode('risk')">🎯 위험점수순</button>
        </div>
      </div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="btn primary" onclick="downloadXlsx()">⬇️ 엑셀(.xlsx) 저장</button>
      <button class="btn" onclick="downloadCsv()">CSV 저장</button>
      <button class="btn" onclick="openPdf()">🖨️ PDF로 저장 (인쇄)</button>
      <span class="hint">엑셀(.xlsx)은 줄바꿈·특수문자가 그대로 보존됩니다(권장). PDF는 새 창의 인쇄 대화상자에서 "PDF로 저장"을 선택하세요.</span>
    </div>
    <div id="stats"></div>
    <div id="trend"></div>
    <div id="summary"></div>
    <div id="findings"></div>
    <div class="hint" style="margin-top:14px">※ 오프라인 규칙 기반 자동 검토 결과이며 참고용입니다. 실제 조치 전 대상 환경과 업무 요건을 확인하세요.</div>
  </div>
 </div><!-- /pane-audit -->

 <div id="pane-commands" style="display:none">
  <div class="card">
    <div class="banner">📋 <b>정보 수집 명령어 가이드</b> — 각 클라우드에서 보안 취약 여부를 확인할 정보를 뽑는 CLI 명령입니다.
      관리망에서 아래 명령으로 정책·구성을 <code>-o json</code>(AWS는 <code>--output json</code>)으로 내보내 txt로 저장한 뒤, '보안검토' 탭에 업로드하세요.</div>
    <div class="row" style="margin-top:12px">
      <span class="hint">플랫폼:</span>
      <div class="toggle" id="cmd-plat">
        <button data-p="aws" class="on" onclick="setCmdPlatform('aws')">AWS</button>
        <button data-p="azure" onclick="setCmdPlatform('azure')">Azure</button>
      </div>
      <span class="hint" id="cmd-count"></span>
    </div>
    <input class="search" id="cmd-search" placeholder="검색: 통제항목 코드·영역·명령어(예: 2.6.1, 보안그룹, s3, nsg)" oninput="renderCommands()">
    <div class="row" style="margin-top:10px">
      <span class="hint">📥 일괄 수집 스크립트:</span>
      <button class="btn primary" onclick="downloadScript('bash')">Bash(.sh) 다운로드</button>
      <button class="btn" onclick="downloadScript('ps1')">PowerShell(.ps1) 다운로드</button>
    </div>
    <div class="hint" style="margin-top:6px">스크립트를 관리망 PC에서 실행하면 장비/서비스별로 결과가 <code>out/</code> 폴더에 JSON으로 저장됩니다. 실행 방법은 스크립트 맨 위 주석을 참고하세요. 그 폴더(zip 또는 JSON 내용)를 '보안검토' 탭에 업로드하면 됩니다.</div>
    <div class="err" id="cmd-err"></div>
  </div>
  <div id="cmd-list"></div>
  <div class="hint" style="margin:0 0 20px">※ 명령의 &lt;NSG&gt;·&lt;RG&gt;·&lt;BUCKET&gt; 등 자리표시자는 실제 값으로 바꿔 사용하세요. 조직 계정·리전·CLI 버전·권한에 맞게 조정이 필요할 수 있습니다.</div>
 </div><!-- /pane-commands -->

 <div id="pane-auto" style="display:none">
  <div class="card">
    <div class="banner">⚙️ <b>자동화 배포 가이드</b> — 이 프로그램을 클라우드에 올려두면, 정해진 주기마다
      <b>자동으로 점검·침해탐지</b>하고 심각한 것은 <b>Slack</b>으로 알려줍니다. 아래 순서대로 따라 하세요.</div>

    <div class="row" style="margin:8px 0">
      <span class="hint" style="margin-right:6px">배포 대상:</span>
      <button class="btn" id="ac-aws" onclick="setAutoCloud('aws')">🟧 AWS (Lambda)</button>
      <button class="btn" id="ac-azure" onclick="setAutoCloud('azure')">🟦 Azure (Functions)</button>
    </div>

   <div id="auto-aws">
    <div class="autostep">
      <div class="autonum">1</div>
      <div class="autobody">
        <b>사전 준비</b>
        <ul>
          <li>AWS <b>SAM CLI</b> 설치 (AWS 공식 "Install SAM CLI" 문서)</li>
          <li>AWS 자격증명 구성: <code>aws configure</code> (배포 권한: CloudFormation/Lambda/IAM/S3/Events)</li>
          <li>기존 <b>Slack Incoming Webhook URL</b> 준비 (지금 쓰시는 워크스페이스·채널 것 그대로)</li>
        </ul>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">2</div>
      <div class="autobody">
        <b>배포 (한 줄)</b> — 프로젝트의 <code>deploy</code> 폴더에서 실행합니다. Webhook URL만 본인 것으로 바꾸세요.
        <div class="cmdline"><pre id="acmd1">cd deploy
deploy.bat "https://hooks.slack.com/services/XXX/YYY/ZZZ" "rate(1 hour)"</pre><button class="copybtn" onclick="copyCmd('acmd1',this)">복사</button></div>
        <div class="hint">Linux/mac는 <code>./deploy.sh "웹훅URL" "rate(1 hour)"</code> · 2번째 값은 주기(예: <code>rate(6 hours)</code>, <code>cron(0 9 * * ? *)</code>)</div>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">3</div>
      <div class="autobody">
        <b>바로 한 번 실행해 Slack 확인</b> — 스케줄을 기다리지 않고 즉시 테스트합니다.
        <div class="cmdline"><pre id="acmd2">aws lambda invoke --function-name cloud-sec-auto-auditor out.json</pre><button class="copybtn" onclick="copyCmd('acmd2',this)">복사</button></div>
        <div class="hint">심각(HIGH↑)하거나 침해가 탐지되면 Slack 채널로 요약이 도착합니다. (그 미만이면 소음 방지를 위해 전송 안 함)</div>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">4</div>
      <div class="autobody">
        <b>동작 방식 (무엇이 자동으로 되나요)</b>
        <ul>
          <li>매 주기마다 <b>boto3(AWS SDK)</b>로 실제 계정의 보안그룹·RDS·S3·IAM·GuardDuty를 수집</li>
          <li>이 프로그램의 <b>같은 분석 엔진</b>으로 위험 점수·복합 위험 판정 + 침해(무차별 대입·루트 사용·악성 IP) 탐지</li>
          <li>심각/침해 시 <b>Slack 알림</b>, 결과 리포트는 Lambda <code>/tmp</code>에 생성(요약은 로그·Slack으로 확인)</li>
          <li>차단/대응은 기본 <b>반자동</b>(명령만 생성) — 실제 변경은 하지 않아 안전</li>
        </ul>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">5</div>
      <div class="autobody">
        <b>옵션 조정</b> (배포 시 값 전달)
        <table class="opttbl">
          <tr><th>파라미터</th><th>설명</th><th>기본</th></tr>
          <tr><td>AlertMinSeverity</td><td>알림 최소 심각도</td><td>HIGH</td></tr>
          <tr><td>Remediation</td><td>off / suggest(반자동) / auto</td><td>suggest</td></tr>
          <tr><td>DryRun</td><td>true면 auto라도 실제 변경 안 함</td><td>true</td></tr>
          <tr><td>ProtectTags</td><td>차단 금지(화이트리스트) 키워드, 쉼표구분</td><td>(없음)</td></tr>
          <tr><td>Schedule</td><td>실행 주기(EventBridge 식)</td><td>rate(1 hour)</td></tr>
        </table>
        <div class="cmdline"><pre id="acmd3">sam deploy --parameter-overrides SlackWebhook="웹훅URL" Schedule="rate(6 hours)" ProtectTags="prod-critical,dns"</pre><button class="copybtn" onclick="copyCmd('acmd3',this)">복사</button></div>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">6</div>
      <div class="autobody">
        <b>로그 확인 · 삭제</b>
        <div class="cmdline"><pre id="acmd4">sam logs --name cloud-sec-auto-auditor --tail</pre><button class="copybtn" onclick="copyCmd('acmd4',this)">복사</button></div>
        <div class="cmdline"><pre id="acmd5">sam delete --stack-name cloud-sec-auto-auditor</pre><button class="copybtn" onclick="copyCmd('acmd5',this)">복사</button></div>
      </div>
    </div>

    <div class="crit-hint">⚠️ <b>자동 차단(auto)</b>은 잘못되면 정상 서비스를 막을 수 있어 기본이 <b>반자동(suggest)</b>입니다.
      실제 자동 차단을 켜려면 <code>Remediation=auto</code> + <code>DryRun=false</code> + <code>ProtectTags</code>(보호 리소스)를 반드시 함께 설정하고, 소규모부터 신중히 적용하세요.</div>
    <div class="hint" style="margin-top:10px">자세한 내용: 프로젝트의 <code>deploy/README.md</code>. Slack이 안 오면 (1) Webhook URL, (2) 이번 주기에 HIGH↑ 이슈/침해 존재 여부, (3) <code>aws lambda invoke</code>로 즉시 테스트해 로그 확인.</div>
   </div><!-- /auto-aws -->

   <div id="auto-azure" style="display:none">
    <div class="autostep">
      <div class="autonum">1</div>
      <div class="autobody">
        <b>사전 준비</b>
        <ul>
          <li><b>Azure CLI</b> 설치 후 로그인: <code>az login</code> (필요 시 <code>az account set --subscription &lt;구독ID&gt;</code>)</li>
          <li><b>Azure Functions Core Tools(func)</b> 설치</li>
          <li>기존 <b>Slack Incoming Webhook URL</b> 준비 (지금 쓰시는 워크스페이스·채널 것 그대로)</li>
        </ul>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">2</div>
      <div class="autobody">
        <b>배포 (한 줄)</b> — 프로젝트의 <code>deploy-azure</code> 폴더에서 실행합니다. Webhook URL만 본인 것으로 바꾸세요.
        <div class="cmdline"><pre id="zcmd1">cd deploy-azure
deploy.bat "https://hooks.slack.com/services/XXX/YYY/ZZZ"</pre><button class="copybtn" onclick="copyCmd('zcmd1',this)">복사</button></div>
        <div class="hint">Linux/mac는 <code>./deploy.sh "웹훅URL"</code> · 리소스 그룹·스토리지·Function App·관리 ID·역할·앱설정·코드게시가 자동으로 만들어집니다.</div>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">3</div>
      <div class="autobody">
        <b>바로 한 번 실행해 Slack 확인</b>
        <ul>
          <li>Azure Portal → 만들어진 <b>Function App</b> → 함수 <b>AutoAudit</b> → <b>코드+테스트 → 테스트/실행</b></li>
          <li>또는 스케줄(기본 <b>매시간</b>)을 기다립니다.</li>
        </ul>
        <div class="hint">심각(HIGH↑)하거나 침해가 탐지되면 Slack 채널로 요약이 도착합니다.</div>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">4</div>
      <div class="autobody">
        <b>동작 방식 (무엇이 자동으로 되나요)</b>
        <ul>
          <li>매 주기마다 <b>Azure SDK</b>로 실제 구독의 NSG·Storage·SQL·Defender 경고를 수집 (Function App의 <b>관리 ID</b>로 인증)</li>
          <li>이 프로그램의 <b>같은 분석 엔진</b>으로 위험 점수·복합 위험 + 침해 탐지</li>
          <li>심각/침해 시 <b>Slack 알림</b>, 차단/대응은 기본 <b>반자동</b>(명령만 생성) — 안전</li>
        </ul>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">5</div>
      <div class="autobody">
        <b>옵션 조정</b> — Portal → Function App → <b>구성(Configuration)</b>의 앱 설정으로 변경
        <table class="opttbl">
          <tr><th>앱 설정</th><th>설명</th><th>기본</th></tr>
          <tr><td>AUTOAUDITOR_ALERT_MIN_SEVERITY</td><td>알림 최소 심각도</td><td>HIGH</td></tr>
          <tr><td>AUTOAUDITOR_REMEDIATION</td><td>off / suggest(반자동) / auto</td><td>suggest</td></tr>
          <tr><td>AUTOAUDITOR_DRY_RUN</td><td>true면 auto라도 실제 변경 안 함</td><td>true</td></tr>
          <tr><td>AUTOAUDITOR_PROTECT_TAGS</td><td>차단 금지(화이트리스트) 키워드</td><td>(없음)</td></tr>
        </table>
        <div class="hint">스케줄은 <code>deploy-azure/AutoAudit/function.json</code>의 CRON으로 조정 (예: <code>0 0 */6 * * *</code> = 6시간마다)</div>
      </div>
    </div>

    <div class="autostep">
      <div class="autonum">6</div>
      <div class="autobody">
        <b>로그 확인 · 삭제</b>
        <ul>
          <li>로그: Portal → Function App → <b>로그 스트림</b>(또는 Application Insights)</li>
        </ul>
        <div class="cmdline"><pre id="zcmd2">az group delete -n rg-cloudsec-autoaudit --yes</pre><button class="copybtn" onclick="copyCmd('zcmd2',this)">복사</button></div>
      </div>
    </div>

    <div class="crit-hint">⚠️ <b>자동 차단(auto)</b>은 잘못되면 정상 서비스를 막을 수 있어 기본이 <b>반자동(suggest)</b>입니다.
      실제 자동 차단은 관리 ID에 기여자(수정) 권한 추가 + <code>DryRun=false</code> + <code>ProtectTags</code>를 함께 설정하고 소규모부터 적용하세요.</div>
    <div class="hint" style="margin-top:10px">자세한 내용: 프로젝트의 <code>deploy-azure/README.md</code>. 수집이 비면 관리 ID의 Reader 역할·<code>AZURE_SUBSCRIPTION_ID</code>를 확인(역할 전파에 몇 분 소요).</div>
   </div><!-- /auto-azure -->
  </div>
 </div><!-- /pane-auto -->

 <div id="pane-ir" style="display:none">
  <div class="card">
    <div class="banner">🚨 <b>사고 대응(IR) 가이드</b> — 침해 유형을 고르면 ISMS-P 2.11(사고 예방·대응) 절차에 맞춘
      <b>단계별 대응 플레이북 · 증거수집 명령어 · 보고서 양식</b>을 만들어 드립니다.
      <br>※ 실제 격리·복구·신고는 담당자가 승인 절차에 따라 직접 수행해야 합니다. 이 화면은 절차 안내용입니다.</div>
    <div class="row" style="margin-top:12px">
      <span class="hint">침해 유형:</span>
      <select id="ir-type" class="search" style="max-width:320px"></select>
      <span class="hint" style="margin-left:8px">대상:</span>
      <div class="toggle" id="ir-plat">
        <button data-p="aws" class="on" onclick="setIrPlat('aws')">AWS</button>
        <button data-p="azure" onclick="setIrPlat('azure')">Azure</button>
      </div>
      <button class="btn primary" onclick="runIr()">플레이북 생성</button>
    </div>
    <div class="err" id="ir-err"></div>
  </div>
  <div id="ir-result"></div>
 </div><!-- /pane-ir -->

 <div id="pane-appsec" style="display:none">
  <div class="card">
    <div class="banner">🧪 <b>애플리케이션 보안 점검</b> — 소스코드에서 위험 패턴(간이 SAST)을 찾고,
      WAF(웹 방화벽) 구성이 켜져 있는지 점검합니다.
      <br>※ 정규식 기반 <b>참고용</b>이며 상용 정적분석/실제 공격시험(DAST)을 대체하지 않습니다. 결과는 코드 맥락으로 확인하세요.</div>
    <div class="row" style="margin-top:12px">
      <span class="hint">점검 종류:</span>
      <div class="toggle" id="as-mode">
        <button data-m="sast" class="on" onclick="setAsMode('sast')">소스코드(SAST)</button>
        <button data-m="waf" onclick="setAsMode('waf')">WAF 구성</button>
        <button data-m="both" onclick="setAsMode('both')">둘 다</button>
      </div>
      <span class="hint" style="margin-left:8px" id="as-plat-wrap">플랫폼:</span>
      <div class="toggle" id="as-plat">
        <button data-p="aws" class="on" onclick="setAsPlat('aws')">AWS</button>
        <button data-p="azure" onclick="setAsPlat('azure')">Azure</button>
      </div>
    </div>
    <label id="as-label" style="margin-top:10px">점검할 소스코드 붙여넣기</label>
    <textarea id="as-input" placeholder="예) app.py 등 소스코드를 붙여넣으세요. WAF 구성 점검은 'WAF 구성' 선택 후 WAF 정책 JSON을 붙여넣습니다."></textarea>
    <div class="row">
      <input type="file" id="as-file" accept=".py,.js,.ts,.java,.go,.php,.rb,.txt,.json,.tf,.yaml,.yml" onchange="loadAsFile()">
      <button class="btn primary" onclick="runAppsec()">점검 실행</button>
      <button class="btn" onclick="clearAppsec()">지우기</button>
      <span class="hint">파일도 로컬에서만 읽어 입력칸에 채웁니다(외부 전송·저장 없음).</span>
    </div>
    <div class="hint" id="as-load-info" style="margin-top:6px"></div>
    <div class="err" id="as-err"></div>
  </div>
  <div id="as-result"></div>
 </div><!-- /pane-appsec -->
</main>
<script>
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function nl2br(s){ return String(s==null?'':s).replace(/\\n/g,'<br>'); }

// ----- 탭 -----
function switchTab(t){
  var panes=['audit','commands','auto','ir','appsec'];
  panes.forEach(function(p){
    var pane=document.getElementById('pane-'+p); if(pane) pane.style.display=(t===p)?'block':'none';
    var tab=document.getElementById('tab-'+p); if(tab) tab.classList.toggle('active', t===p);
  });
  if(t==='commands' && !CMD_DATA){ loadCommands(); }
  if(t==='auto'){ setAutoCloud('aws'); }
  if(t==='ir' && !IR_TYPES){ loadIrTypes(); }
}
// 자동화 배포 가이드: AWS/Azure 절차 전환
function setAutoCloud(c){
  var aws=document.getElementById('auto-aws'), az=document.getElementById('auto-azure');
  if(aws) aws.style.display=(c==='aws')?'block':'none';
  if(az) az.style.display=(c==='azure')?'block':'none';
  var ba=document.getElementById('ac-aws'), bz=document.getElementById('ac-azure');
  if(ba) ba.style.opacity=(c==='aws')?'1':'0.5';
  if(bz) bz.style.opacity=(c==='azure')?'1':'0.5';
}

// 업로드한 파일명(있으면 저장 파일명에 포함). 붙여넣기만 한 경우엔 빈 문자열.
var LOADED_FILENAME='';

// ----- 수집 명령어 가이드 -----
var CMD_PLATFORM='aws';
var CMD_DATA=null;
function setCmdPlatform(p){
  CMD_PLATFORM=p; CMD_DATA=null;
  Array.prototype.forEach.call(document.querySelectorAll('#cmd-plat button'), function(b){
    b.classList.toggle('on', b.getAttribute('data-p')===p);
  });
  loadCommands();
}
function downloadScript(shell){
  var url='/api/script?platform='+encodeURIComponent(CMD_PLATFORM)+'&shell='+encodeURIComponent(shell);
  fetch(url).then(function(r){ return r.blob(); }).then(function(blob){
    var u=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=u; a.download='collect-'+CMD_PLATFORM+'.'+(shell==='ps1'?'ps1':'sh');
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function(){ URL.revokeObjectURL(u); }, 1000);
  }).catch(function(e){ document.getElementById('cmd-err').textContent='스크립트 다운로드 실패: '+e; });
}
async function loadCommands(){
  document.getElementById('cmd-err').textContent='';
  try{
    var r=await fetch('/api/commands?platform='+encodeURIComponent(CMD_PLATFORM));
    var d=await r.json();
    CMD_DATA=d.commands||[];
    renderCommands();
  }catch(e){ document.getElementById('cmd-err').textContent='명령어 로드 실패: '+e; }
}
function renderCommands(){
  if(!CMD_DATA) return;
  var q=(document.getElementById('cmd-search').value||'').toLowerCase().trim();
  var platName = CMD_PLATFORM==='aws'?'AWS':'Azure';
  var pcolor = CMD_PLATFORM==='aws'?'#ff9900':'#4da3ff';
  var items=CMD_DATA.filter(function(c){
    if(!q) return true;
    return (c.code+' '+c.domain+' '+c.desc+' '+(c.cmd_lines||[]).join(' ')).toLowerCase().indexOf(q)>=0;
  });
  document.getElementById('cmd-count').textContent = platName+' · '+items.length+'/'+CMD_DATA.length+'개 항목';
  var host=document.getElementById('cmd-list');
  if(!items.length){ host.innerHTML='<div class="cmdcard empty">검색 결과가 없습니다.</div>'; return; }
  host.innerHTML=items.map(function(c){
    var lines=(c.cmd_lines||[]).map(function(ln,i){
      var id='cmd_'+c.code.replace(/\\./g,'_')+'_'+i;
      return '<div class="cmdline"><pre id="'+id+'">'+esc(ln)+'</pre>'+
             '<button class="copybtn" onclick="copyCmd(\\''+id+'\\',this)">복사</button></div>';
    }).join('') || '<div class="hint">이 항목은 참고 명령이 없습니다.</div>';
    var crit = c.criteria ? '<div class="crit-hint">⚠️ 확인 포인트: '+esc(c.criteria)+'</div>' : '';
    var bad = c.bad_example ? '<div class="exbad"><b>✗ 위반 예시:</b> <code>'+esc(c.bad_example)+'</code></div>' : '';
    var good = c.good_example ? '<div class="exgood"><b>✓ 개선 예시:</b> <code>'+esc(c.good_example)+'</code></div>' : '';
    var runinfo = (c.run_where||c.service_perm) ?
      '<div class="runwhere">🖥️ 실행 위치: '+esc(c.run_where||'')+
      (c.service_target?' &nbsp;·&nbsp; 대상: '+esc(c.service_target):'')+
      (c.service_perm?' &nbsp;·&nbsp; 필요 권한: '+esc(c.service_perm):'')+'</div>' : '';
    return '<div class="cmdcard">'+
      '<div class="cmdhead"><span class="platbadge" style="background:'+pcolor+'">'+platName+'</span>'+
      '<span class="code">'+esc(c.code)+'</span><b>'+esc(c.domain)+'</b>'+
      (c.service?'<span class="svcbadge">'+esc(c.service)+'</span>':'')+'</div>'+
      '<div class="meta">'+esc(c.desc)+'</div>'+runinfo+lines+crit+bad+good+'</div>';
  }).join('');
}
function copyCmd(id, btn){
  var el=document.getElementById(id); if(!el) return;
  var text=el.textContent;
  function done(){ var t=btn.textContent; btn.textContent='복사됨 ✓'; setTimeout(function(){ btn.textContent=t; },1200); }
  if(navigator.clipboard && navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(done, function(){ fallbackCopy(text); done(); });
  } else { fallbackCopy(text); done(); }
}
function fallbackCopy(text){
  var ta=document.createElement('textarea'); ta.value=text;
  ta.style.position='fixed'; ta.style.left='-9999px';
  document.body.appendChild(ta); ta.select();
  try{ document.execCommand('copy'); }catch(e){}
  document.body.removeChild(ta);
}
function clearAll(){ document.getElementById('input').value=''; document.getElementById('result-card').style.display='none'; document.getElementById('err').textContent=''; LOADED_FILENAME=''; var m=document.getElementById('load-info'); if(m) m.textContent=''; var s=document.getElementById('summary'); if(s) s.innerHTML=''; var tr=document.getElementById('trend'); if(tr) tr.innerHTML=''; var stt=document.getElementById('stats'); if(stt) stt.innerHTML=''; }
function loadFile(){
  var f=document.getElementById('file').files[0];
  var meta=document.getElementById('load-info');
  var errEl=document.getElementById('err');
  if(!f){ errEl.textContent='파일을 먼저 선택하세요.'; return; }
  errEl.textContent='';
  // 최초 버전과 동일하게 브라우저의 readAsText로 그대로 읽는다(대부분 UTF-8이라 정상).
  // 다만 결과에 깨짐 문자(U+FFFD)가 보이면 UTF-8이 아닌 파일(UTF-16/cp949)이므로,
  // 그때만 서버(파이썬)에 원본 바이트를 보내 정확히 디코딩해 자동 교정한다.
  var r=new FileReader();
  r.onload=function(e){
    var text=e.target.result;
    if(text.indexOf('\uFFFD')<0){
      // 깨짐 없음 → 최초 버전 그대로. 성공.
      document.getElementById('input').value=text;
      LOADED_FILENAME=f.name;
      if(meta) meta.textContent='불러옴: '+f.name+' ('+f.size+' bytes)';
      return;
    }
    // 깨짐 감지 → 서버 디코딩으로 재시도.
    if(meta) meta.textContent='인코딩 자동 교정 중... ('+f.name+')';
    serverDecode(f, meta, errEl);
  };
  r.onerror=function(){ errEl.textContent='파일 읽기에 실패했습니다.'; };
  r.readAsText(f);
}
function serverDecode(f, meta, errEl){
  // 파일을 Base64로 만들어 /api/decode 로 보낸다(구형 브라우저 호환 위해 XHR 사용).
  var r=new FileReader();
  r.onload=function(e){
    try{
      var dataUrl=e.target.result;                 // "data:...;base64,XXXX"
      var b64=dataUrl.indexOf(',')>=0 ? dataUrl.split(',')[1] : dataUrl;
      var xhr=new XMLHttpRequest();
      xhr.open('POST','/api/decode',true);
      xhr.setRequestHeader('Content-Type','text/plain; charset=utf-8');
      xhr.onreadystatechange=function(){
        if(xhr.readyState!==4) return;
        if(xhr.status<200 || xhr.status>=300){
          errEl.textContent='서버 응답 오류(HTTP '+xhr.status+'). 프로그램이 실행 중인지 확인하세요.';
          if(meta) meta.textContent=''; return;
        }
        var data;
        try{ data=JSON.parse(xhr.responseText); }
        catch(pe){ errEl.textContent='서버 응답을 해석하지 못했습니다.'; if(meta) meta.textContent=''; return; }
        if(!data.ok){ errEl.textContent=data.error||'파일 디코딩 실패'; if(meta) meta.textContent=''; return; }
        document.getElementById('input').value=data.text;
        LOADED_FILENAME=f.name;
        errEl.textContent='';
        if(meta) meta.textContent='불러옴: '+f.name+' ('+f.size+' bytes, 인코딩: '+data.encoding+')';
      };
      xhr.onerror=function(){ errEl.textContent='서버에 연결하지 못했습니다.'; if(meta) meta.textContent=''; };
      xhr.send(b64);
    }catch(err){
      errEl.textContent='파일을 읽는 중 오류: '+err;
      if(meta) meta.textContent='';
    }
  };
  r.onerror=function(){ errEl.textContent='파일 읽기에 실패했습니다.'; if(meta) meta.textContent=''; };
  r.readAsDataURL(f);
}
async function runAudit(){
  document.getElementById('err').textContent='';
  var text=document.getElementById('input').value;
  if(!text.trim()){ document.getElementById('err').textContent='검토할 텍스트를 입력하거나 파일을 불러오세요.'; return; }
  try{
    var resp=await fetch('/api/audit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text})});
    var data=await resp.json();
    if(!data.ok){ document.getElementById('err').textContent=data.error||'검토 실패'; return; }
    render(data.report);
  }catch(e){ document.getElementById('err').textContent='요청 실패: '+e; }
}
var LAST_REPORT=null;
var PLAT_FILTER='all';
var VIEW_MODE='control'; // 'control'=통제항목별, 'location'=위치별, 'risk'=위험점수순
function platLabel(p){ return p==='aws'?'AWS':(p==='azure'?'Azure':(p||'').toUpperCase()); }
function setPlatFilter(p){ PLAT_FILTER=p; renderFindings(LAST_REPORT); updateFilterButtons(); }
function setViewMode(m){ VIEW_MODE=m; renderFindings(LAST_REPORT); updateViewButtons(); }
function updateViewButtons(){
  var wrap=document.getElementById('view-mode'); if(!wrap) return;
  Array.prototype.forEach.call(wrap.querySelectorAll('button'), function(b){
    b.style.opacity = (b.getAttribute('data-v')===VIEW_MODE)?'1':'0.5';
  });
}
function updateFilterButtons(){
  var wrap=document.getElementById('plat-filter'); if(!wrap) return;
  Array.prototype.forEach.call(wrap.querySelectorAll('button'), function(b){
    b.style.opacity = (b.getAttribute('data-p')===PLAT_FILTER)?'1':'0.5';
  });
}
function render(r){
  LAST_REPORT=r; PLAT_FILTER='all';
  document.getElementById('result-card').style.display='block';
  var g=document.getElementById('gauge'); if(g) g.innerHTML=_gaugeSVG(r.score, r.grade);
  document.getElementById('grade-line').textContent='등급 '+r.grade+'  /  100점';
  var c=r.severity_counts||{};
  var order=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  var sevHtml=order.filter(k=>c[k]).map(k=>'<span><b>'+k+'</b> '+c[k]+'</span>').join('');
  var pc=r.platform_counts||{};
  var platHtml=Object.keys(pc).sort().map(k=>'<span style="color:'+(k==='aws'?'#ff9900':'#4da3ff')+'"><b>'+platLabel(k)+'</b> '+pc[k]+'</span>').join('');
  document.getElementById('counts').innerHTML=(sevHtml+' '+platHtml) || '<span class="empty">이슈 없음</span>';
  document.getElementById('meta').textContent='입력형식: '+r.input_kind+' · 파싱 리소스: '+r.parsed_resources+'개 · 발견 이슈: '+r.total_findings+'건';

  // 플랫폼 필터 버튼(2개 플랫폼 모두 있을 때만 표시)
  var plats=(r.detected_platforms||[]);
  var fbar=document.getElementById('plat-filter');
  if(plats.length>1){
    fbar.style.display='flex';
    fbar.innerHTML='<span class="hint" style="margin-right:6px">플랫폼 필터:</span>'+
      '<button class="btn" data-p="all" onclick="setPlatFilter(\\'all\\')">전체</button>'+
      plats.map(function(p){ return '<button class="btn" data-p="'+p+'" onclick="setPlatFilter(\\''+p+'\\')">'+platLabel(p)+'</button>'; }).join('');
  } else { fbar.style.display='none'; fbar.innerHTML=''; }

  renderStats(r);
  renderTrend(r);
  renderSummary(r);
  renderFindings(r);
  updateFilterButtons();
  updateViewButtons();
}
// ── 통계 차트(순수 SVG, 외부 라이브러리 불필요) ──
var _SEVCOLOR={CRITICAL:'#e05563',HIGH:'#ff9a3d',MEDIUM:'#ffd166',LOW:'#4da3ff',INFO:'#8a9084'};
var _BARCOLORS=['#4da3ff','#ff9900','#37d67a','#c39bff','#ffd166','#e05563','#5bc0de','#a0a0a0'];
function _gaugeColor(score){
  if(score>=90) return '#37d67a';   // A
  if(score>=80) return '#8fd14f';   // B
  if(score>=70) return '#ffd166';   // C
  if(score>=60) return '#ff9a3d';   // D
  return '#e05563';                 // F
}
function _gaugeSVG(score, grade){
  // 반원형 게이지(180도). 0점=왼쪽, 100점=오른쪽.
  score = Math.max(0, Math.min(100, score||0));
  var w=200, h=118, cx=100, cy=100, r=82;
  function pt(deg){ var a=(180-deg)*Math.PI/180; return [cx+r*Math.cos(a), cy-r*Math.sin(a)]; }
  var arc=180*score/100;
  var s=pt(0), e=pt(arc), full=pt(180);
  var large=arc>180?1:0;
  var col=_gaugeColor(score);
  return '<svg width="'+w+'" height="'+h+'" viewBox="0 0 '+w+' '+h+'">'+
    // 배경 트랙
    '<path d="M '+s[0].toFixed(1)+' '+s[1].toFixed(1)+' A '+r+' '+r+' 0 0 1 '+full[0].toFixed(1)+' '+full[1].toFixed(1)+'" fill="none" stroke="#22303f" stroke-width="14" stroke-linecap="round"/>'+
    // 점수 호
    '<path d="M '+s[0].toFixed(1)+' '+s[1].toFixed(1)+' A '+r+' '+r+' 0 '+large+' 1 '+e[0].toFixed(1)+' '+e[1].toFixed(1)+'" fill="none" stroke="'+col+'" stroke-width="14" stroke-linecap="round"/>'+
    // 점수·등급 텍스트
    '<text x="'+cx+'" y="'+(cy-14)+'" text-anchor="middle" font-size="40" font-weight="800" fill="'+col+'">'+score+'</text>'+
    '<text x="'+cx+'" y="'+(cy+6)+'" text-anchor="middle" font-size="13" fill="#8a9084">/ 100 · 등급 '+esc(grade||'')+'</text>'+
    '</svg>';
}
function _donutSVG(items, size){
  var total=items.reduce(function(s,x){return s+x.value;},0);
  if(!total) return '';
  var cx=size/2, cy=size/2, r=size/2-6, C=2*Math.PI*r, off=0;
  var segs='';
  items.forEach(function(it,i){
    var frac=it.value/total; var len=frac*C;
    var col=_SEVCOLOR[it.label]||_BARCOLORS[i%_BARCOLORS.length];
    segs+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+col+'" stroke-width="12" '+
      'stroke-dasharray="'+len.toFixed(2)+' '+(C-len).toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')"></circle>';
    off+=len;
  });
  return '<svg width="'+size+'" height="'+size+'" viewBox="0 0 '+size+' '+size+'">'+segs+
    '<text x="'+cx+'" y="'+(cy-2)+'" text-anchor="middle" font-size="22" font-weight="700" fill="#e8eef2">'+total+'</text>'+
    '<text x="'+cx+'" y="'+(cy+16)+'" text-anchor="middle" font-size="11" fill="#8a9084">건</text></svg>';
}
function _legend(items){
  return '<div class="legend">'+items.map(function(it,i){
    var col=_SEVCOLOR[it.label]||_BARCOLORS[i%_BARCOLORS.length];
    return '<span class="lg"><i style="background:'+col+'"></i>'+esc(it.label)+' '+it.value+'</span>';
  }).join('')+'</div>';
}
function _hbars(items){
  var max=items.reduce(function(m,x){return Math.max(m,x.value);},0)||1;
  return '<div class="hbars">'+items.map(function(it,i){
    var w=Math.round(it.value/max*100);
    var col=_BARCOLORS[i%_BARCOLORS.length];
    return '<div class="hbrow"><span class="hblabel" title="'+esc(it.label)+'">'+esc(it.label)+'</span>'+
      '<span class="hbtrack"><span class="hbfill" style="width:'+w+'%;background:'+col+'"></span></span>'+
      '<span class="hbval">'+it.value+'</span></div>';
  }).join('')+'</div>';
}
function renderStats(r){
  var host=document.getElementById('stats'); if(!host) return;
  var st=r.statistics;
  if(!st || !st.total){ host.innerHTML=''; return; }
  function card(title, body){ return '<div class="statcard"><div class="statt">'+title+'</div>'+body+'</div>'; }
  var html='<div class="sec">📊 통계 요약</div><div class="statgrid">';
  // 심각도 도넛
  if(st.severity && st.severity.length)
    html+=card('심각도 분포', '<div class="donutwrap">'+_donutSVG(st.severity,120)+_legend(st.severity)+'</div>');
  // 플랫폼 도넛
  if(st.platform && st.platform.length>0)
    html+=card('플랫폼별', '<div class="donutwrap">'+_donutSVG(st.platform,120)+_legend(st.platform)+'</div>');
  // 영역별 막대
  if(st.domain && st.domain.length)
    html+=card('ISMS-P 영역별', _hbars(st.domain));
  // 위치별 막대
  if(st.location && st.location.length)
    html+=card('위치별 TOP', _hbars(st.location));
  // MITRE 막대
  if(st.mitre && st.mitre.length)
    html+=card('MITRE ATT&CK 기법별', _hbars(st.mitre));
  html+='</div>';
  host.innerHTML=html;
}
// ── 추세 비교(이전 점검 대비) : 브라우저 localStorage에 이전 결과 저장 ──
var TREND_KEY='auditor_prev_findings_v1';
function _findingKey(f){ return f.platform+'|'+f.control_code+'|'+f.issue_type+'|'+(f.resource||''); }
function _snapshot(r){
  // 비교에 필요한 최소 정보만 저장
  var m={}; (r.findings||[]).forEach(function(f){ m[_findingKey(f)]={title:f.title,severity:f.severity,platform:f.platform}; });
  return {ts:new Date().toISOString(), score:r.score, grade:r.grade, total:r.total_findings, items:m};
}
function renderTrend(r){
  var host=document.getElementById('trend'); if(!host) return;
  var prevRaw=null;
  try{ prevRaw=localStorage.getItem(TREND_KEY); }catch(e){ prevRaw=null; }
  var html='';
  if(prevRaw){
    var prev=null; try{ prev=JSON.parse(prevRaw); }catch(e){ prev=null; }
    if(prev && prev.items){
      var cur={}; (r.findings||[]).forEach(function(f){ cur[_findingKey(f)]=f; });
      var added=[], kept=0;
      Object.keys(cur).forEach(function(k){ if(!(k in prev.items)) added.push(cur[k]); else kept++; });
      var when = prev.ts ? prev.ts.replace('T',' ').substring(0,16) : '이전';
      var scoreDelta = (typeof prev.score==='number') ? (r.score - prev.score) : null;
      var deltaTxt = scoreDelta===null ? '' :
        (scoreDelta>0 ? ' (▲ +'+scoreDelta+'점 개선)' : (scoreDelta<0 ? ' (▼ '+scoreDelta+'점 악화)' : ' (변화 없음)'));
      html+='<div class="sec">📈 이전 점검 대비 변화 <span class="hint">(기준: '+esc(when)+')</span></div>';
      html+='<div class="trendbar">'+
        '<span class="tb tb-new">🆕 신규 '+added.length+'건</span>'+
        '<span class="tb tb-keep">➖ 유지 '+kept+'건</span>'+
        '<span class="tb tb-score">점수 '+r.score+deltaTxt+'</span></div>';
      if(added.length){
        html+='<div class="meta" style="margin-top:6px"><b>신규 발생:</b></div>';
        added.slice(0,10).forEach(function(f){ html+='<div class="tritem tri-new">🆕 ['+esc(f.severity)+'] '+esc(f.title)+'</div>'; });
        if(added.length>10) html+='<div class="hint">…외 '+(added.length-10)+'건</div>';
      }
      html+='<div class="row" style="margin-top:6px"><button class="btn" onclick="clearTrend()">이전 기준 지우기</button>'+
        '<span class="hint">지금 결과가 다음 비교의 기준으로 저장됩니다(이 브라우저에만 보관).</span></div>';
    }
  } else {
    html='<div class="sec">📈 이전 점검 대비 변화</div>'+
      '<div class="hint">이전 점검 기록이 없습니다. 이번 결과를 기준으로 저장했으니, 다음 점검 때 신규 발생 이슈를 비교해 보여줍니다.</div>';
  }
  host.innerHTML=html;
  // 현재 결과를 다음 비교 기준으로 저장
  try{ localStorage.setItem(TREND_KEY, JSON.stringify(_snapshot(r))); }catch(e){}
}
function clearTrend(){
  try{ localStorage.removeItem(TREND_KEY); }catch(e){}
  var host=document.getElementById('trend');
  if(host) host.innerHTML='<div class="hint">이전 기준을 지웠습니다. 다음 점검부터 새로 비교합니다.</div>';
}
function renderSummary(r){
  var host=document.getElementById('summary'); if(!host) return;
  var html='';
  // 복합 위험(공격 경로) 경고 — 최상단 강조
  if(r.correlations && r.correlations.length){
    html+='<div class="sec" style="color:#ff8080">🚨 복합 위험(공격 경로) '+r.correlations.length+'건 — 즉시 조치 권장</div>';
    r.correlations.forEach(function(c){
      html+='<div class="corr">'+
        '<div class="corrtitle">⚠️ '+esc(c.title)+'</div>'+
        '<div class="meta"><b>공격 경로:</b> '+esc(c.attack_path)+'</div>'+
        '<div class="fix"><b>✅ 우선 조치:</b> '+esc(c.recommendation)+'</div></div>';
    });
  }
  // TOP 위험(조치 우선순위)
  if(r.top_risks && r.top_risks.length){
    html+='<div class="sec">🎯 조치 우선순위 TOP '+r.top_risks.length+' (위험 점수순)</div>';
    html+='<div class="toprisk">';
    r.top_risks.forEach(function(t,i){
      var pc=t.platform==='aws'?'#ff9900':'#4da3ff';
      html+='<div class="trow">'+
        '<span class="trnum">'+(i+1)+'</span>'+
        '<span class="trscore">'+t.risk_score+'점</span>'+
        '<span class="sev '+esc(t.severity)+'">'+esc(t.severity)+'</span>'+
        '<span class="platbadge" style="background:'+pc+'">'+platLabel(t.platform)+'</span>'+
        '<span class="trtitle">'+esc(t.title)+'</span>'+
        (t.risk_factors&&t.risk_factors.length?'<span class="trfac">'+esc(t.risk_factors.join(' · '))+'</span>':'')+
        '</div>';
    });
    html+='</div>';
  }
  host.innerHTML=html;
}
function renderFindings(r){
  try{ _renderFindings(r); }
  catch(e){
    var host=document.getElementById('findings');
    if(host) host.innerHTML='<div class="finding" style="border-color:#e05563">'
      +'<b>화면 표시 중 오류가 발생했습니다.</b><br>'+esc(String(e))
      +'<br><span class="hint">브라우저를 Ctrl+Shift+R로 새로고침하거나 최신 코드로 교체했는지 확인하세요.</span></div>';
  }
}
function _renderFindings(r){
  var host=document.getElementById('findings');
  if(!r.findings || !r.findings.length){
    host.innerHTML='<div class="sec">결과</div><div class="finding empty">'+esc((r.notes&&r.notes[0])||'탐지된 이슈가 없습니다.')+'</div>';
    return;
  }
  var items=r.findings.filter(function(f){ return PLAT_FILTER==='all' || f.platform===PLAT_FILTER; });
  // VIEW_MODE에 따라 그룹핑
  var groups={}; var keyOrder=[];
  items.forEach(function(f){
    var key;
    if(VIEW_MODE==='location'){
      key=f.location || '(위치 미상)';
    } else if(VIEW_MODE==='risk'){
      key='_risk'; // 단일 그룹(위험점수순 정렬)
    } else {
      key=f.control_code+'|'+f.platform;
    }
    if(!groups[key]){ groups[key]=[]; keyOrder.push(key); }
    groups[key].push(f);
  });
  if(VIEW_MODE==='control'){
    keyOrder.sort(function(a,b){
      var ca=a.split('|')[0].split('.').map(Number), cb=b.split('|')[0].split('.').map(Number);
      for(var i=0;i<3;i++){ if((ca[i]||0)!==(cb[i]||0)) return (ca[i]||0)-(cb[i]||0); }
      return a.split('|')[1].localeCompare(b.split('|')[1]);
    });
  } else if(VIEW_MODE==='location'){
    keyOrder.sort();
  }
  // 위험점수순이면 각 그룹 안도 점수순 정렬
  if(VIEW_MODE==='risk'){
    keyOrder.forEach(function(k){ groups[k].sort(function(a,b){ return (b.risk_score||0)-(a.risk_score||0); }); });
  }
  var html='';
  keyOrder.forEach(function(key){
    var fs=groups[key];
    // 섹션 헤더
    if(VIEW_MODE==='location'){
      html+='<div class="sec">📍 '+esc(key)+' — '+fs.length+'건</div>';
    } else if(VIEW_MODE==='risk'){
      html+='<div class="sec">🎯 전체 이슈 (위험 점수순) — '+fs.length+'건</div>';
    } else {
      var code=key.split('|')[0]; var plat=fs[0].platform;
      var pcolor=plat==='aws'?'#ff9900':'#4da3ff';
      html+='<div class="sec"><span class="platbadge" style="background:'+pcolor+'">'+platLabel(plat)+'</span> ['+esc(code)+'] '+esc(fs[0].control_domain||'')+' — '+fs.length+'건</div>';
    }
    fs.forEach(function(f){
      var fpc=f.platform==='aws'?'#ff9900':'#4da3ff';
      html+='<div class="finding"><div class="ftop">'+
        '<span class="sev '+esc(f.severity)+'">'+esc(f.severity)+'</span>'+
        (typeof f.risk_score==='number' ? '<span class="rsbadge">위험 '+f.risk_score+'</span>' : '')+
        '<span class="platbadge" style="background:'+fpc+'">'+platLabel(f.platform)+'</span>'+
        '<span class="code">'+esc(f.control_code)+'</span>'+
        '<span class="ftitle">'+esc(f.title)+'</span></div>';
      if(f.resource) html+='<div class="meta"><b>대상:</b> '+esc(f.resource)+'</div>';
      if(f.location) html+='<div class="loc"><b>📍 위치:</b> '+esc(f.location)+'</div>';
      if(f.mitre_id) html+='<div class="meta"><span class="mitre">ATT&CK '+esc(f.mitre_id)+'</span> '+esc(f.mitre_name)+'</div>';
      html+='<div class="meta"><b>문제:</b> '+esc(f.description)+'</div>';
      if(f.why) html+='<div class="why"><b>❓ 왜 문제인가요?</b><br>'+nl2br(esc(f.why))+'</div>';
      html+='<div class="fix"><b>✅ 개선 제안:</b> '+esc(f.recommendation)+'</div>';
      if(f.how_to_fix) html+='<div class="howto"><b>🛠️ 해결 방법(단계별)</b><br>'+nl2br(esc(f.how_to_fix))+'</div>';
      if(f.steps) html+='<div class="steps"><b>📖 따라하기 (포털 클릭 순서 + 실행 명령어)</b><br>'+nl2br(esc(f.steps))+'</div>';
      if(f.bad_example) html+='<div class="exbad"><b>✗ 위반 예시:</b> <code>'+esc(f.bad_example)+'</code></div>';
      if(f.good_example) html+='<div class="exgood"><b>✓ 개선 예시:</b> <code>'+esc(f.good_example)+'</code></div>';
      if(f.evidence) html+='<div class="evlabel"><b>🔎 판단 근거(입력에서 감지된 내용)</b></div><pre>'+esc(f.evidence)+'</pre>';
      html+='</div>';
    });
  });
  host.innerHTML=html || '<div class="finding empty">선택한 플랫폼의 이슈가 없습니다.</div>';
}

function _baseFromLoaded(){
  // 업로드한 파일명이 있으면 확장자를 뗀 기본이름을 돌려준다(없으면 빈 문자열).
  if(!LOADED_FILENAME) return '';
  var name=LOADED_FILENAME;
  var dot=name.lastIndexOf('.');
  if(dot>0) name=name.substring(0,dot);           // 확장자 제거
  name=name.replace(/[\\\/:*?"<>|]+/g,'_').trim(); // 파일명 금지문자 정리
  return name;
}
function _tsName(ext){
  var d=new Date();
  function p(n){ return (n<10?'0':'')+n; }
  var stamp=d.getFullYear()+p(d.getMonth()+1)+p(d.getDate())+'_'+p(d.getHours())+p(d.getMinutes());
  var base=_baseFromLoaded();
  // 업로드 파일명이 있으면 "audit_<파일명>_<날짜시간>.ext", 없으면 기존과 동일.
  if(base) return 'audit_'+base+'_'+stamp+'.'+ext;
  return 'azure-audit_'+stamp+'.'+ext;
}
async function downloadCsv(){
  var text=document.getElementById('input').value;
  if(!text.trim()){ document.getElementById('err').textContent='먼저 보안검토를 실행하세요.'; return; }
  try{
    var resp=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text,format:'csv',filename:LOADED_FILENAME})});
    var blob=await resp.blob();
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url; a.download=_tsName('csv');
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
  }catch(e){ document.getElementById('err').textContent='CSV 저장 실패: '+e; }
}
async function downloadXlsx(){
  var text=document.getElementById('input').value;
  if(!text.trim()){ document.getElementById('err').textContent='먼저 보안검토를 실행하세요.'; return; }
  try{
    var resp=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text,format:'xlsx',filename:LOADED_FILENAME})});
    var blob=await resp.blob();
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url; a.download=_tsName('xlsx');
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
  }catch(e){ document.getElementById('err').textContent='엑셀 저장 실패: '+e; }
}
async function openPdf(){
  var text=document.getElementById('input').value;
  if(!text.trim()){ document.getElementById('err').textContent='먼저 보안검토를 실행하세요.'; return; }
  try{
    var resp=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text,format:'html'})});
    var html=await resp.text();
    var w=window.open('', '_blank');
    if(!w){ document.getElementById('err').textContent='팝업이 차단되었습니다. 팝업을 허용한 뒤 다시 시도하세요.'; return; }
    w.document.open(); w.document.write(html); w.document.close();
    // 브라우저의 "PDF로 저장" 기본 파일명은 창 제목을 따르므로, 업로드 파일명 기반 이름으로 설정.
    try{ w.document.title=_tsName('pdf').replace(/\.pdf$/,''); }catch(e){}
  }catch(e){ document.getElementById('err').textContent='PDF(인쇄) 준비 실패: '+e; }
}

// ===== 사고 대응(IR) 가이드 =====
var IR_TYPES=null; var IR_PLAT='aws';
async function loadIrTypes(){
  try{
    var resp=await fetch('/api/ir_types');
    var d=await resp.json();
    IR_TYPES=(d&&d.types)||[];
    var sel=document.getElementById('ir-type');
    sel.innerHTML=IR_TYPES.map(function(t){
      return '<option value="'+esc(t.type)+'">'+esc(t.name)+' ('+esc(t.severity)+')</option>';
    }).join('');
  }catch(e){ document.getElementById('ir-err').textContent='유형 목록 로드 실패: '+e; }
}
function setIrPlat(p){
  IR_PLAT=p;
  Array.prototype.forEach.call(document.querySelectorAll('#ir-plat button'), function(b){
    b.classList.toggle('on', b.getAttribute('data-p')===p);
  });
}
async function runIr(){
  var errEl=document.getElementById('ir-err'); errEl.textContent='';
  var itype=document.getElementById('ir-type').value;
  if(!itype){ errEl.textContent='침해 유형을 선택하세요.'; return; }
  try{
    var resp=await fetch('/api/ir',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({type:itype, platform:IR_PLAT})});
    var d=await resp.json();
    if(!d.ok){ errEl.textContent='생성 실패: '+(d.error||'알 수 없는 오류'); return; }
    renderIr(d.playbook);
  }catch(e){ errEl.textContent='생성 실패: '+e; }
}
function renderIr(pb){
  var host=document.getElementById('ir-result'); if(!host) return;
  var sev=pb.severity||'INFO';
  var html='<div class="card">';
  html+='<div class="ftop"><span class="sev '+esc(sev)+'">'+esc(sev)+'</span>'+
        '<span class="ftitle" style="font-size:16px">'+esc(pb.name)+'</span>'+
        '<span class="code">'+esc(pb.platform.toUpperCase())+'</span></div>';
  html+='<div class="meta" style="margin-top:6px">'+esc(pb.summary)+'</div>';
  html+='<div class="hint" style="margin-top:4px"><b>ISMS-P:</b> '+esc(pb.isms_p)+' &nbsp;|&nbsp; <b>MITRE:</b> '+esc(pb.mitre)+'</div>';
  // 단계
  (pb.steps||[]).forEach(function(st){
    html+='<div class="sec" style="margin-top:10px">'+esc(st.phase)+'</div>';
    (st.actions||[]).forEach(function(a){ html+='<div class="tritem tri-new">• '+esc(a)+'</div>'; });
  });
  // 증거 수집 명령어
  if(pb.evidence_commands && pb.evidence_commands.length){
    html+='<div class="sec" style="margin-top:10px">🔎 증거 수집 명령어 <span class="hint">(담당자 검토 후 실행, 값은 실제로 치환)</span></div>';
    pb.evidence_commands.forEach(function(c,i){
      var id='ircmd'+i;
      html+='<div class="cmdcard"><code id="'+id+'">'+esc(c)+'</code>'+
            ' <button class="copybtn" onclick="copyCmd(\\''+id+'\\',this)">복사</button></div>';
    });
  }
  // 보고서 양식
  if(pb.report_template && pb.report_template.length){
    html+='<div class="sec" style="margin-top:10px">📝 사고 보고서 양식</div>';
    html+='<div class="finding">'+pb.report_template.map(function(r){return esc(r);}).join('<br>')+'</div>';
  }
  html+='<div class="crit-hint" style="margin-top:10px">'+esc(pb.disclaimer)+'</div>';
  html+='</div>';
  host.innerHTML=html;
}

// ===== 앱 보안 점검(SAST/WAF) =====
var AS_MODE='sast'; var AS_PLAT='aws';
function setAsMode(m){
  AS_MODE=m;
  Array.prototype.forEach.call(document.querySelectorAll('#as-mode button'), function(b){
    b.classList.toggle('on', b.getAttribute('data-m')===m);
  });
  var lbl=document.getElementById('as-label');
  var pw=document.getElementById('as-plat-wrap'); var pt=document.getElementById('as-plat');
  if(m==='sast'){ lbl.textContent='점검할 소스코드 붙여넣기'; }
  else if(m==='waf'){ lbl.textContent='WAF 정책·구성(JSON) 붙여넣기'; }
  else { lbl.textContent='소스코드 또는 구성 붙여넣기'; }
  // WAF 점검일 때만 플랫폼 선택이 의미 있음(표기)
  var show=(m!=='sast');
  pw.style.opacity=show?'1':'0.4'; pt.style.opacity=show?'1':'0.4';
}
function setAsPlat(p){
  AS_PLAT=p;
  Array.prototype.forEach.call(document.querySelectorAll('#as-plat button'), function(b){
    b.classList.toggle('on', b.getAttribute('data-p')===p);
  });
}
function loadAsFile(){
  var f=document.getElementById('as-file').files[0];
  var meta=document.getElementById('as-load-info');
  var errEl=document.getElementById('as-err');
  if(!f){ return; }
  errEl.textContent='';
  var r=new FileReader();
  r.onload=function(e){
    document.getElementById('as-input').value=e.target.result;
    if(meta) meta.textContent='불러옴: '+f.name+' ('+f.size+' bytes)';
  };
  r.onerror=function(){ errEl.textContent='파일 읽기에 실패했습니다.'; };
  r.readAsText(f);
}
function clearAppsec(){
  document.getElementById('as-input').value='';
  document.getElementById('as-result').innerHTML='';
  document.getElementById('as-err').textContent='';
  var m=document.getElementById('as-load-info'); if(m) m.textContent='';
}
async function runAppsec(){
  var errEl=document.getElementById('as-err'); errEl.textContent='';
  var text=document.getElementById('as-input').value;
  if(!text.trim()){ errEl.textContent='점검할 소스코드 또는 구성을 입력하세요.'; return; }
  try{
    var resp=await fetch('/api/appsec',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({text:text, mode:AS_MODE, platform:AS_PLAT})});
    var d=await resp.json();
    if(!d.ok){ errEl.textContent='점검 실패: '+(d.error||'알 수 없는 오류'); return; }
    renderAppsec(d);
  }catch(e){ errEl.textContent='점검 실패: '+e; }
}
function renderAppsec(d){
  var host=document.getElementById('as-result'); if(!host) return;
  var html='<div class="card">';
  var order=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  var cnt=d.severity_counts||{};
  var chips=order.filter(function(s){return cnt[s];}).map(function(s){
    return '<span class="sev '+s+'">'+s+' '+cnt[s]+'</span>';
  }).join(' ');
  html+='<div class="ftop"><span class="ftitle" style="font-size:16px">점검 결과: 이슈 '+d.total+'건</span> '+chips+'</div>';
  if(!d.findings.length){
    html+='<div class="finding empty" style="margin-top:8px">탐지된 이슈가 없습니다. (규칙 기반 참고 결과)</div>';
  } else {
    d.findings.forEach(function(f){
      html+='<div class="finding">';
      html+='<div class="ftop"><span class="sev '+esc(f.severity)+'">'+esc(f.severity)+'</span>'+
            '<span class="code">'+esc(f.control_code)+'</span>'+
            '<span class="ftitle">'+esc(f.title)+'</span></div>';
      if(f.description) html+='<div class="meta" style="margin-top:6px">'+esc(f.description)+'</div>';
      if(f.evidence) html+='<div class="exbad" style="margin-top:6px">근거: '+esc(f.evidence)+'</div>';
      if(f.recommendation) html+='<div class="fix" style="margin-top:6px"><b>✅ 개선:</b> '+esc(f.recommendation)+'</div>';
      if(f.bad_example) html+='<div class="exbad" style="margin-top:6px">✗ '+esc(f.bad_example)+'</div>';
      if(f.good_example) html+='<div class="exgood" style="margin-top:4px">✓ '+esc(f.good_example)+'</div>';
      html+='</div>';
    });
  }
  (d.notes||[]).forEach(function(n){ html+='<div class="crit-hint" style="margin-top:8px">'+esc(n)+'</div>'; });
  html+='</div>';
  host.innerHTML=html;
}
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "AzureAuditor/0.1"

    def log_message(self, fmt, *args):
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # 브라우저가 옛 화면을 캐시에 붙잡지 않도록(코드 갱신 후 새로고침만으로 반영).
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send_html(INDEX_HTML)
        elif self.path == "/favicon.ico":
            # 브라우저가 자동 요청하는 파비콘. 콘솔 404 방지용으로 빈 응답(204).
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/api/controls":
            self._send_json({"controls": all_controls()})
        elif self.path == "/api/ir_types":
            self._send_json({"types": ir_playbook.list_incident_types()})
        elif self.path.startswith("/api/commands"):
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            platform = (qs.get("platform", ["aws"])[0] or "aws").lower()
            if platform not in ("aws", "azure"):
                platform = "aws"
            from .collector_script import _SERVICE_INFO
            cmds = collection_commands(platform)
            cli = "az" if platform == "azure" else "aws"
            for c in cmds:
                target, perm = _SERVICE_INFO.get(c.get("service", "기타"), ("해당 서비스 구성", "읽기 전용 권한"))
                c["run_where"] = f"관리자 PC ({cli} CLI) — 클라우드 API로 원격 수집"
                c["service_target"] = target
                c["service_perm"] = perm
            self._send_json({"platform": platform, "commands": cmds})
        elif self.path.startswith("/api/script"):
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            platform = (qs.get("platform", ["azure"])[0] or "azure").lower()
            if platform not in ("aws", "azure"):
                platform = "azure"
            shell = (qs.get("shell", ["bash"])[0] or "bash").lower()
            if shell not in ("bash", "ps1"):
                shell = "bash"
            body = build_script(platform, shell).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{script_filename(platform, shell)}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

    def _disposition(self, filename):
        """다운로드 파일명 헤더 값 생성. 한글 등 비ASCII는 RFC 5987로 인코딩.

        브라우저의 <a download> 속성 지원 여부와 무관하게 파일명이 적용되도록
        서버가 직접 Content-Disposition을 내려준다(구형 브라우저 대응).
        """
        from urllib.parse import quote
        # ASCII 폴백 파일명(비ASCII는 _ 로 치환)과 UTF-8 filename* 를 함께 제공.
        ascii_name = filename.encode("ascii", "replace").decode("ascii").replace("?", "_")
        star = quote(filename, safe="")
        return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{star}"

    def _send_text(self, text, content_type="text/plain; charset=utf-8", status=200, filename=None):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if filename:
            self.send_header("Content-Disposition", self._disposition(filename))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, data: bytes, content_type: str, status=200, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if filename:
            self.send_header("Content-Disposition", self._disposition(filename))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_payload(self):
        """요청 본문을 dict로. (payload, error_response) 반환."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > _MAX_BODY:
            return None, "입력이 너무 큽니다(최대 8MB)."
        raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            payload = {"text": raw}
        if not isinstance(payload, dict):
            payload = {}
        return payload, None

    def _read_raw_bytes(self):
        """요청 본문을 원시 바이트로. (data, error) 반환."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > _MAX_BODY:
            return None, "파일이 너무 큽니다(최대 8MB)."
        return (self.rfile.read(length) if length else b""), None

    def do_POST(self):
        if self.path == "/api/audit":
            self._handle_audit()
        elif self.path == "/api/export":
            self._handle_export()
        elif self.path == "/api/decode":
            self._handle_decode()
        elif self.path == "/api/ir":
            self._handle_ir()
        elif self.path == "/api/appsec":
            self._handle_appsec()
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

    def _handle_ir(self):
        """사고 대응(IR) 플레이북 생성. {type, platform} 입력."""
        try:
            payload, err = self._read_payload()
            if err:
                self._send_json({"ok": False, "error": err}, status=413)
                return
            itype = (payload.get("type") or "").strip()
            platform = (payload.get("platform") or "aws").lower()
            try:
                pb = ir_playbook.build_playbook(itype, platform)
            except KeyError:
                self._send_json({"ok": False, "error": f"알 수 없는 침해 유형: {itype}"}, status=400)
                return
            self._send_json({"ok": True, "playbook": pb})
        except Exception as e:  # noqa: BLE001
            logger.exception("ir 실패")
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _handle_appsec(self):
        """앱 보안 점검(간이 SAST / WAF). {text, mode, platform} 입력."""
        try:
            payload, err = self._read_payload()
            if err:
                self._send_json({"ok": False, "error": err}, status=413)
                return
            text = payload.get("text", "")
            mode = (payload.get("mode") or "sast").lower()
            platform = (payload.get("platform") or "aws").lower()
            result = appsec.run(text, filename=payload.get("filename", ""),
                                platform=platform, mode=mode)
            self._send_json(result)
        except Exception as e:  # noqa: BLE001
            logger.exception("appsec 실패")
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _handle_decode(self):
        """파일 바이트를 받아 인코딩을 판별·디코딩해 텍스트로 돌려준다.

        두 가지 전송 방식을 모두 지원한다(구형 브라우저 호환):
          - Content-Type: text/plain  → 본문이 Base64 문자열(구형 브라우저용, 권장)
          - 그 외                      → 본문이 원시 바이트
        """
        try:
            data, err = self._read_raw_bytes()
            if err:
                self._send_json({"ok": False, "error": err}, status=413)
                return
            ctype = (self.headers.get("Content-Type") or "").lower()
            if "text/plain" in ctype or "base64" in ctype:
                # Base64 문자열로 전송된 경우 디코딩(구형 브라우저 XHR 방식).
                import base64
                raw = data.decode("ascii", errors="ignore").strip()
                # "data:...;base64," 접두어가 붙어 오면 제거.
                if "," in raw and raw[:5].lower() == "data:":
                    raw = raw.split(",", 1)[1]
                try:
                    data = base64.b64decode(raw)
                except Exception:  # noqa: BLE001 - 잘못된 base64면 원시로 취급
                    pass
            text, enc = decode_bytes(data)
            self._send_json({"ok": True, "text": text, "encoding": enc})
        except Exception as e:  # noqa: BLE001
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _handle_audit(self):
        try:
            payload, err = self._read_payload()
            if err:
                self._send_json({"ok": False, "error": err}, status=413)
                return
            report = analyze(payload.get("text", ""))
            rd = report.to_dict()
            from .engine import build_statistics
            rd["statistics"] = build_statistics(rd)
            self._send_json({"ok": True, "report": rd})
        except Exception as e:  # noqa: BLE001 - UI에 오류 전달
            logger.exception("audit 실패")
            self._send_json({"ok": False, "error": str(e)}, status=500)

    def _handle_export(self):
        """검토 결과를 CSV 또는 HTML 텍스트로 반환(브라우저에서 다운로드/인쇄)."""
        try:
            payload, err = self._read_payload()
            if err:
                self._send_json({"ok": False, "error": err}, status=413)
                return
            fmt = str(payload.get("format", "csv")).lower()
            report = analyze(payload.get("text", ""))
            # 클라이언트가 보낸 업로드 파일명(base)으로 다운로드 파일명을 서버에서 확정.
            # 이렇게 하면 브라우저 <a download> 지원 여부와 무관하게 파일명이 적용된다.
            ext = "csv" if fmt == "csv" else ("xlsx" if fmt == "xlsx" else "html")
            fname = _export_filename(payload.get("filename", ""), ext)
            if fmt == "html":
                # HTML은 새 창에서 열어 인쇄하므로 다운로드 파일명(Content-Disposition) 불필요.
                self._send_text(format_html(report), "text/html; charset=utf-8")
            elif fmt == "csv":
                # CSV(BOM 포함). 브라우저 JS가 Blob으로 받아 파일 저장.
                self._send_text(format_csv(report), "text/csv; charset=utf-8", filename=fname)
            elif fmt == "xlsx":
                # 진짜 엑셀(.xlsx) 바이트. CSV의 셀 분리/데이터 손실 없음.
                self._send_bytes(
                    format_xlsx(report),
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    filename=fname,
                )
            else:
                self._send_json({"ok": False, "error": "지원하지 않는 format"}, status=400)
        except Exception as e:  # noqa: BLE001
            logger.exception("export 실패")
            self._send_json({"ok": False, "error": str(e)}, status=500)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="클라우드 전용 보안검토(AWS/Azure) - 로컬 웹 UI")
    parser.add_argument("--host", default="127.0.0.1",
                        help="바인딩 주소(기본 127.0.0.1=로컬 전용, 권장). "
                             "0.0.0.0 등 외부 주소는 네트워크 노출 위험이 있으니 주의")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # 보안 경고: 로컬 루프백(127.0.0.1)이 아닌 주소로 바인딩하면 같은 네트워크의
    # 다른 기기에서 접근 가능해진다. 이 도구는 인증이 없으므로 로컬 사용을 권장한다.
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("⚠️  경고: 이 서버는 인증이 없습니다. 로컬(127.0.0.1)이 아닌 주소로 바인딩하면")
        print(f"    같은 네트워크의 다른 기기에서 접근할 수 있습니다(현재: {args.host}).")
        print("    신뢰된 폐쇄망에서만, 필요한 경우에만 사용하세요.")
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"웹 UI: http://{args.host}:{args.port}  (Ctrl+C로 종료)")
    print("폐쇄망 전용 · 외부 네트워크 연결 없음(Slack 알림은 자동화 모듈에서만, 선택)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
