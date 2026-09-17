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
<title>클라우드 정책 오프라인 보안검토 (ISMS-P · AWS/Azure)</title>
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
  .trendbar{ display:flex; gap:8px; flex-wrap:wrap; margin:6px 0; }
  .tb{ font-size:13px; font-weight:700; padding:4px 10px; border-radius:8px; border:1px solid var(--border); }
  .tb-new{ background:#2a1518; color:#ff9b9b; }
  .tb-res{ background:#0f2418; color:#8fe6b0; }
  .tb-keep{ background:#12233a; color:#cfe3ff; }
  .tb-score{ background:#241a38; color:#e0c8ff; }
  .tritem{ font-size:12px; padding:3px 8px; margin:2px 0; border-radius:5px; }
  .tri-new{ background:#2a1518; }
  .tri-res{ background:#0f2418; }
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
</style>
</head>
<body>
<header>
  <h1>🛡️ 클라우드 정책 오프라인 보안검토 <span class="sub">(ISMS-P · AWS/Azure)</span> <span class="sub" style="font-size:12px;opacity:.7">v4 (해결가이드·따라하기 포함)</span></h1>
  <div class="sub">AWS(<code>aws ...</code>)/Azure(<code>az ...</code>) CLI로 추출한 정책·구성 텍스트를 붙여넣거나 업로드하면, <b>인터넷·AI 없이</b> 이슈를 찾고 개선안을 제안합니다. 플랫폼은 자동으로 구별됩니다.</div>
</header>
<div class="tabs">
  <div class="tab active" id="tab-audit" onclick="switchTab('audit')">🔎 보안검토</div>
  <div class="tab" id="tab-commands" onclick="switchTab('commands')">📋 수집 명령어 가이드</div>
</div>
<main>
 <div id="pane-audit">
  <div class="card">
    <div class="banner">🔒 폐쇄망 전용 · 외부 전송 없음 · 입력은 서버 메모리에서만 처리되고 저장되지 않습니다.
      <br>입력 예: <code>az network nsg rule list ... -o json</code>, <code>az storage account show ...</code>, <code>az role assignment list ...</code> 등의 출력(여러 명령 출력을 이어붙여도 됨).</div>
    <label>AWS/Azure 정책·구성 텍스트 (붙여넣기)</label>
    <textarea id="input" placeholder='예) [{"name":"allow-ssh","access":"Allow","direction":"Inbound","sourceAddressPrefix":"*","destinationPortRange":"22"}]'></textarea>
    <div class="row">
      <input type="file" id="file" accept=".txt,.json,.log,.tsv">
      <button class="btn" onclick="loadFile()">파일 불러오기</button>
      <button class="btn primary" onclick="runAudit()">보안검토 실행</button>
      <button class="btn" onclick="clearAll()">지우기</button>
      <span class="hint">파일 업로드도 로컬에서만 읽어 텍스트칸에 채웁니다(서버 전송 시에도 저장 안 함).</span>
    </div>
    <div class="hint" id="load-info" style="margin-top:6px"></div>
    <div class="err" id="err"></div>
  </div>

  <div class="card" id="result-card" style="display:none">
    <div class="scorecard">
      <div class="score" id="score">-</div>
      <div>
        <div id="grade-line" style="font-size:15px;font-weight:700"></div>
        <div class="counts" id="counts"></div>
        <div class="hint" id="meta"></div>
        <div class="row" id="plat-filter" style="display:none;margin-top:8px"></div>
      </div>
    </div>
    <div class="row" style="margin-top:12px">
      <button class="btn primary" onclick="downloadXlsx()">⬇️ 엑셀(.xlsx) 저장</button>
      <button class="btn" onclick="downloadCsv()">CSV 저장</button>
      <button class="btn" onclick="openPdf()">🖨️ PDF로 저장 (인쇄)</button>
      <span class="hint">엑셀(.xlsx)은 줄바꿈·특수문자가 그대로 보존됩니다(권장). PDF는 새 창의 인쇄 대화상자에서 "PDF로 저장"을 선택하세요.</span>
    </div>
    <div id="trend"></div>
    <div id="summary"></div>
    <div id="findings"></div>
    <div class="hint" style="margin-top:14px">※ 오프라인 규칙 기반 자동 검토 결과이며 참고용입니다. 실제 조치 전 대상 환경과 업무 요건을 확인하세요. KISA 공식 심사자료를 대체하지 않습니다.</div>
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
</main>
<script>
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function nl2br(s){ return String(s==null?'':s).replace(/\\n/g,'<br>'); }

// ----- 탭 -----
function switchTab(t){
  document.getElementById('pane-audit').style.display = (t==='audit')?'block':'none';
  document.getElementById('pane-commands').style.display = (t==='commands')?'block':'none';
  document.getElementById('tab-audit').classList.toggle('active', t==='audit');
  document.getElementById('tab-commands').classList.toggle('active', t==='commands');
  if(t==='commands' && !CMD_DATA){ loadCommands(); }
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
    return '<div class="cmdcard">'+
      '<div class="cmdhead"><span class="platbadge" style="background:'+pcolor+'">'+platName+'</span>'+
      '<span class="code">'+esc(c.code)+'</span><b>'+esc(c.domain)+'</b></div>'+
      '<div class="meta">'+esc(c.desc)+'</div>'+lines+crit+bad+good+'</div>';
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
function clearAll(){ document.getElementById('input').value=''; document.getElementById('result-card').style.display='none'; document.getElementById('err').textContent=''; LOADED_FILENAME=''; var m=document.getElementById('load-info'); if(m) m.textContent=''; var s=document.getElementById('summary'); if(s) s.innerHTML=''; var tr=document.getElementById('trend'); if(tr) tr.innerHTML=''; }
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
function platLabel(p){ return p==='aws'?'AWS':(p==='azure'?'Azure':(p||'').toUpperCase()); }
function setPlatFilter(p){ PLAT_FILTER=p; renderFindings(LAST_REPORT); updateFilterButtons(); }
function updateFilterButtons(){
  var wrap=document.getElementById('plat-filter'); if(!wrap) return;
  Array.prototype.forEach.call(wrap.querySelectorAll('button'), function(b){
    b.style.opacity = (b.getAttribute('data-p')===PLAT_FILTER)?'1':'0.5';
  });
}
function render(r){
  LAST_REPORT=r; PLAT_FILTER='all';
  document.getElementById('result-card').style.display='block';
  var sc=document.getElementById('score'); sc.textContent=r.score; sc.className='score grade-'+r.grade;
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

  renderTrend(r);
  renderSummary(r);
  renderFindings(r);
  updateFilterButtons();
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
      var added=[], resolved=[], kept=0;
      Object.keys(cur).forEach(function(k){ if(!(k in prev.items)) added.push(cur[k]); else kept++; });
      Object.keys(prev.items).forEach(function(k){ if(!(k in cur)) resolved.push(prev.items[k]); });
      var when = prev.ts ? prev.ts.replace('T',' ').substring(0,16) : '이전';
      var scoreDelta = (typeof prev.score==='number') ? (r.score - prev.score) : null;
      var deltaTxt = scoreDelta===null ? '' :
        (scoreDelta>0 ? ' (▲ +'+scoreDelta+'점 개선)' : (scoreDelta<0 ? ' (▼ '+scoreDelta+'점 악화)' : ' (변화 없음)'));
      html+='<div class="sec">📈 이전 점검 대비 변화 <span class="hint">(기준: '+esc(when)+')</span></div>';
      html+='<div class="trendbar">'+
        '<span class="tb tb-new">🆕 신규 '+added.length+'건</span>'+
        '<span class="tb tb-res">✅ 해결 '+resolved.length+'건</span>'+
        '<span class="tb tb-keep">➖ 유지 '+kept+'건</span>'+
        '<span class="tb tb-score">점수 '+r.score+deltaTxt+'</span></div>';
      if(added.length){
        html+='<div class="meta" style="margin-top:6px"><b>신규 발생:</b></div>';
        added.slice(0,10).forEach(function(f){ html+='<div class="tritem tri-new">🆕 ['+esc(f.severity)+'] '+esc(f.title)+'</div>'; });
        if(added.length>10) html+='<div class="hint">…외 '+(added.length-10)+'건</div>';
      }
      if(resolved.length){
        html+='<div class="meta" style="margin-top:6px"><b>해결됨:</b></div>';
        resolved.slice(0,10).forEach(function(f){ html+='<div class="tritem tri-res">✅ '+esc(f.title)+'</div>'; });
        if(resolved.length>10) html+='<div class="hint">…외 '+(resolved.length-10)+'건</div>';
      }
      html+='<div class="row" style="margin-top:6px"><button class="btn" onclick="clearTrend()">이전 기준 지우기</button>'+
        '<span class="hint">지금 결과가 다음 비교의 기준으로 저장됩니다(이 브라우저에만 보관).</span></div>';
    }
  } else {
    html='<div class="sec">📈 이전 점검 대비 변화</div>'+
      '<div class="hint">이전 점검 기록이 없습니다. 이번 결과를 기준으로 저장했으니, 다음 점검 때 신규/해결 이슈를 비교해 보여줍니다.</div>';
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
  // (통제항목, 플랫폼)별 그룹
  var groups={}; var keyOrder=[];
  items.forEach(function(f){
    var key=f.control_code+'|'+f.platform;
    if(!groups[key]){ groups[key]=[]; keyOrder.push(key); }
    groups[key].push(f);
  });
  keyOrder.sort(function(a,b){
    var ca=a.split('|')[0].split('.').map(Number), cb=b.split('|')[0].split('.').map(Number);
    for(var i=0;i<3;i++){ if((ca[i]||0)!==(cb[i]||0)) return (ca[i]||0)-(cb[i]||0); }
    return a.split('|')[1].localeCompare(b.split('|')[1]);
  });
  var html='';
  keyOrder.forEach(function(key){
    var fs=groups[key]; var code=key.split('|')[0]; var plat=fs[0].platform;
    var pcolor=plat==='aws'?'#ff9900':'#4da3ff';
    html+='<div class="sec"><span class="platbadge" style="background:'+pcolor+'">'+platLabel(plat)+'</span> ['+esc(code)+'] '+esc(fs[0].control_domain||'')+' — '+fs.length+'건</div>';
    fs.forEach(function(f){
      html+='<div class="finding"><div class="ftop">'+
        '<span class="sev '+esc(f.severity)+'">'+esc(f.severity)+'</span>'+
        '<span class="platbadge" style="background:'+pcolor+'">'+platLabel(f.platform)+'</span>'+
        '<span class="code">'+esc(f.control_code)+'</span>'+
        '<span class="ftitle">'+esc(f.title)+'</span></div>';
      if(f.resource) html+='<div class="meta"><b>대상:</b> '+esc(f.resource)+'</div>';
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
        elif self.path.startswith("/api/commands"):
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            platform = (qs.get("platform", ["aws"])[0] or "aws").lower()
            if platform not in ("aws", "azure"):
                platform = "aws"
            self._send_json({"platform": platform, "commands": collection_commands(platform)})
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
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

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
            self._send_json({"ok": True, "report": report.to_dict()})
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
    parser = argparse.ArgumentParser(description="클라우드 정책 오프라인 보안검토(AWS/Azure) - 로컬 웹 UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"웹 UI: http://{args.host}:{args.port}  (Ctrl+C로 종료)")
    print("폐쇄망 전용 · 외부 네트워크 연결 없음")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
