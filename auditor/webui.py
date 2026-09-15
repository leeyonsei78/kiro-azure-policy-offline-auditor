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
from .knowledge_base import all_controls, collection_commands
from .report import format_csv, format_html

logger = logging.getLogger(__name__)

# 업로드 크기 상한(폐쇄망 로컬이지만 방어적으로): 8MB
_MAX_BODY = 8 * 1024 * 1024


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
  <h1>🛡️ 클라우드 정책 오프라인 보안검토 <span class="sub">(ISMS-P · AWS/Azure)</span></h1>
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
      <button class="btn" onclick="downloadCsv()">⬇️ CSV 저장 (엑셀)</button>
      <button class="btn" onclick="openPdf()">🖨️ PDF로 저장 (인쇄)</button>
      <span class="hint">CSV는 엑셀에서 열립니다. PDF는 새 창의 인쇄 대화상자에서 "PDF로 저장"을 선택하세요.</span>
    </div>
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
    <div class="err" id="cmd-err"></div>
  </div>
  <div id="cmd-list"></div>
  <div class="hint" style="margin:0 0 20px">※ 명령의 &lt;NSG&gt;·&lt;RG&gt;·&lt;BUCKET&gt; 등 자리표시자는 실제 값으로 바꿔 사용하세요. 조직 계정·리전·CLI 버전·권한에 맞게 조정이 필요할 수 있습니다.</div>
 </div><!-- /pane-commands -->
</main>
<script>
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// ----- 탭 -----
function switchTab(t){
  document.getElementById('pane-audit').style.display = (t==='audit')?'block':'none';
  document.getElementById('pane-commands').style.display = (t==='commands')?'block':'none';
  document.getElementById('tab-audit').classList.toggle('active', t==='audit');
  document.getElementById('tab-commands').classList.toggle('active', t==='commands');
  if(t==='commands' && !CMD_DATA){ loadCommands(); }
}

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
function clearAll(){ document.getElementById('input').value=''; document.getElementById('result-card').style.display='none'; document.getElementById('err').textContent=''; }
function loadFile(){
  var f=document.getElementById('file').files[0];
  if(!f){ document.getElementById('err').textContent='파일을 먼저 선택하세요.'; return; }
  var r=new FileReader();
  r.onload=function(e){ document.getElementById('input').value=e.target.result; document.getElementById('err').textContent=''; };
  r.readAsText(f);
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

  renderFindings(r);
  updateFilterButtons();
}
function renderFindings(r){
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
      html+='<div class="meta"><b>문제:</b> '+esc(f.description)+'</div>';
      html+='<div class="fix"><b>✅ 개선 제안:</b> '+esc(f.recommendation)+'</div>';
      if(f.bad_example) html+='<div class="exbad"><b>✗ 위반 예시:</b> <code>'+esc(f.bad_example)+'</code></div>';
      if(f.good_example) html+='<div class="exgood"><b>✓ 개선 예시:</b> <code>'+esc(f.good_example)+'</code></div>';
      if(f.evidence) html+='<pre>'+esc(f.evidence)+'</pre>';
      html+='</div>';
    });
  });
  host.innerHTML=html || '<div class="finding empty">선택한 플랫폼의 이슈가 없습니다.</div>';
}

function _tsName(ext){
  var d=new Date();
  function p(n){ return (n<10?'0':'')+n; }
  return 'azure-audit_'+d.getFullYear()+p(d.getMonth()+1)+p(d.getDate())+'_'+p(d.getHours())+p(d.getMinutes())+'.'+ext;
}
async function downloadCsv(){
  var text=document.getElementById('input').value;
  if(!text.trim()){ document.getElementById('err').textContent='먼저 보안검토를 실행하세요.'; return; }
  try{
    var resp=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:text,format:'csv'})});
    var blob=await resp.blob();
    var url=URL.createObjectURL(blob);
    var a=document.createElement('a');
    a.href=url; a.download=_tsName('csv');
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
  }catch(e){ document.getElementById('err').textContent='CSV 저장 실패: '+e; }
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
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send_html(INDEX_HTML)
        elif self.path == "/api/controls":
            self._send_json({"controls": all_controls()})
        elif self.path.startswith("/api/commands"):
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            platform = (qs.get("platform", ["aws"])[0] or "aws").lower()
            if platform not in ("aws", "azure"):
                platform = "aws"
            self._send_json({"platform": platform, "commands": collection_commands(platform)})
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

    def _send_text(self, text, content_type="text/plain; charset=utf-8", status=200):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

    def do_POST(self):
        if self.path == "/api/audit":
            self._handle_audit()
        elif self.path == "/api/export":
            self._handle_export()
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

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
            if fmt == "html":
                self._send_text(format_html(report), "text/html; charset=utf-8")
            elif fmt == "csv":
                # CSV(BOM 포함). 브라우저 JS가 Blob으로 받아 파일 저장.
                self._send_text(format_csv(report), "text/csv; charset=utf-8")
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
