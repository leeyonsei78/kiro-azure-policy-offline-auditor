"""로컬 웹 업로드 UI (폐쇄망 전용, 표준 라이브러리 http.server만 사용).

실행:
  python -m auditor.webui                 # http://127.0.0.1:8080
  python -m auditor.webui --port 9000 --host 0.0.0.0

엔드포인트:
  GET  /            -> 업로드/붙여넣기 UI (단일 HTML, 외부 CDN 없음)
  GET  /api/controls -> ISMS-P 통제항목 목록(참고용)
  POST /api/audit   -> {"text": "<az 출력 텍스트>"} → 검토 결과 JSON

외부 네트워크·AI·AWS 연결 없음. 입력 텍스트는 메모리에서만 처리하고 저장하지 않는다.
"""

from __future__ import annotations

import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import analyze
from .knowledge_base import all_controls

logger = logging.getLogger(__name__)

# 업로드 크기 상한(폐쇄망 로컬이지만 방어적으로): 8MB
_MAX_BODY = 8 * 1024 * 1024


INDEX_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Azure 정책 오프라인 보안검토 (ISMS-P)</title>
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
  .ftitle{ font-weight:600; }
  .meta{ color:var(--muted); font-size:13px; margin-top:6px; line-height:1.5; }
  .meta b{ color:var(--text); }
  .fix{ margin-top:6px; padding:8px 10px; background:#10233a; border-radius:8px; border:1px solid var(--border); font-size:13px; }
  pre{ white-space:pre-wrap; word-break:break-all; background:#0b1220; border:1px solid var(--border);
    border-radius:6px; padding:6px 8px; font-size:11px; color:var(--muted); margin:6px 0 0; }
  .empty{ color:var(--muted); }
  .banner{ background:#10233a; border:1px solid var(--border); border-radius:8px; padding:10px 12px; font-size:12px; color:var(--muted); }
  .err{ color:var(--crit); margin-top:8px; white-space:pre-wrap; }
</style>
</head>
<body>
<header>
  <h1>🛡️ Azure 정책 오프라인 보안검토 <span class="sub">(ISMS-P 클라우드 인프라 기준)</span></h1>
  <div class="sub">Azure CLI(<code>az ...</code>)로 추출한 정책·구성 텍스트를 붙여넣거나 업로드하면, <b>인터넷·AI 없이</b> 이슈를 찾고 개선안을 제안합니다.</div>
</header>
<main>
  <div class="card">
    <div class="banner">🔒 폐쇄망 전용 · 외부 전송 없음 · 입력은 서버 메모리에서만 처리되고 저장되지 않습니다.
      <br>입력 예: <code>az network nsg rule list ... -o json</code>, <code>az storage account show ...</code>, <code>az role assignment list ...</code> 등의 출력(여러 명령 출력을 이어붙여도 됨).</div>
    <label>Azure 정책/구성 텍스트 (붙여넣기)</label>
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
      </div>
    </div>
    <div id="findings"></div>
    <div class="hint" style="margin-top:14px">※ 오프라인 규칙 기반 자동 검토 결과이며 참고용입니다. 실제 조치 전 대상 환경과 업무 요건을 확인하세요. KISA 공식 심사자료를 대체하지 않습니다.</div>
  </div>
</main>
<script>
function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
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
function render(r){
  document.getElementById('result-card').style.display='block';
  var sc=document.getElementById('score'); sc.textContent=r.score; sc.className='score grade-'+r.grade;
  document.getElementById('grade-line').textContent='등급 '+r.grade+'  /  100점';
  var c=r.severity_counts||{};
  var order=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  document.getElementById('counts').innerHTML=order.filter(k=>c[k]).map(k=>'<span><b>'+k+'</b> '+c[k]+'</span>').join('') || '<span class="empty">이슈 없음</span>';
  document.getElementById('meta').textContent='입력형식: '+r.input_kind+' · 파싱 리소스: '+r.parsed_resources+'개 · 발견 이슈: '+r.total_findings+'건';

  var host=document.getElementById('findings');
  if(!r.findings || !r.findings.length){
    host.innerHTML='<div class="sec">결과</div><div class="finding empty">'+esc((r.notes&&r.notes[0])||'탐지된 이슈가 없습니다.')+'</div>';
    return;
  }
  // 통제항목별 그룹
  var groups={};
  r.findings.forEach(function(f){ (groups[f.control_code]=groups[f.control_code]||[]).push(f); });
  var codes=Object.keys(groups).sort(function(a,b){ return a.split('.').map(Number) > b.split('.').map(Number) ? 1 : -1; });
  var html='';
  codes.forEach(function(code){
    var fs=groups[code];
    html+='<div class="sec">['+esc(code)+'] '+esc(fs[0].control_domain||'')+' — '+fs.length+'건</div>';
    fs.forEach(function(f){
      html+='<div class="finding"><div class="ftop">'+
        '<span class="sev '+esc(f.severity)+'">'+esc(f.severity)+'</span>'+
        '<span class="code">'+esc(f.control_code)+'</span>'+
        '<span class="ftitle">'+esc(f.title)+'</span></div>';
      if(f.resource) html+='<div class="meta"><b>대상:</b> '+esc(f.resource)+'</div>';
      html+='<div class="meta"><b>문제:</b> '+esc(f.description)+'</div>';
      html+='<div class="fix"><b>✅ 개선 제안:</b> '+esc(f.recommendation)+'</div>';
      if(f.evidence) html+='<pre>'+esc(f.evidence)+'</pre>';
      html+='</div>';
    });
  });
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
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send_html(INDEX_HTML)
        elif self.path == "/api/controls":
            self._send_json({"controls": all_controls()})
        else:
            self._send_json({"ok": False, "error": "not found"}, status=404)

    def do_POST(self):
        if self.path != "/api/audit":
            self._send_json({"ok": False, "error": "not found"}, status=404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > _MAX_BODY:
                self._send_json({"ok": False, "error": "입력이 너무 큽니다(최대 8MB)."}, status=413)
                return
            raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            try:
                payload = json.loads(raw) if raw else {}
            except ValueError:
                payload = {"text": raw}
            text = payload.get("text", "") if isinstance(payload, dict) else ""
            report = analyze(text)
            self._send_json({"ok": True, "report": report.to_dict()})
        except Exception as e:  # noqa: BLE001 - UI에 오류 전달
            logger.exception("audit 실패")
            self._send_json({"ok": False, "error": str(e)}, status=500)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Azure 정책 오프라인 보안검토 - 로컬 웹 UI")
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
