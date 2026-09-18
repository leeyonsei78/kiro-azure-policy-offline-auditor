"""신규 웹 UI 기능(사고대응 IR / 앱 보안) 엔드포인트·화면 요소 테스트.

인프로세스로 ThreadingHTTPServer를 띄워 실제 HTTP 요청/응답을 검증한다.
표준 라이브러리(http.server, http.client, json, threading)만 사용.
"""

import json
import os
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor.webui import INDEX_HTML, Handler


class TestWebUiMarkup(unittest.TestCase):
    """새 탭·패널·JS 함수가 화면 문자열에 포함되는지 확인."""

    def test_tabs_present(self):
        for needle in ("tab-ir", "tab-appsec", "사고 대응 가이드", "앱 보안 점검"):
            self.assertIn(needle, INDEX_HTML, f"'{needle}' 누락")

    def test_panes_present(self):
        for needle in ("pane-ir", "pane-appsec", 'id="ir-type"', 'id="as-input"'):
            self.assertIn(needle, INDEX_HTML, f"'{needle}' 누락")

    def test_js_functions_present(self):
        for needle in ("function runIr", "function renderIr", "function runAppsec",
                       "function renderAppsec", "loadIrTypes", "/api/ir_types"):
            self.assertIn(needle, INDEX_HTML, f"'{needle}' 누락")

    def test_appsec_language_selector_present(self):
        # 언어 선택 드롭다운과 옵션들이 화면에 있어야 함
        for needle in ('id="as-lang"', 'value="python"', 'value="html"',
                       'value="sql"', 'value="all"', "자동 감지"):
            self.assertIn(needle, INDEX_HTML, f"'{needle}' 누락")


class TestWebUiEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def _get(self, path):
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def _post(self, path, obj):
        import urllib.request
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(obj).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def test_ir_types(self):
        status, d = self._get("/api/ir_types")
        self.assertEqual(status, 200)
        self.assertEqual(len(d["types"]), 6)

    def test_ir_playbook(self):
        status, d = self._post("/api/ir", {"type": "ransomware", "platform": "azure"})
        self.assertEqual(status, 200)
        self.assertTrue(d["ok"])
        self.assertEqual(d["playbook"]["platform"], "azure")
        self.assertEqual(len(d["playbook"]["steps"]), 6)

    def test_ir_unknown_type(self):
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post("/api/ir", {"type": "nope"})
        self.assertEqual(ctx.exception.code, 400)

    def test_appsec_sast(self):
        src = 'password = "abc123"\nos.system("rm " + x)\n'
        status, d = self._post("/api/appsec", {"text": src, "mode": "sast"})
        self.assertEqual(status, 200)
        self.assertTrue(d["ok"])
        self.assertEqual(d["total"], 2)

    def test_appsec_waf(self):
        status, d = self._post("/api/appsec", {"text": "{}", "mode": "waf", "platform": "azure"})
        self.assertEqual(status, 200)
        self.assertEqual([f["issue_type"] for f in d["findings"]], ["waf_not_found"])

    def test_appsec_lang_explicit(self):
        # 명시적 lang=sql 전달 시 SQL 규칙 적용 + lang 반환
        status, d = self._post("/api/appsec", {
            "text": "GRANT ALL PRIVILEGES ON db.* TO 'a'@'x';",
            "mode": "sast", "lang": "sql"})
        self.assertEqual(status, 200)
        self.assertEqual(d["lang"], "sql")
        self.assertIn("sast_sql_grant_all", {f["issue_type"] for f in d["findings"]})

    def test_appsec_lang_auto_by_filename(self):
        # 파일명 확장자로 언어 자동 감지(HTML)
        status, d = self._post("/api/appsec", {
            "text": '<a href="https://x.com" target="_blank">y</a>',
            "mode": "sast", "lang": "auto", "filename": "index.html"})
        self.assertEqual(status, 200)
        self.assertEqual(d["lang"], "html")
        self.assertIn("sast_target_blank_noopener", {f["issue_type"] for f in d["findings"]})


if __name__ == "__main__":
    unittest.main()
