"""웹 UI에 삽입된 JavaScript의 문법 안전성 검사.

INDEX_HTML 안의 <script>는 파이썬 문자열로 작성되므로, 정규식의 백슬래시(\\n 등)를
이스케이프하지 않으면 파이썬이 실제 제어문자로 바꿔 브라우저 JS가 통째로 깨진다
(그러면 모든 버튼이 동작하지 않음). 이런 회귀를 자동으로 잡는다.

Node가 있으면 `node --check`로 실제 문법을 검증하고, 없으면 위험 패턴(스크립트 내
실제 개행이 정규식 리터럴을 깨뜨리는 경우 등)을 정적으로 점검한다.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

from auditor.webui import INDEX_HTML


def _extract_script():
    m = re.search(r"<script>(.*?)</script>", INDEX_HTML, re.S)
    return m.group(1) if m else ""


class WebUiJsTest(unittest.TestCase):
    def setUp(self):
        self.js = _extract_script()
        self.assertTrue(self.js, "<script> 블록을 찾지 못함")

    def test_no_raw_newline_in_regex_literal(self):
        # 정규식 리터럴 안에 '진짜 개행'이 들어가면 JS가 깨진다.
        # (예: replace(/\n/g,...) 에서 \n 이스케이프를 빠뜨린 경우)
        for lineno, line in enumerate(self.js.splitlines(), 1):
            # /.../ 형태 정규식 리터럴 후보에서 개행은 이미 splitlines로 분리되므로,
            # 여기서는 'replace(/' 뒤가 곧바로 줄 끝나면(리터럴 미완결) 위험으로 본다.
            for m in re.finditer(r"replace\(/", line):
                rest = line[m.end():]
                # 같은 줄에서 정규식이 닫히는지(다음 '/' 존재) 확인
                self.assertIn("/", rest,
                              f"{lineno}행: 정규식 리터럴이 한 줄에서 닫히지 않음(개행으로 깨질 위험): {line!r}")

    @unittest.skipUnless(shutil.which("node"), "node 미설치 — 정적 검사만 수행")
    def test_node_syntax_check(self):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
            f.write(self.js)
            path = f.name
        try:
            env = dict(os.environ)
            env.pop("NODE_OPTIONS", None)  # 샌드박스 preload 방지
            r = subprocess.run(["node", "--check", path],
                               capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, f"JS 문법 오류:\n{r.stderr}")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
