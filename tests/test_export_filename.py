"""다운로드 파일명 생성(_export_filename) 테스트.

업로드한 파일을 검토한 뒤 엑셀/CSV로 저장할 때, 다운로드 파일명에
업로드한 파일명이 포함돼야 한다. 브라우저의 <a download> 지원 여부와
무관하게 서버가 Content-Disposition으로 파일명을 확정하므로, 그 파일명
생성 규칙을 여기서 검증한다.
"""

import re
import unittest

from auditor.webui import _export_filename


class ExportFilenameTest(unittest.TestCase):
    STAMP = r"\d{8}_\d{4}"

    def test_uploaded_name_included(self):
        name = _export_filename("Ho-prod01.txt", "xlsx")
        self.assertTrue(
            re.fullmatch(rf"audit_Ho-prod01_{self.STAMP}\.xlsx", name),
            f"예상 형식과 다름: {name}",
        )

    def test_extension_stripped(self):
        # 원본 확장자(.txt)는 제거되고 저장 확장자(.csv)만 남아야 한다.
        name = _export_filename("policy.txt", "csv")
        self.assertNotIn(".txt", name)
        self.assertTrue(name.endswith(".csv"))
        self.assertIn("audit_policy_", name)

    def test_no_upload_fallback(self):
        name = _export_filename("", "xlsx")
        self.assertTrue(
            re.fullmatch(rf"azure-audit_{self.STAMP}\.xlsx", name),
            f"업로드 없을 때 기본 형식과 다름: {name}",
        )

    def test_forbidden_chars_sanitized(self):
        name = _export_filename('a/b:c*d.txt', "xlsx")
        # 파일명 금지문자(\ / : * ? " < > |)는 남아있으면 안 된다.
        for ch in '\\/:*?"<>|':
            self.assertNotIn(ch, name)

    def test_korean_name_preserved(self):
        # 한글 파일명은 그대로 유지(서버가 RFC5987로 인코딩해 전송).
        name = _export_filename("서버운영.txt", "xlsx")
        self.assertIn("서버운영", name)
        self.assertTrue(name.endswith(".xlsx"))


if __name__ == "__main__":
    unittest.main()
