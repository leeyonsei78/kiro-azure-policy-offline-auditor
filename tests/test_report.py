"""리포트 포매터(CSV/HTML) 단위 테스트.

실행: python -m unittest -v   (프로젝트 루트에서)
"""

import csv
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor.engine import analyze
from auditor.report import format_csv, format_html, format_text, format_xlsx

_NSG = ('[{"name":"allow-ssh","access":"Allow","direction":"Inbound",'
        '"sourceAddressPrefix":"*","destinationPortRange":"22"},'
        '{"name":"deny","access":"Deny","direction":"Inbound",'
        '"sourceAddressPrefix":"*","destinationPortRange":"*"}]')


class TestCsv(unittest.TestCase):
    def test_bom_prefix(self):
        out = format_csv(analyze(_NSG))
        self.assertTrue(out.startswith("\ufeff"), "엑셀 한글용 UTF-8 BOM이 있어야 함")

    def test_columns_and_rows(self):
        report = analyze(_NSG)
        out = format_csv(report)
        # BOM 제거 후 CSV 파싱
        rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
        # 요약 2줄 + 빈줄 + 헤더 + 데이터(1건: deny는 제외되므로 1건)
        header_idx = next(i for i, r in enumerate(rows) if r and r[0] == "플랫폼")
        header = rows[header_idx]
        self.assertIn("통제항목", header)
        self.assertIn("심각도", header)
        self.assertIn("개선방안", header)
        data = [r for r in rows[header_idx + 1:] if r]
        self.assertEqual(len(data), len(report.findings))
        self.assertEqual(len(data), 1)  # deny 규칙 제외 → 1건

    def test_empty_report_csv(self):
        out = format_csv(analyze(""))
        self.assertTrue(out.startswith("\ufeff"))
        self.assertIn("통제항목", out)  # 헤더는 항상 존재


class TestHtml(unittest.TestCase):
    def test_selfcontained_and_printable(self):
        html = format_html(analyze(_NSG))
        self.assertTrue(html.startswith("<!DOCTYPE html"))
        self.assertIn("window.print()", html)      # 인쇄 버튼
        self.assertIn("@media print", html)          # 인쇄 스타일
        self.assertNotIn("http://", html.split("<body")[0])  # 외부 CDN 링크 없음(head)

    def test_contains_finding_and_score(self):
        report = analyze(_NSG)
        html = format_html(report)
        self.assertIn("allow-ssh", html)             # 이슈 제목
        self.assertIn(str(report.score()), html)     # 점수
        self.assertIn("CRITICAL", html)

    def test_html_escaping(self):
        # 특수문자가 이스케이프되는지(태그 주입 방지)
        html = format_html(analyze('[{"name":"<script>x","access":"Allow",'
                                   '"direction":"Inbound","sourceAddressPrefix":"*",'
                                   '"destinationPortRange":"22"}]'))
        self.assertNotIn("<script>x", html)
        self.assertIn("&lt;script&gt;x", html)


class TestTextStillWorks(unittest.TestCase):
    def test_text_report(self):
        out = format_text(analyze(_NSG))
        self.assertIn("ISMS-P", out)
        self.assertIn("점수", out)


_AWS_SG = ('[{"GroupId":"sg-1","IpPermissions":[{"IpProtocol":"tcp","FromPort":22,'
           '"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]}]')
_MIXED = _AWS_SG + "\n" + _NSG


class TestPlatformInReports(unittest.TestCase):
    def test_csv_has_platform_column(self):
        out = format_csv(analyze(_MIXED))
        rows = list(csv.reader(io.StringIO(out.lstrip("\ufeff"))))
        header = next(r for r in rows if r and r[0] == "플랫폼")
        self.assertEqual(header[0], "플랫폼")
        # 데이터 행에 AWS/Azure 라벨이 등장
        body = "\n".join(",".join(r) for r in rows)
        self.assertIn("AWS", body)
        self.assertIn("Azure", body)

    def test_text_shows_platform_labels(self):
        out = format_text(analyze(_MIXED))
        self.assertIn("[AWS]", out)
        self.assertIn("[Azure]", out)
        self.assertIn("플랫폼별:", out)

    def test_html_platform_badges(self):
        html = format_html(analyze(_MIXED))
        self.assertIn(">AWS<", html)
        self.assertIn(">Azure<", html)
        self.assertIn("class='plat'", html)


class TestXlsx(unittest.TestCase):
    def test_valid_zip_and_sheets(self):
        import io
        import zipfile
        data = format_xlsx(analyze(_MIXED))
        self.assertEqual(data[:2], b"PK")  # zip 시그니처
        zf = zipfile.ZipFile(io.BytesIO(data))
        self.assertIsNone(zf.testzip())  # 손상 없음
        names = zf.namelist()
        self.assertIn("[Content_Types].xml", names)
        self.assertIn("xl/workbook.xml", names)
        # 워크시트 3개(요약/상세/통계) — _rels 제외
        sheets = [n for n in names
                  if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
        self.assertEqual(len(sheets), 3)
        # 발표용 차트 포함
        self.assertIn("xl/charts/chart1.xml", names)

    def test_all_xml_parseable(self):
        import io
        import xml.dom.minidom as minidom
        import zipfile
        zf = zipfile.ZipFile(io.BytesIO(format_xlsx(analyze(_MIXED))))
        for n in zf.namelist():
            if n.endswith(".xml") or n.endswith(".rels"):
                minidom.parseString(zf.read(n))  # 파싱 실패 시 예외

    def test_data_preserved_with_special_chars(self):
        import io
        import zipfile
        # 줄바꿈·따옴표·쉼표가 섞인 SQL 위반(CSV 손실 유발 케이스)
        r = analyze('{"name":"proddb","state":"Disabled","transparentDataEncryption":true}')
        zf = zipfile.ZipFile(io.BytesIO(format_xlsx(r)))
        detail = zf.read("xl/worksheets/sheet2.xml").decode("utf-8")
        # 위반 예시(따옴표 포함) 값이 셀에 보존됨
        self.assertIn("Disabled", detail)
        self.assertIn("inlineStr", detail)  # 인라인 문자열 방식

    def test_empty_report_xlsx(self):
        import io
        import zipfile
        data = format_xlsx(analyze(""))
        zf = zipfile.ZipFile(io.BytesIO(data))
        self.assertIsNone(zf.testzip())  # 이슈 없어도 유효한 xlsx


if __name__ == "__main__":
    unittest.main(verbosity=2)
