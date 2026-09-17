"""수집 스크립트 생성기 + service 태깅 단위 테스트."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor.collector_script import build_script, script_filename
from auditor.knowledge_base import collection_commands


class TestServiceTag(unittest.TestCase):
    def test_every_command_has_service(self):
        for plat in ("aws", "azure"):
            for c in collection_commands(plat):
                self.assertTrue(c.get("service"), f"{plat} {c['code']} service 없음")

    def test_azure_has_sql_group(self):
        svcs = {c["service"] for c in collection_commands("azure")}
        self.assertIn("SQL Database", svcs)

    def test_aws_no_sql_database_group(self):
        # AWS는 SQL Database 세부 그룹이 없어야(RDS로 매핑)
        svcs = {c["service"] for c in collection_commands("aws")}
        self.assertNotIn("SQL Database", svcs)


class TestBashScript(unittest.TestCase):
    def test_azure_bash_structure(self):
        s = build_script("azure", "bash")
        self.assertTrue(s.startswith("#!/usr/bin/env bash"))
        self.assertIn("az login", s)          # 로그인 안내
        self.assertIn("mkdir -p", s)           # out 폴더
        self.assertIn("# 서비스 그룹:", s)      # 서비스 섹션
        self.assertIn("run ", s)               # run 헬퍼 호출
        self.assertIn("업로드", s)             # 업로드 안내
        # 서비스 섹션이 여러 개
        self.assertGreaterEqual(s.count("# 서비스 그룹:"), 5)

    def test_aws_bash_uses_aws(self):
        s = build_script("aws", "bash")
        self.assertIn("aws configure", s)
        self.assertIn('run "', s)
        # SQL Database 그룹 없음 → AWS 섹션명에 없음
        self.assertNotIn("SQL Database", s)

    def test_results_saved_as_json(self):
        s = build_script("azure", "bash")
        # run 결과 파일이 .json으로 저장됨
        self.assertIn(".json", s)


class TestPs1Script(unittest.TestCase):
    def test_ps1_structure(self):
        s = build_script("azure", "ps1")
        self.assertIn("Compress-Archive", s)   # zip 안내
        self.assertIn("New-Item", s)           # out 폴더
        self.assertIn("Run ", s)               # Run 함수 호출
        self.assertIn("az login", s)


class TestRunLocationGuidance(unittest.TestCase):
    """명령을 '어디서' 실행하는지 + 필요 권한 안내가 스크립트에 포함되는지."""

    def test_bash_header_explains_single_admin_pc(self):
        for plat in ("azure", "aws"):
            s = build_script(plat, "bash")
            self.assertIn("관리자 PC", s)          # 실행 장비 명시
            self.assertIn("원격", s)                # API 원격 수집 설명
            self.assertIn("각 장비에 개별 접속할 필요가 없습니다", s)

    def test_bash_sections_show_target_and_permission(self):
        for plat in ("azure", "aws"):
            s = build_script(plat, "bash")
            self.assertIn("실행 위치:", s)
            self.assertIn("점검 대상:", s)
            self.assertIn("필요 권한:", s)

    def test_ps1_header_explains_run_location(self):
        s = build_script("azure", "ps1")
        self.assertIn("관리자 PC", s)
        self.assertIn("필요 권한:", s)

    def test_all_service_groups_in_single_script(self):
        # 한 스크립트로 모든 서비스 그룹이 수집되는지(누락 없이)
        for plat in ("azure", "aws"):
            s = build_script(plat, "bash")
            groups = {c["service"] for c in collection_commands(plat)}
            for g in groups:
                self.assertIn(f"서비스 그룹: {g}", s, f"{plat}: {g} 섹션 누락")


class TestScriptFilename(unittest.TestCase):
    def test_filename(self):
        self.assertEqual(script_filename("azure", "bash"), "collect-azure.sh")
        self.assertEqual(script_filename("aws", "bash"), "collect-aws.sh")
        self.assertEqual(script_filename("azure", "ps1"), "collect-azure.ps1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
