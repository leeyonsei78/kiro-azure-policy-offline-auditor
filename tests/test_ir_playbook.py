"""사고 대응(IR) 플레이북 생성기 단위 테스트 (표준 unittest만 사용).

실행: python -m unittest -v   (프로젝트 루트에서)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor import ir_playbook
from autoauditor.threat import detect


class TestIrPlaybook(unittest.TestCase):
    def test_list_incident_types(self):
        types = ir_playbook.list_incident_types()
        self.assertEqual(len(types), 6)
        keys = {t["type"] for t in types}
        self.assertIn("account_compromise", keys)
        self.assertIn("ransomware", keys)
        # 각 항목에 name/severity 존재
        for t in types:
            self.assertTrue(t["name"])
            self.assertIn(t["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

    def test_build_playbook_shape(self):
        pb = ir_playbook.build_playbook("account_compromise", "aws")
        self.assertEqual(pb["type"], "account_compromise")
        self.assertEqual(pb["platform"], "aws")
        # 6단계 골격
        self.assertEqual(len(pb["steps"]), 6)
        for step in pb["steps"]:
            self.assertIn("phase", step)
            self.assertIsInstance(step["actions"], list)
            self.assertTrue(step["actions"])
        # 필수 필드
        for key in ("summary", "isms_p", "mitre", "evidence_commands",
                    "report_template", "disclaimer"):
            self.assertIn(key, pb)
        # ISMS-P 2.11 사고대응 관련 언급
        self.assertTrue(pb["isms_p"])

    def test_platform_specific_evidence(self):
        aws = ir_playbook.build_playbook("data_exposure", "aws")
        azure = ir_playbook.build_playbook("data_exposure", "azure")
        # AWS는 aws CLI, Azure는 az CLI 명령이 들어감
        self.assertTrue(any("aws " in c for c in aws["evidence_commands"]))
        self.assertTrue(any(c.startswith("az ") for c in azure["evidence_commands"]))

    def test_invalid_platform_falls_back_to_aws(self):
        pb = ir_playbook.build_playbook("ransomware", "gcp")
        self.assertEqual(pb["platform"], "aws")

    def test_unknown_type_raises(self):
        with self.assertRaises(KeyError):
            ir_playbook.build_playbook("does_not_exist", "aws")

    def test_playbook_from_threats(self):
        # 무차별 대입(로그인 실패 급증) + 악성 지표 -> 관련 플레이북
        text = ("login failed from 10.0.0.9\n" * 6) + "detected cryptomining c2 traffic\n"
        events = detect(text, platform="aws")
        bundle = ir_playbook.playbook_from_threats(events, "aws")
        self.assertGreaterEqual(bundle["count"], 1)
        ptypes = {p["type"] for p in bundle["playbooks"]}
        # brute_force -> account_compromise, malicious_indicator -> malware_host
        self.assertTrue({"account_compromise", "malware_host"} & ptypes)
        # 심각도 정렬(첫 항목이 가장 높은 심각도)
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sev_vals = [order[p["severity"]] for p in bundle["playbooks"]]
        self.assertEqual(sev_vals, sorted(sev_vals))

    def test_playbook_from_threats_accepts_dicts(self):
        events = [{"threat_type": "root_activity"}]
        bundle = ir_playbook.playbook_from_threats(events, "aws")
        self.assertEqual(bundle["count"], 1)
        self.assertEqual(bundle["playbooks"][0]["type"], "privilege_abuse")

    def test_playbook_from_threats_dedup(self):
        events = [{"threat_type": "brute_force"}, {"threat_type": "brute_force"}]
        bundle = ir_playbook.playbook_from_threats(events, "aws")
        self.assertEqual(bundle["count"], 1)

    def test_render_text(self):
        pb = ir_playbook.build_playbook("privilege_abuse", "azure")
        txt = ir_playbook.render_text(pb)
        self.assertIn("사고 대응 플레이북", txt)
        self.assertIn("증거 수집 명령어", txt)
        self.assertIn("사고 보고서 양식", txt)
        # 6단계 phase 헤더 모두 포함
        for step in pb["steps"]:
            self.assertIn(step["phase"], txt)


if __name__ == "__main__":
    unittest.main()
