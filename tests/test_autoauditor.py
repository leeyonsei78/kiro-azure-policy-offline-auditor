"""자동 점검 에이전트(autoauditor) 테스트.

수집→분석→침해탐지→대응계획→알림→리포트 파이프라인과 각 모듈의 안전장치를 검증한다.
표준 라이브러리만 사용하고, 실제 클라우드/Slack에 접속하지 않는다(mock).
"""

import json
import os
import tempfile
import unittest

from autoauditor import collector, threat, notifier, remediation
from autoauditor.config import (
    Config, REMEDIATION_OFF, REMEDIATION_SUGGEST, REMEDIATION_AUTO,
)
from autoauditor.orchestrator import run_once
from auditor.engine import analyze


class ConfigTest(unittest.TestCase):
    def test_defaults_safe(self):
        c = Config()
        self.assertEqual(c.remediation, REMEDIATION_SUGGEST)  # 기본 반자동
        self.assertTrue(c.dry_run)                            # 기본 실제변경 안 함
        self.assertFalse(c.use_mock)

    def test_redacted_hides_webhook(self):
        c = Config(slack_webhook="https://hooks.slack.com/secret")
        self.assertEqual(c.redacted()["slack_webhook"], "설정됨")
        self.assertNotIn("secret", json.dumps(c.redacted()))

    def test_from_env(self):
        os.environ["AUTOAUDITOR_PLATFORM"] = "azure"
        os.environ["AUTOAUDITOR_REMEDIATION"] = "auto"
        try:
            c = Config.from_env()
            self.assertEqual(c.platform, "azure")
            self.assertEqual(c.remediation, "auto")
        finally:
            del os.environ["AUTOAUDITOR_PLATFORM"]
            del os.environ["AUTOAUDITOR_REMEDIATION"]


class CollectorTest(unittest.TestCase):
    def test_mock_returns_text(self):
        for plat in ("aws", "azure"):
            r = collector.collect(plat, use_mock=True)
            self.assertEqual(r["source"], "mock")
            self.assertTrue(r["text"])

    def test_mock_analyzable(self):
        # 목업 데이터가 엔진에 의해 실제 이슈로 탐지되는지
        r = collector.collect("aws", use_mock=True)
        d = analyze(r["text"]).to_dict()
        self.assertGreater(d["total_findings"], 0)


class ThreatTest(unittest.TestCase):
    def test_guardduty(self):
        txt = '[{"Type":"UnauthorizedAccess:EC2/SSHBruteForce","Severity":8}]'
        ev = threat.detect(txt, platform="aws")
        self.assertTrue(any(e.threat_type == "guardduty_finding" for e in ev))

    def test_brute_force(self):
        txt = "\n".join(["ConsoleLogin failed from 198.51.100.9"] * 6)
        ev = threat.detect(txt, platform="aws", login_fail_threshold=5)
        bf = [e for e in ev if e.threat_type == "brute_force"]
        self.assertTrue(bf)
        self.assertEqual(bf[0].source_ip, "198.51.100.9")

    def test_brute_force_below_threshold(self):
        txt = "\n".join(["login failed from 1.2.3.4"] * 2)
        ev = threat.detect(txt, platform="aws", login_fail_threshold=5)
        self.assertFalse([e for e in ev if e.threat_type == "brute_force"])

    def test_root_activity(self):
        ev = threat.detect("root console login arn:aws:iam::111:root", platform="aws")
        self.assertTrue(any(e.threat_type == "root_activity" for e in ev))

    def test_summarize(self):
        ev = threat.detect('[{"Type":"Recon:EC2/PortProbeUnprotectedPort","Severity":5}]', platform="aws")
        s = threat.summarize(ev)
        self.assertIn("total", s)
        self.assertIn("block_candidate_ips", s)


class NotifierTest(unittest.TestCase):
    def test_no_message_when_below_threshold(self):
        cfg = Config(alert_min_severity="CRITICAL")
        rd = {"findings": [{"severity": "LOW", "issue_type": "x"}], "correlations": [],
              "severity_counts": {"LOW": 1}, "score": 97, "grade": "A"}
        self.assertIsNone(notifier.build_message(rd, [], cfg))

    def test_message_built_for_high(self):
        cfg = Config(alert_min_severity="HIGH")
        rd = {"findings": [{"severity": "HIGH", "issue_type": "x", "title": "t"}],
              "correlations": [], "severity_counts": {"HIGH": 1}, "score": 55, "grade": "F",
              "top_risks": [{"risk_score": 60, "severity": "HIGH", "title": "t"}]}
        msg = notifier.build_message(rd, [], cfg)
        self.assertIsNotNone(msg)
        self.assertIn("자동점검", msg["text"])

    def test_send_no_webhook_skips(self):
        r = notifier.send("", {"text": "x"})
        self.assertTrue(r["skipped"])


class RemediationTest(unittest.TestCase):
    def _rd(self):
        return analyze(collector.collect("aws", use_mock=True)["text"]).to_dict()

    def test_off_mode_empty(self):
        cfg = Config(remediation=REMEDIATION_OFF)
        self.assertEqual(remediation.plan(self._rd(), [], cfg), [])

    def test_suggest_generates_but_not_executes(self):
        cfg = Config(remediation=REMEDIATION_SUGGEST)
        acts = remediation.plan(self._rd(), [], cfg)
        self.assertTrue(acts)
        self.assertTrue(all(a["status"] == "suggested" for a in acts))

    def test_protect_whitelist(self):
        cfg = Config(remediation=REMEDIATION_AUTO, dry_run=True, protect_tags=["prod-db"])
        acts = remediation.plan(self._rd(), [], cfg)
        prot = [a for a in acts if "prod-db" in a["target"]]
        self.assertTrue(prot)
        self.assertTrue(all(a["status"] == "skipped_protected" for a in prot))

    def test_auto_dryrun_does_not_execute(self):
        cfg = Config(remediation=REMEDIATION_AUTO, dry_run=True)
        acts = remediation.plan(self._rd(), [], cfg)
        # dry_run이면 실제 실행(executed) 없이 dry_run 또는 skipped 상태
        self.assertFalse(any(a["status"] == "executed" for a in acts))

    def test_threat_ip_block_command(self):
        cfg = Config(remediation=REMEDIATION_SUGGEST)
        ev = threat.detect("\n".join(["login failed from 203.0.113.9"] * 6),
                           platform="aws", login_fail_threshold=5)
        acts = remediation.plan({"findings": []}, ev, cfg)
        self.assertTrue(any("203.0.113.9" in a["target"] for a in acts))


class OrchestratorTest(unittest.TestCase):
    def test_run_once_full_pipeline(self):
        tmp = tempfile.mkdtemp()
        cfg = Config(platform="aws", use_mock=True, output_dir=tmp,
                     remediation=REMEDIATION_SUGGEST, alert_min_severity="HIGH")
        threat_log = "\n".join(["ConsoleLogin failed from 198.51.100.9"] * 6)
        res = run_once(cfg, threat_text=threat_log)
        self.assertTrue(res["ok"])
        self.assertGreater(res["findings"], 0)
        self.assertGreaterEqual(res["threats"]["total"], 1)
        self.assertGreater(res["remediations_planned"], 0)
        # 리포트 4종 저장 확인
        files = os.listdir(tmp)
        self.assertTrue(any(f.endswith(".txt") for f in files))
        self.assertTrue(any(f.endswith(".html") for f in files))
        self.assertTrue(any(f.endswith(".xlsx") for f in files))
        self.assertTrue(any(f.endswith(".json") for f in files))

    def test_run_once_with_provided_config(self):
        tmp = tempfile.mkdtemp()
        cfg = Config(platform="aws", output_dir=tmp)
        text = collector.mock_data("aws")
        res = run_once(cfg, config_text=text)
        self.assertEqual(res["collect_source"], "provided")
        self.assertGreater(res["findings"], 0)


if __name__ == "__main__":
    unittest.main()
