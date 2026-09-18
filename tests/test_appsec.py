"""애플리케이션 보안 점검(간이 SAST + WAF) 단위 테스트 (표준 unittest만 사용).

실행: python -m unittest -v   (프로젝트 루트에서)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor import appsec
from auditor.models import Severity


def _types(findings):
    return {f.issue_type for f in findings}


class TestSast(unittest.TestCase):
    def test_hardcoded_secret(self):
        f = appsec.scan_source('password = "P@ssw0rd123"')
        self.assertIn("sast_hardcoded_secret", _types(f))

    def test_sql_injection(self):
        f = appsec.scan_source('cursor.execute("SELECT * FROM u WHERE id=" + uid)')
        self.assertIn("sast_sql_injection", _types(f))

    def test_os_command_exec(self):
        f = appsec.scan_source('subprocess.run(f"ping {host}", shell=True)')
        self.assertIn("sast_os_command_exec", _types(f))

    def test_dangerous_eval(self):
        f = appsec.scan_source("result = eval(user_input)")
        self.assertIn("sast_dangerous_eval", _types(f))

    def test_weak_crypto(self):
        f = appsec.scan_source("hashlib.md5(pw.encode())")
        self.assertIn("sast_weak_crypto", _types(f))

    def test_insecure_random(self):
        f = appsec.scan_source("token = random.randint(1000, 9999)")
        self.assertIn("sast_insecure_random", _types(f))

    def test_tls_verify_disabled(self):
        f = appsec.scan_source("requests.get(url, verify=False)")
        self.assertIn("sast_tls_verify_disabled", _types(f))

    def test_debug_enabled(self):
        f = appsec.scan_source("app.run(debug=True)")
        self.assertIn("sast_debug_enabled", _types(f))

    def test_comment_lines_skipped(self):
        # 순수 주석 줄은 오탐 방지 위해 스킵
        f = appsec.scan_source('# password = "secret-in-comment"\n// api_key = "abc12345"')
        self.assertEqual(len(f), 0)

    def test_clean_code_no_findings(self):
        clean = 'import os\npassword = os.environ["DB_PASSWORD"]\nx = 1 + 2\n'
        f = appsec.scan_source(clean)
        # 환경변수 사용은 하드코딩 패턴(따옴표 리터럴)에 걸리지 않아야 함
        self.assertEqual(_types(f), set())

    def test_finding_metadata(self):
        f = appsec.scan_source('password = "abc123"', filename="app.py")
        self.assertEqual(len(f), 1)
        finding = f[0]
        self.assertEqual(finding.control_code, "APP")
        self.assertEqual(finding.platform, "appsec")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("app.py", finding.location)
        self.assertTrue(finding.recommendation)
        self.assertTrue(finding.good_example)

    def test_empty_input(self):
        self.assertEqual(appsec.scan_source(""), [])


class TestWaf(unittest.TestCase):
    def test_no_waf_hint(self):
        f = appsec.check_waf('{"some": "config"}', platform="aws")
        self.assertEqual(_types(f), {"waf_not_found"})

    def test_waf_detection_mode_not_enabled(self):
        # Detection 모드는 차단하지 않으므로 not_enabled로 잡혀야 함
        cfg = '{"webACL": {"managedRuleGroup": "OWASP", "mode": "Detection"}}'
        f = appsec.check_waf(cfg, platform="azure")
        self.assertIn("waf_not_enabled", _types(f))

    def test_waf_no_managed_rules(self):
        cfg = '{"webACL": {"mode": "Prevention"}}'
        f = appsec.check_waf(cfg, platform="azure")
        self.assertIn("waf_no_managed_rules", _types(f))

    def test_waf_ok(self):
        cfg = '{"webACL": {"managedRuleGroup": "OWASP CRS", "policySettings": {"mode": "Prevention"}}}'
        f = appsec.check_waf(cfg, platform="azure")
        self.assertEqual(_types(f), {"waf_ok"})

    def test_waf_control_code(self):
        f = appsec.check_waf('{}', platform="aws")
        self.assertEqual(f[0].control_code, "2.6.7")

    def test_empty_input(self):
        self.assertEqual(appsec.check_waf(""), [])


class TestRun(unittest.TestCase):
    def test_run_sast_mode(self):
        r = appsec.run('password = "abc123"\neval(x)', mode="sast")
        self.assertTrue(r["ok"])
        self.assertEqual(r["mode"], "sast")
        self.assertEqual(r["total"], 2)
        self.assertIn("HIGH", r["severity_counts"])
        self.assertTrue(r["notes"])

    def test_run_waf_mode(self):
        r = appsec.run('{}', mode="waf", platform="azure")
        self.assertEqual(r["mode"], "waf")
        self.assertEqual(r["total"], 1)

    def test_run_both_mode(self):
        text = 'password = "abc123"\n{"webACL": {"mode": "Detection"}}'
        r = appsec.run(text, mode="both", platform="aws")
        self.assertEqual(r["mode"], "both")
        self.assertGreaterEqual(r["total"], 2)

    def test_run_sorted_by_severity(self):
        # LOW + HIGH 섞였을 때 HIGH가 먼저
        text = 'app.run(debug=True)\npassword = "abc123"'
        r = appsec.run(text, mode="sast")
        sevs = [f["severity"] for f in r["findings"]]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.assertEqual([order[s] for s in sevs], sorted(order[s] for s in sevs))

    def test_findings_are_dicts(self):
        r = appsec.run('password = "abc123"', mode="sast")
        self.assertIsInstance(r["findings"][0], dict)
        self.assertEqual(r["findings"][0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
