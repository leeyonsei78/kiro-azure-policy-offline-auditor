"""CVE 탐지 + Azure SQL 보안 8항목 + 위반/개선 예시 단위 테스트."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor.engine import analyze
from auditor.models import Severity


def _types(r):
    return {f.issue_type for f in r.findings}


class TestCve(unittest.TestCase):
    def test_single_cve_in_text(self):
        r = analyze("Defender assessment: CVE-2024-12345 found on host web01")
        f = next(f for f in r.findings if f.issue_type == "cve_detected")
        self.assertEqual(f.control_code, "2.11.2")
        self.assertIn("CVE-2024-12345", f.evidence)

    def test_many_cves_critical(self):
        txt = "CVE-2024-0001 CVE-2024-0002 CVE-2023-9999 CVE-2022-1111 CVE-2021-2222"
        r = analyze(txt)
        f = next(f for f in r.findings if f.issue_type == "cve_detected")
        self.assertEqual(f.severity, Severity.CRITICAL)

    def test_lowercase_cve(self):
        r = analyze("vuln: cve-2024-5555 detected")
        self.assertIn("cve_detected", _types(r))

    def test_cve_in_json(self):
        r = analyze('[{"finding":"vuln","cve":"CVE-2019-0708","host":"srv"}]')
        self.assertIn("cve_detected", _types(r))

    def test_no_cve_no_finding(self):
        r = analyze('{"name":"safe","note":"no vulnerabilities"}')
        self.assertNotIn("cve_detected", _types(r))


class TestSqlChecks(unittest.TestCase):
    def test_tde_disabled(self):
        r = analyze('{"name":"db","state":"Disabled","transparentDataEncryption":true}')
        self.assertIn("sql_tde_disabled", _types(r))

    def test_cmk_not_used(self):
        r = analyze('{"name":"srv","serverKeyType":"ServiceManaged"}')
        self.assertIn("sql_cmk_not_used", _types(r))

    def test_public_access(self):
        r = analyze('{"name":"srv","publicNetworkAccess":"Enabled"}')
        self.assertIn("sql_public_access", _types(r))

    def test_firewall_open_all(self):
        r = analyze('{"name":"AllowAll","startIpAddress":"0.0.0.0","endIpAddress":"255.255.255.255"}')
        self.assertIn("sql_public_access", _types(r))

    def test_no_private_endpoint(self):
        r = analyze('{"name":"srv","publicNetworkAccess":"Enabled","privateEndpointConnections":[]}')
        self.assertIn("sql_no_private_endpoint", _types(r))

    def test_auditing_disabled(self):
        r = analyze('{"name":"srv-audit","auditPolicy":true,"state":"Disabled","retentionDays":0}')
        self.assertIn("sql_auditing_disabled", _types(r))

    def test_defender_disabled(self):
        r = analyze('{"name":"srv-atp","advancedThreatProtection":true,"state":"Disabled"}')
        self.assertIn("sql_defender_disabled", _types(r))

    def test_va_disabled(self):
        r = analyze('{"name":"srv","recurringScans":{"isEnabled":false}}')
        self.assertIn("sql_va_disabled", _types(r))

    def test_ltr_not_configured(self):
        r = analyze('{"name":"db","weeklyRetention":"PT0S","monthlyRetention":"PT0S","yearlyRetention":"PT0S"}')
        self.assertIn("sql_ltr_not_configured", _types(r))

    def test_secure_sql_clean(self):
        # 안전 설정은 아무 이슈도 안 나와야
        r = analyze('{"name":"db","state":"Enabled","transparentDataEncryption":true}')
        self.assertNotIn("sql_tde_disabled", _types(r))
        r2 = analyze('{"name":"srv","serverKeyType":"AzureKeyVault"}')
        self.assertNotIn("sql_cmk_not_used", _types(r2))


class TestExamples(unittest.TestCase):
    def test_bad_good_examples_present(self):
        r = analyze('{"name":"db","state":"Disabled","transparentDataEncryption":true}')
        f = next(f for f in r.findings if f.issue_type == "sql_tde_disabled")
        self.assertTrue(f.bad_example)
        self.assertTrue(f.good_example)
        d = f.to_dict()
        self.assertIn("bad_example", d)
        self.assertIn("good_example", d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
