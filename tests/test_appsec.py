"""애플리케이션 보안 점검(간이 SAST + WAF) 단위 테스트 (표준 unittest만 사용).

실행: python -m unittest -v   (프로젝트 루트에서)
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor import appsec
from auditor.appsec import _SAST_RULES, _KISA_TYPES
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
        # control_code 에 KISA 유형코드가 붙는다(예: "APP·K2")
        self.assertTrue(finding.control_code.startswith("APP"))
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
        r = appsec.run('password = "abc123"\neval(x)', filename="app.py", mode="sast")
        self.assertTrue(r["ok"])
        self.assertEqual(r["mode"], "sast")
        self.assertGreaterEqual(r["total"], 2)
        types = {f["issue_type"] for f in r["findings"]}
        self.assertIn("sast_hardcoded_secret", types)
        self.assertIn("sast_dangerous_eval", types)
        self.assertIn("HIGH", r["severity_counts"])
        self.assertTrue(r["notes"])
        self.assertIn("lang", r)

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

    def test_run_returns_lang(self):
        r = appsec.run('os.chmod(p, 0o777)', filename="a.py", mode="sast")
        self.assertEqual(r["lang"], "python")


class TestPythonRules(unittest.TestCase):
    """확장된 파이썬 취약점 규칙."""

    def test_insecure_file_perms(self):
        f = appsec.scan_source("os.chmod(path, 0o777)", "a.py", lang="python")
        self.assertIn("sast_insecure_file_perms", _types(f))

    def test_path_traversal(self):
        f = appsec.scan_source('open(os.path.join(base, request.args["n"]))', "a.py", lang="python")
        self.assertIn("sast_path_traversal", _types(f))

    def test_xxe_risk(self):
        f = appsec.scan_source("import xml.etree.ElementTree as ET", "a.py", lang="python")
        self.assertIn("sast_xxe_risk", _types(f))

    def test_assert_for_security(self):
        f = appsec.scan_source("assert user.is_admin, 'forbidden'", "a.py", lang="python")
        self.assertIn("sast_assert_for_security", _types(f))

    def test_insecure_tempfile(self):
        f = appsec.scan_source("path = tempfile.mktemp()", "a.py", lang="python")
        self.assertIn("sast_insecure_tempfile", _types(f))

    def test_bind_all_interfaces(self):
        f = appsec.scan_source('app.run(host="0.0.0.0")', "a.py", lang="python")
        self.assertIn("sast_flask_ssl_none", _types(f))


class TestCommonRules(unittest.TestCase):
    def test_hardcoded_ip(self):
        f = appsec.scan_source('DB_HOST = "192.168.10.25"', "a.py", lang="python")
        self.assertIn("sast_private_ip_hardcoded", _types(f))

    def test_version_string_not_flagged_as_ip(self):
        # 1.2.3.4 같은 버전 문자열/자리표시자는 IP로 잡지 않음(오탐 완화)
        f = appsec.scan_source('version = "1.2.3.4"', "a.py", lang="python")
        self.assertNotIn("sast_private_ip_hardcoded", _types(f))

    def test_loopback_not_flagged(self):
        f = appsec.scan_source('host = "127.0.0.1"', "a.py", lang="python")
        self.assertNotIn("sast_private_ip_hardcoded", _types(f))

    def test_invalid_octet_not_flagged(self):
        # 999.1.1.1 은 유효 IP가 아니므로 제외
        f = appsec.scan_source('x = "999.1.1.1"', "a.py", lang="python")
        self.assertNotIn("sast_private_ip_hardcoded", _types(f))

    def test_weak_crypto_des(self):
        f = appsec.scan_source("cipher = DES.new(key)", "a.py", lang="python")
        self.assertIn("sast_weak_crypto", _types(f))


class TestSqlRules(unittest.TestCase):
    def test_grant_all(self):
        f = appsec.scan_source("GRANT ALL PRIVILEGES ON db.* TO 'app'@'x';", "s.sql", lang="sql")
        self.assertIn("sast_sql_grant_all", _types(f))

    def test_public_grant(self):
        f = appsec.scan_source("CREATE USER 'a'@'%' IDENTIFIED BY 'plainpw';", "s.sql", lang="sql")
        self.assertIn("sast_sql_public_grant", _types(f))

    def test_xp_cmdshell_critical(self):
        f = appsec.scan_source("EXEC xp_cmdshell 'whoami';", "s.sql", lang="sql")
        self.assertIn("sast_sql_xp_cmdshell", _types(f))
        finding = [x for x in f if x.issue_type == "sast_sql_xp_cmdshell"][0]
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_plaintext_password(self):
        f = appsec.scan_source("WHERE password = 'user_input'", "s.sql", lang="sql")
        self.assertIn("sast_sql_plaintext_password", _types(f))


class TestHtmlRules(unittest.TestCase):
    def test_xss_innerhtml(self):
        f = appsec.scan_source("el.innerHTML = userInput;", "x.html", lang="html")
        self.assertIn("sast_xss_innerhtml", _types(f))

    def test_js_url_scheme(self):
        f = appsec.scan_source('<a href="javascript:doIt()">x</a>', "x.html", lang="html")
        self.assertIn("sast_js_url_scheme", _types(f))

    def test_target_blank_noopener(self):
        f = appsec.scan_source('<a href="https://x.com" target="_blank">y</a>', "x.html", lang="html")
        self.assertIn("sast_target_blank_noopener", _types(f))

    def test_target_blank_with_noopener_ok(self):
        f = appsec.scan_source('<a href="https://x.com" target="_blank" rel="noopener">y</a>',
                               "x.html", lang="html")
        self.assertNotIn("sast_target_blank_noopener", _types(f))

    def test_inline_event_handler(self):
        f = appsec.scan_source('<img src=x onerror="fetch(\'/x\')">', "x.html", lang="html")
        self.assertIn("sast_inline_event_handler", _types(f))


class TestLanguageDetection(unittest.TestCase):
    def test_detect_by_extension(self):
        self.assertEqual(appsec.detect_language("a.py", ""), "python")
        self.assertEqual(appsec.detect_language("a.js", ""), "js")
        self.assertEqual(appsec.detect_language("a.html", ""), "html")
        self.assertEqual(appsec.detect_language("a.sql", ""), "sql")

    def test_detect_by_content(self):
        self.assertEqual(appsec.detect_language("", "<html><body>hi</body></html>"), "html")
        self.assertEqual(appsec.detect_language("", "SELECT * FROM users WHERE id=1"), "sql")
        self.assertEqual(appsec.detect_language("", "def foo():\n    print('hi')"), "python")

    def test_detect_unknown(self):
        self.assertEqual(appsec.detect_language("", "some plain text 123"), "unknown")

    def test_language_filtering(self):
        # SQL 규칙(grant_all)은 python으로 지정하면 적용되지 않아야 함
        sql_line = "GRANT ALL PRIVILEGES ON db.* TO 'a'@'x';"
        py = appsec.scan_source(sql_line, "a.py", lang="python")
        self.assertNotIn("sast_sql_grant_all", _types(py))
        # sql로 지정하면 적용됨
        s = appsec.scan_source(sql_line, "s.sql", lang="sql")
        self.assertIn("sast_sql_grant_all", _types(s))

    def test_lang_all_applies_everything(self):
        # lang="all"이면 언어 무관하게 SQL 규칙도 적용
        f = appsec.scan_source("GRANT ALL PRIVILEGES ON db.* TO 'a'@'x';", "a.py", lang="all")
        self.assertIn("sast_sql_grant_all", _types(f))

    def test_unknown_applies_everything(self):
        # 언어 미상이면 모든 규칙 적용(넓게 점검)
        f = appsec.scan_source("GRANT ALL PRIVILEGES ON db.* TO 'a'@'x';", "", lang="auto")
        self.assertIn("sast_sql_grant_all", _types(f))


class TestNewWeaknessRules(unittest.TestCase):
    """KISA 보강으로 추가된 누락 약점 규칙."""

    def test_sensitive_info_logging(self):
        f = appsec.scan_source('logger.info("login pw=" + password)', "a.py", lang="python")
        self.assertIn("sast_sensitive_info_logging", _types(f))

    def test_broad_except_pass(self):
        f = appsec.scan_source("try:\n    verify(t)\nexcept:\n    pass", "a.py", lang="python")
        self.assertIn("sast_broad_except_pass", _types(f))

    def test_ssrf_risk(self):
        f = appsec.scan_source('requests.get(request.args["url"])', "a.py", lang="python")
        self.assertIn("sast_ssrf_risk", _types(f))

    def test_open_redirect(self):
        f = appsec.scan_source('return redirect(request.args["next"])', "a.py", lang="python")
        self.assertIn("sast_open_redirect", _types(f))

    def test_debug_code_leftover(self):
        f = appsec.scan_source("console.log('token=', token);", "x.html", lang="html")
        self.assertIn("sast_debug_code_leftover", _types(f))


class TestKisaMapping(unittest.TestCase):
    """KISA 시큐어코딩 매핑 검증."""

    def test_every_rule_has_kisa(self):
        # 모든 SAST 규칙에 KISA 매핑이 있어야 함
        missing = [r["id"] for r in _SAST_RULES if not r.get("kisa")]
        self.assertEqual(missing, [], f"KISA 매핑 누락: {missing}")

    def test_kisa_codes_valid(self):
        # kisa 코드가 정의된 7대 유형(K1~K7) 안에 있어야 함
        for r in _SAST_RULES:
            code = r["kisa"][0]
            self.assertIn(code, _KISA_TYPES, f"{r['id']} 의 KISA 코드 {code} 미정의")

    def test_kisa_type_name_helper(self):
        self.assertEqual(appsec.kisa_type_name("K1"), "입력데이터 검증 및 표현")
        self.assertEqual(appsec.kisa_type_name("K7"), "API 오용")
        self.assertEqual(appsec.kisa_type_name("K99"), "")

    def test_finding_control_code_has_kisa(self):
        f = appsec.scan_source('password = "abc123"', "a.py", lang="python")
        self.assertTrue(f[0].control_code.startswith("APP·K"))

    def test_finding_description_has_kisa_prefix(self):
        f = appsec.scan_source('password = "abc123"', "a.py", lang="python")
        self.assertTrue(f[0].description.startswith("[KISA"))

    def test_run_kisa_summary(self):
        text = 'password = "abc123"\neval(x)\nrequests.get(request.args["u"])'
        r = appsec.run(text, "a.py", mode="sast")
        self.assertIn("kisa_summary", r)
        summary = {k["code"]: k["count"] for k in r["kisa_summary"]}
        # K2(하드코딩), K7(eval), K1(SSRF) 최소 포함
        self.assertIn("K2", summary)
        self.assertIn("K7", summary)
        self.assertIn("K1", summary)
        # 각 항목에 type 명칭이 채워져 있어야 함
        for k in r["kisa_summary"]:
            self.assertTrue(k["type"])

    def test_waf_findings_have_no_kisa_summary_entries(self):
        # WAF 점검 결과는 APP·Kn 형식이 아니므로 kisa_summary가 비어야 함
        r = appsec.run("{}", mode="waf", platform="aws")
        self.assertEqual(r["kisa_summary"], [])


if __name__ == "__main__":
    unittest.main()
