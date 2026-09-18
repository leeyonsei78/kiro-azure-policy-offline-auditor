"""보안 강화 회귀 테스트 (금융권 반입 대비).

- 소스 전체에 shell=True / eval / exec / os.system / pickle 이 없어야 한다.
- 자동 차단(remediation)은 셸 메타문자가 든 명령을 실제 실행하지 않아야 한다.
- collector._run 은 파이프 명령을 셸 없이 안전하게 처리해야 한다.
- 하드코딩된 Slack Webhook/AWS 키가 소스에 없어야 한다.
"""

import glob
import os
import re
import unittest


def _source_files():
    root = os.path.join(os.path.dirname(__file__), "..")
    files = []
    for pkg in ("auditor", "autoauditor"):
        files += glob.glob(os.path.join(root, pkg, "*.py"))
    return files


class NoDangerousPatternsTest(unittest.TestCase):
    def test_no_shell_true(self):
        for f in _source_files():
            src = open(f, encoding="utf-8").read()
            self.assertNotRegex(src, r"shell\s*=\s*True",
                                f"{os.path.basename(f)} 에 shell=True 존재")

    def test_no_eval_exec_system_pickle(self):
        # 실제 호출 형태만 탐지(주석/문자열 설명은 정규식 경계로 최소화)
        patterns = [r"\beval\s*\(", r"\bexec\s*\(", r"os\.system\s*\(",
                    r"\bimport\s+pickle\b", r"\b__import__\s*\("]
        for f in _source_files():
            src = open(f, encoding="utf-8").read()
            for pat in patterns:
                self.assertNotRegex(src, pat,
                                    f"{os.path.basename(f)} 에 위험 패턴 {pat}")

    def test_no_hardcoded_secrets(self):
        secret_pats = [
            r"hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}",  # real webhook
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",  # AWS access key id (EXAMPLE 는 제외됨)
        ]
        for f in _source_files():
            src = open(f, encoding="utf-8").read()
            for pat in secret_pats:
                for m in re.finditer(pat, src):
                    val = m.group(0)
                    # 문서/예시용 EXAMPLE 값은 허용
                    if "EXAMPLE" in val:
                        continue
                    self.fail(f"{os.path.basename(f)} 에 하드코딩 시크릿 의심: {val[:12]}...")


class RemediationSafeExecTest(unittest.TestCase):
    def _run(self, command):
        from autoauditor.remediation import RemediationAction, _maybe_execute
        from autoauditor.config import Config, REMEDIATION_AUTO
        a = RemediationAction(title="t", platform="aws", command=command, target="x")
        cfg = Config(remediation=REMEDIATION_AUTO, dry_run=False)
        _maybe_execute(a, cfg)
        return a

    def test_semicolon_blocked(self):
        a = self._run("aws s3 ls; rm -rf /tmp/x")
        self.assertEqual(a.status, "skipped_protected")

    def test_pipe_blocked(self):
        a = self._run("aws s3 ls | cat")
        self.assertEqual(a.status, "skipped_protected")

    def test_backtick_blocked(self):
        a = self._run("aws s3 ls `whoami`")
        self.assertEqual(a.status, "skipped_protected")

    def test_placeholder_stays_dryrun(self):
        # 자리표시자(<...>)가 있으면 실행하지 않고 dry_run
        from autoauditor.remediation import RemediationAction, _maybe_execute
        from autoauditor.config import Config, REMEDIATION_AUTO
        a = RemediationAction(title="t", platform="azure",
                              command="az sql server update -g <RG> -n <SERVER>", target="y")
        _maybe_execute(a, Config(remediation=REMEDIATION_AUTO, dry_run=False))
        self.assertEqual(a.status, "dry_run")


class CollectorPipeSafeTest(unittest.TestCase):
    def test_pipe_command_without_shell(self):
        from autoauditor import collector
        out = collector._run("echo hello | tr a-z A-Z")
        self.assertIsNotNone(out)
        self.assertIn("HELLO", out)

    def test_plain_command(self):
        from autoauditor import collector
        out = collector._run("echo abc123")
        self.assertIn("abc123", out)


if __name__ == "__main__":
    unittest.main()
