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


# 위험 패턴을 '데이터(탐지 규칙·예시 문자열)'로만 담는 모듈은 스캔에서 제외한다.
# appsec.py 는 간이 SAST 스캐너로, shell=True·eval(·os.system( 등을 '탐지 대상 문자열'로
# 포함해야 하므로 실행 코드 스캔 대상에서 뺀다. 대신 이 모듈이 해당 함수를 '실제로 호출'하지
# 않는지는 AppsecScannerIsDataOnlyTest 에서 별도로 검증한다.
_PATTERN_SCAN_EXEMPT = {"appsec.py"}


def _source_files(exempt=None):
    exempt = exempt or set()
    root = os.path.join(os.path.dirname(__file__), "..")
    files = []
    for pkg in ("auditor", "autoauditor"):
        files += glob.glob(os.path.join(root, pkg, "*.py"))
    return [f for f in files if os.path.basename(f) not in exempt]


class NoDangerousPatternsTest(unittest.TestCase):
    def test_no_shell_true(self):
        for f in _source_files(_PATTERN_SCAN_EXEMPT):
            src = open(f, encoding="utf-8").read()
            self.assertNotRegex(src, r"shell\s*=\s*True",
                                f"{os.path.basename(f)} 에 shell=True 존재")

    def test_no_eval_exec_system_pickle(self):
        # 실제 호출 형태만 탐지(주석/문자열 설명은 정규식 경계로 최소화)
        patterns = [r"\beval\s*\(", r"\bexec\s*\(", r"os\.system\s*\(",
                    r"\bimport\s+pickle\b", r"\b__import__\s*\("]
        for f in _source_files(_PATTERN_SCAN_EXEMPT):
            src = open(f, encoding="utf-8").read()
            for pat in patterns:
                self.assertNotRegex(src, pat,
                                    f"{os.path.basename(f)} 에 위험 패턴 {pat}")


class AppsecScannerIsDataOnlyTest(unittest.TestCase):
    """appsec.py(간이 SAST)는 위험 패턴을 '탐지 규칙'으로만 갖고, 실제로 호출하지 않아야 한다.

    검증 방식: 모듈을 AST로 파싱해 실행 가능한 호출부(Call/Import 노드)에
    eval/exec/os.system/subprocess(shell=True)/pickle 이 없는지 본다.
    (regex 문자열·예시 문자열은 AST에서 그냥 상수 문자열이라 잡히지 않는다.)
    """

    def _tree(self):
        import ast
        root = os.path.join(os.path.dirname(__file__), "..")
        src = open(os.path.join(root, "auditor", "appsec.py"), encoding="utf-8").read()
        return ast.parse(src)

    def test_no_real_dangerous_calls(self):
        import ast
        tree = self._tree()
        banned_calls = {"eval", "exec", "system", "popen"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                # eval(...) / exec(...)
                if isinstance(fn, ast.Name):
                    self.assertNotIn(fn.id, banned_calls,
                                     f"appsec.py 가 {fn.id}() 를 실제 호출")
                # os.system(...) / os.popen(...)
                if isinstance(fn, ast.Attribute):
                    self.assertNotIn(fn.attr, banned_calls,
                                     f"appsec.py 가 .{fn.attr}() 를 실제 호출")
                # subprocess(..., shell=True) 실제 호출 금지
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.fail("appsec.py 가 shell=True 로 실제 호출")

    def test_no_dangerous_imports(self):
        import ast
        tree = self._tree()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    self.assertNotIn(n.name, {"pickle", "subprocess"},
                                     f"appsec.py 가 {n.name} 를 import")
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module, {"pickle", "subprocess"},
                                 f"appsec.py 가 {node.module} 에서 import")

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
