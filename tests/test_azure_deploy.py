"""Azure 자동 배포(Functions) 관련 테스트.

Azure SDK가 없는 환경(로컬/CI)에서도 available()=False 이고, collector.collect가
안전하게 CLI/목업으로 폴백해야 한다. 배포 구성 파일(JSON)의 유효성도 확인한다.
실제 Azure 호출은 하지 않는다.
"""

import json
import os
import unittest

from autoauditor import collector, collector_azure_sdk


class AzureSdkAvailabilityTest(unittest.TestCase):
    def test_available_returns_bool(self):
        self.assertIsInstance(collector_azure_sdk.available(), bool)

    def test_collect_unavailable_shape(self):
        if not collector_azure_sdk.available():
            r = collector_azure_sdk.collect()
            self.assertEqual(r["source"], "unavailable")
            self.assertIn("text", r)
            self.assertIn("threat_text", r)

    def test_safe_wrapper(self):
        def boom():
            raise RuntimeError("권한 없음")
        self.assertEqual(collector_azure_sdk._safe(boom, []), [])
        self.assertEqual(collector_azure_sdk._safe(lambda: [1], []), [1])

    def test_collect_config_needs_subscription(self):
        # 구독 ID가 없으면 빈 목록(예외 없이)
        old = os.environ.pop("AZURE_SUBSCRIPTION_ID", None)
        try:
            self.assertEqual(collector_azure_sdk.collect_config(None), [])
        finally:
            if old is not None:
                os.environ["AZURE_SUBSCRIPTION_ID"] = old


class AzureCollectorFallbackTest(unittest.TestCase):
    def test_azure_collect_has_threat_text_key(self):
        r = collector.collect("azure", use_mock=True)
        self.assertIn("threat_text", r)
        self.assertEqual(r["source"], "mock")

    def test_azure_mock_analyzable(self):
        from auditor.engine import analyze
        r = collector.collect("azure", use_mock=True)
        d = analyze(r["text"]).to_dict()
        self.assertGreater(d["total_findings"], 0)


class AzureFunctionImportTest(unittest.TestCase):
    def test_import_and_signature(self):
        from autoauditor import azure_function
        self.assertTrue(hasattr(azure_function, "main"))


class AzureDeployFilesTest(unittest.TestCase):
    def _root(self):
        return os.path.join(os.path.dirname(__file__), "..")

    def test_host_json_valid(self):
        p = os.path.join(self._root(), "deploy-azure", "host.json")
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("version"), "2.0")

    def test_function_json_timer_trigger(self):
        p = os.path.join(self._root(), "deploy-azure", "AutoAudit", "function.json")
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        bindings = data.get("bindings", [])
        self.assertTrue(any(b.get("type") == "timerTrigger" for b in bindings))

    def test_requirements_has_azure_sdk(self):
        p = os.path.join(self._root(), "deploy-azure", "requirements.txt")
        with open(p, encoding="utf-8") as f:
            req = f.read()
        for pkg in ("azure-functions", "azure-identity", "azure-mgmt-network"):
            self.assertIn(pkg, req)


if __name__ == "__main__":
    unittest.main()
