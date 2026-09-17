"""정보보안 고도화 기능 테스트.

- Flow Logs 플랫폼 자동 구분(Azure=NSG / AWS=VPC)
- 개인정보(PII)·시크릿 하드코딩 탐지 + 마스킹 + 오탐 방지
- 위험 점수(risk_score) 산정·정렬
- 상관 분석(복합 위험 경로)
"""

import json
import unittest

from auditor.engine import analyze


def _findings(text):
    return analyze(text).to_dict()["findings"]


def _types(text):
    return {f["issue_type"] for f in _findings(text)}


class FlowLogsPlatformTest(unittest.TestCase):
    def _flow(self, text):
        return [f for f in _findings(text) if f["issue_type"] == "vpc_flowlogs_missing"]

    def test_azure_flowlogs_tagged_azure(self):
        f = self._flow("az network watcher flow-log list: [] (no flow logs for nsg-prod)")
        self.assertTrue(f)
        self.assertEqual(f[0]["platform"], "azure")
        self.assertIn("NSG", f[0]["title"])

    def test_aws_flowlogs_tagged_aws(self):
        f = self._flow("aws ec2 describe-flow-logs: [] no flow log for vpc-abc")
        self.assertTrue(f)
        self.assertEqual(f[0]["platform"], "aws")
        self.assertIn("VPC", f[0]["title"])


class PiiSecretTest(unittest.TestCase):
    def test_pii_detected_and_masked(self):
        txt = "log: 900101-1234567 hong@corp.com 010-1234-5678"
        f = [x for x in _findings(txt) if x["issue_type"] == "pii_exposed"]
        self.assertTrue(f)
        self.assertEqual(f[0]["severity"], "CRITICAL")  # 주민번호 포함
        # 원문이 그대로 노출되면 안 됨(마스킹)
        self.assertNotIn("900101-1234567", f[0]["evidence"])
        self.assertIn("*", f[0]["evidence"])

    def test_secret_detected_and_masked(self):
        txt = "aws_access_key=AKIAIOSFODNN7EXAMPLE password=Sup3rSecret!"
        f = [x for x in _findings(txt) if x["issue_type"] == "secret_exposed"]
        self.assertTrue(f)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f[0]["evidence"])

    def test_luhn_false_card_not_flagged(self):
        # Luhn 실패하는 가짜 카드번호는 개인정보로 잡히면 안 됨
        txt = '{"num":"1234 5678 9012 3456"}'
        types = _types(txt)
        self.assertNotIn("pii_exposed", types)

    def test_cloud_json_no_false_positive(self):
        # 전형적인 클라우드 JSON에 PII/시크릿 오탐이 없어야 함
        txt = json.dumps([
            {"name": "nsg1", "sourceAddressPrefix": "0.0.0.0/0",
             "destinationPortRange": "22", "access": "Allow", "direction": "Inbound"},
            {"id": "/subscriptions/abc-123/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/stg1"},
        ])
        types = _types(txt)
        self.assertNotIn("pii_exposed", types)
        self.assertNotIn("secret_exposed", types)


class RiskScoreTest(unittest.TestCase):
    def test_risk_score_present_and_ordered(self):
        txt = json.dumps([
            {"name": "nsg1", "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "22",
             "access": "Allow", "direction": "Inbound"},
            {"name": "kv1", "enableSoftDelete": False, "type": "Microsoft.KeyVault/vaults"},
        ])
        d = analyze(txt).to_dict()
        # 모든 finding에 risk_score가 있고, findings는 위험점수 내림차순
        scores = [f["risk_score"] for f in d["findings"]]
        self.assertTrue(all(isinstance(s, int) for s in scores))
        self.assertEqual(scores, sorted(scores, reverse=True))
        # top_risks 노출
        self.assertTrue(d["top_risks"])
        self.assertIn("risk_factors", d["top_risks"][0])

    def test_internet_exposed_scores_higher(self):
        # 인터넷 노출(관리포트) 이슈가 Key Vault soft-delete보다 높은 위험점수
        txt = json.dumps([
            {"name": "nsg1", "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "3389",
             "access": "Allow", "direction": "Inbound"},
            {"name": "kv1", "enableSoftDelete": False, "type": "Microsoft.KeyVault/vaults"},
        ])
        fs = {f["issue_type"]: f["risk_score"] for f in _findings(txt)}
        self.assertGreater(fs.get("nsg_open_sensitive_port", 0),
                           fs.get("keyvault_softdelete_off", 0))


class CorrelationTest(unittest.TestCase):
    def test_sg_port_plus_no_mfa_correlation(self):
        txt = json.dumps([
            {"GroupId": "sg-1", "IpPermissions": [{"FromPort": 22, "ToPort": 22,
             "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"UserName": "user1", "MFAActive": False},
        ])
        corr = analyze(txt).to_dict()["correlations"]
        titles = [c["title"] for c in corr]
        self.assertTrue(any("MFA 없는 계정" in t for t in titles))

    def test_no_correlation_when_single_issue(self):
        # 단일 이슈만 있으면 복합 위험 경고가 없어야 함
        txt = json.dumps([{"name": "kv1", "enableSoftDelete": False,
                           "type": "Microsoft.KeyVault/vaults"}])
        corr = analyze(txt).to_dict()["correlations"]
        self.assertEqual(corr, [])


if __name__ == "__main__":
    unittest.main()
