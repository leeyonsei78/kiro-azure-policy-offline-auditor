"""정보보안 고도화 2단계 테스트.

- 컨테이너(EKS/AKS)·API Gateway 탐지
- MITRE ATT&CK 매핑
- 추세 비교(diff_reports)
- 신규 수집 명령어(컨테이너/WAF) 커버리지
"""

import json
import unittest

from auditor.engine import analyze, diff_reports
from auditor.knowledge_base import collection_commands


def _findings(text):
    return analyze(text).to_dict()["findings"]


def _types(text):
    return {f["issue_type"] for f in _findings(text)}


class ContainerApiTest(unittest.TestCase):
    def test_eks_public_api(self):
        txt = json.dumps([{"name": "eks1", "resourcesVpcConfig":
                           {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}}])
        f = [x for x in _findings(txt) if x["issue_type"] == "eks_public_api"]
        self.assertEqual(len(f), 1)          # 중복 없이 1건
        self.assertEqual(f[0]["platform"], "aws")

    def test_eks_private_not_flagged(self):
        txt = json.dumps([{"name": "eks2", "resourcesVpcConfig": {"endpointPublicAccess": False}}])
        self.assertNotIn("eks_public_api", _types(txt))

    def test_aks_public_api(self):
        txt = json.dumps([{"name": "aks1",
                           "apiServerAccessProfile": {"enablePrivateCluster": False, "authorizedIpRanges": []},
                           "type": "Microsoft.ContainerService/managedClusters"}])
        f = [x for x in _findings(txt) if x["issue_type"] == "aks_public_api"]
        self.assertTrue(f)
        self.assertEqual(f[0]["platform"], "azure")

    def test_aks_private_not_flagged(self):
        txt = json.dumps([{"name": "aks2",
                           "apiServerAccessProfile": {"enablePrivateCluster": True}}])
        self.assertNotIn("aks_public_api", _types(txt))

    def test_aks_rbac_disabled(self):
        txt = json.dumps([{"name": "aks3", "enableRbac": False,
                           "apiServerAccessProfile": {"enablePrivateCluster": True}}])
        self.assertIn("aks_rbac_disabled", _types(txt))

    def test_apigw_no_auth(self):
        txt = '{"authorizationType":"NONE","apiKeyRequired":false} apigateway method'
        self.assertIn("apigw_no_auth", _types(txt))


class MitreMappingTest(unittest.TestCase):
    def test_common_types_have_mitre(self):
        txt = json.dumps([
            {"name": "nsg1", "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "22",
             "access": "Allow", "direction": "Inbound"},
            {"name": "stg1", "allowBlobPublicAccess": True},
        ])
        by_type = {f["issue_type"]: f for f in _findings(txt)}
        self.assertEqual(by_type["nsg_open_sensitive_port"]["mitre_id"], "T1190")
        self.assertEqual(by_type["storage_public_blob"]["mitre_id"], "T1530")
        self.assertTrue(by_type["nsg_open_sensitive_port"]["mitre_name"])

    def test_sql_finding_has_mitre(self):
        txt = json.dumps([{"name": "srv1", "publicNetworkAccess": "Enabled"}])
        f = [x for x in _findings(txt) if x["issue_type"] == "sql_public_access"][0]
        self.assertTrue(f["mitre_id"])


class DiffReportsTest(unittest.TestCase):
    def _report(self, objs):
        return analyze(json.dumps(objs)).to_dict()

    def test_added_resolved_kept(self):
        prev = self._report([
            {"name": "nsg1", "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "22",
             "access": "Allow", "direction": "Inbound"},
            {"name": "stg1", "allowBlobPublicAccess": True},
        ])
        cur = self._report([
            {"name": "nsg1", "sourceAddressPrefix": "0.0.0.0/0", "destinationPortRange": "22",
             "access": "Allow", "direction": "Inbound"},
            {"name": "kv1", "enableSoftDelete": False, "type": "Microsoft.KeyVault/vaults"},
        ])
        d = diff_reports(cur, prev)
        self.assertEqual(d["added_count"], 1)     # keyvault 신규
        self.assertEqual(d["resolved_count"], 1)  # storage 해결
        self.assertEqual(d["kept_count"], 1)      # nsg 유지
        self.assertEqual(d["added"][0]["issue_type"], "keyvault_softdelete_off")
        self.assertEqual(d["resolved"][0]["issue_type"], "storage_public_blob")

    def test_score_delta(self):
        prev = self._report([{"name": "stg1", "allowBlobPublicAccess": True}])
        cur = self._report([])  # 이슈 없음 → 개선
        d = diff_reports(cur, prev)
        self.assertGreater(d["score_delta"], 0)  # 점수 상승(개선)

    def test_no_change(self):
        rep = self._report([{"name": "stg1", "allowBlobPublicAccess": True}])
        d = diff_reports(rep, rep)
        self.assertEqual(d["added_count"], 0)
        self.assertEqual(d["resolved_count"], 0)
        self.assertEqual(d["score_delta"], 0)


class NewCommandsTest(unittest.TestCase):
    def _all(self, platform):
        return "\n".join(ln for it in collection_commands(platform) for ln in it["cmd_lines"])

    def test_aws_container_api_waf_commands(self):
        aws = self._all("aws")
        for needle in ["eks list-clusters", "eks describe-cluster", "apigateway get-rest-apis",
                       "wafv2 list-web-acls"]:
            self.assertIn(needle, aws, f"AWS 명령 누락: {needle}")

    def test_azure_container_api_waf_commands(self):
        az = self._all("azure")
        for needle in ["aks list", "aks show", "apim list",
                       "waf-policy list"]:
            self.assertIn(needle, az, f"Azure 명령 누락: {needle}")


if __name__ == "__main__":
    unittest.main()
