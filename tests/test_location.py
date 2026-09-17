"""리소스 위치(어느 장비/위치인지) 추출 테스트.

검토 결과에서 "어디를 고쳐야 하는지"를 명확히 하기 위해, 클라우드 CLI 출력의
위치 정보(Azure: 구독/리소스그룹/리전, AWS: 계정/리전/VPC)를 추출한다.
"""

import json
import unittest

from auditor.engine import analyze, _location_from_dict


def _find(text, itype):
    for f in analyze(text).to_dict()["findings"]:
        if f["issue_type"] == itype:
            return f
    return None


class LocationExtractTest(unittest.TestCase):
    def test_azure_id_parsed(self):
        d = {"id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/"
                   "Microsoft.Network/networkSecurityGroups/nsg1",
             "location": "koreacentral"}
        loc = _location_from_dict(d)
        self.assertIn("구독 sub-1", loc)
        self.assertIn("리소스그룹 rg-prod", loc)
        self.assertIn("리전 koreacentral", loc)

    def test_azure_resourcegroup_field(self):
        d = {"name": "x", "resourceGroup": "rg-net"}
        self.assertIn("리소스그룹 rg-net", _location_from_dict(d))

    def test_aws_account_vpc(self):
        d = {"GroupId": "sg-1", "VpcId": "vpc-9", "OwnerId": "123456789012"}
        loc = _location_from_dict(d)
        self.assertIn("계정 123456789012", loc)
        self.assertIn("VPC vpc-9", loc)

    def test_aws_arn_parsed(self):
        d = {"Arn": "arn:aws:rds:ap-northeast-2:123456789012:db:prod"}
        loc = _location_from_dict(d)
        self.assertIn("리전 ap-northeast-2", loc)
        self.assertIn("계정 123456789012", loc)

    def test_empty_when_no_location(self):
        self.assertEqual(_location_from_dict({"foo": "bar"}), "")
        self.assertEqual(_location_from_dict("not a dict"), "")


class LocationInFindingsTest(unittest.TestCase):
    def test_azure_nsg_finding_has_location(self):
        txt = json.dumps([{
            "name": "r1", "resourceGroup": "rg-prod", "location": "koreacentral",
            "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/"
                  "Microsoft.Network/networkSecurityGroups/nsg1/securityRules/r1",
            "sourceAddressPrefix": "*", "destinationPortRange": "3389",
            "access": "Allow", "direction": "Inbound"}])
        f = _find(txt, "nsg_open_sensitive_port")
        self.assertIsNotNone(f)
        self.assertIn("리소스그룹 rg-prod", f["location"])

    def test_aws_sg_finding_has_location(self):
        txt = json.dumps([{
            "GroupId": "sg-0abc", "GroupName": "prod-web", "VpcId": "vpc-0def",
            "OwnerId": "123456789012",
            "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                               "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}])
        f = _find(txt, "aws_sg_open_sensitive_port")
        self.assertIsNotNone(f)
        self.assertIn("VPC vpc-0def", f["location"])
        self.assertIn("SG prod-web", f["location"])

    def test_sql_finding_has_location(self):
        txt = json.dumps([{
            "name": "srv1", "resourceGroup": "rg-sql", "publicNetworkAccess": "Enabled",
            "id": "/subscriptions/sub-9/resourceGroups/rg-sql/providers/"
                  "Microsoft.Sql/servers/srv1"}])
        f = _find(txt, "sql_public_access")
        self.assertIsNotNone(f)
        self.assertIn("리소스그룹 rg-sql", f["location"])

    def test_raw_text_finding_no_location(self):
        # 텍스트 패턴 탐지는 위치가 비어 있어도 정상(오류 없이)
        f = _find("lastBackupStatus: Failed", "backup_failed")
        self.assertIsNotNone(f)
        self.assertEqual(f["location"], "")


if __name__ == "__main__":
    unittest.main()
