"""오프라인 판정 엔진 단위 테스트 (표준 unittest만 사용).

실행: python -m unittest -v   (프로젝트 루트에서)
     또는  python tests/test_engine.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auditor.engine import analyze
from auditor.models import Severity
from auditor.knowledge_base import all_controls, control


def _types(report):
    return {f.issue_type for f in report.findings}


class TestNsg(unittest.TestCase):
    def test_ssh_open_to_any_is_critical(self):
        r = analyze('[{"name":"r","access":"Allow","direction":"Inbound",'
                    '"sourceAddressPrefix":"*","destinationPortRange":"22"}]')
        self.assertIn("nsg_open_sensitive_port", _types(r))
        f = next(f for f in r.findings if f.issue_type == "nsg_open_sensitive_port")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.control_code, "2.6.1")
        self.assertTrue(f.recommendation)  # kb의 개선방안 연결

    def test_deny_rule_excluded(self):
        r = analyze('[{"name":"deny","access":"Deny","direction":"Inbound",'
                    '"sourceAddressPrefix":"*","destinationPortRange":"*"}]')
        self.assertEqual(len(r.findings), 0)

    def test_internal_source_excluded(self):
        r = analyze('[{"name":"int","access":"Allow","direction":"Inbound",'
                    '"sourceAddressPrefix":"10.0.0.0/8","destinationPortRange":"22"}]')
        self.assertEqual(len(r.findings), 0)

    def test_outbound_any_is_267(self):
        r = analyze('[{"name":"out","access":"Allow","direction":"Outbound",'
                    '"sourceAddressPrefix":"*","destinationPortRange":"*"}]')
        f = next(f for f in r.findings if f.issue_type == "nsg_outbound_any")
        self.assertEqual(f.control_code, "2.6.7")


class TestStorage(unittest.TestCase):
    def test_https_and_public_and_tls(self):
        r = analyze('{"name":"s","type":"Microsoft.Storage/storageAccounts",'
                    '"supportsHttpsTrafficOnly":false,"allowBlobPublicAccess":true,'
                    '"minimumTlsVersion":"TLS1_0"}')
        t = _types(r)
        self.assertIn("storage_https_disabled", t)
        self.assertIn("storage_public_blob", t)
        self.assertIn("storage_weak_tls", t)

    def test_secure_storage_clean(self):
        r = analyze('{"name":"s","type":"Microsoft.Storage/storageAccounts",'
                    '"supportsHttpsTrafficOnly":true,"allowBlobPublicAccess":false,'
                    '"minimumTlsVersion":"TLS1_2"}')
        self.assertEqual(len(r.findings), 0)


class TestKeyVault(unittest.TestCase):
    def test_softdelete_purge_no_duplicate(self):
        r = analyze('{"name":"kv","type":"Microsoft.KeyVault/vaults",'
                    '"properties":{"enableSoftDelete":false,"enablePurgeProtection":false}}')
        kv = [f for f in r.findings if f.issue_type.startswith("keyvault")]
        # 정확히 2건(soft+purge), 중복 없음
        self.assertEqual(len(kv), 2)
        self.assertTrue(all(f.control_code == "2.7.2" for f in kv))


class TestRbac(unittest.TestCase):
    def test_owner_high_reader_ignored(self):
        r = analyze('[{"principalName":"a","roleDefinitionName":"Owner"},'
                    '{"principalName":"b","roleDefinitionName":"Reader"}]')
        rbac = [f for f in r.findings if f.issue_type == "rbac_privileged_assignment"]
        self.assertEqual(len(rbac), 1)
        self.assertEqual(rbac[0].severity, Severity.HIGH)
        self.assertEqual(rbac[0].control_code, "2.5.5")


class TestSql(unittest.TestCase):
    def test_public_access_and_tde(self):
        r = analyze('{"name":"db","type":"Microsoft.Sql/servers/databases",'
                    '"publicNetworkAccess":"Enabled"}')
        self.assertIn("sql_public_access", _types(r))

    def test_tde_disabled(self):
        r = analyze('{"name":"tde","transparentDataEncryption":true,"status":"Disabled"}')
        self.assertIn("sql_tde_disabled", _types(r))


class TestTextFallback(unittest.TestCase):
    def test_backup_and_unhealthy(self):
        r = analyze("lastBackupStatus: Failed\nStorageType: LRS\n12 Unhealthy items\n"
                    "Diagnostic Settings: []")
        t = _types(r)
        self.assertIn("backup_failed", t)
        self.assertIn("backup_lrs", t)
        self.assertIn("assessment_unhealthy", t)
        self.assertIn("diagnostic_missing", t)


class TestReportScoring(unittest.TestCase):
    def test_empty_input_has_note(self):
        r = analyze("")
        self.assertEqual(len(r.findings), 0)
        self.assertTrue(r.notes)

    def test_score_penalty(self):
        # CRITICAL 1건이면 100-25=75
        r = analyze('[{"name":"r","access":"Allow","direction":"Inbound",'
                    '"sourceAddressPrefix":"*","destinationPortRange":"22"}]')
        self.assertEqual(r.score(), 75)
        self.assertEqual(r.grade(), "C")

    def test_all_findings_map_to_known_control(self):
        codes = {c["code"] for c in all_controls()}
        r = analyze('[{"name":"r","access":"Allow","direction":"Inbound",'
                    '"sourceAddressPrefix":"*","destinationPortRange":"22"}]')
        for f in r.findings:
            self.assertIn(f.control_code, codes)
            self.assertIsNotNone(control(f.control_code))


class TestAws(unittest.TestCase):
    def test_sg_open_ssh_critical_and_platform(self):
        r = analyze('[{"GroupId":"sg-1","IpPermissions":[{"IpProtocol":"tcp",'
                    '"FromPort":22,"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]}]')
        f = next(f for f in r.findings if f.issue_type == "aws_sg_open_sensitive_port")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.platform, "aws")
        self.assertEqual(f.control_code, "2.6.1")
        self.assertTrue(f.recommendation)  # aws 플랫폼 개선방안 연결

    def test_sg_internal_source_excluded(self):
        r = analyze('[{"GroupId":"sg-2","IpPermissions":[{"IpProtocol":"tcp",'
                    '"FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"10.0.0.0/8"}]}]}]')
        self.assertEqual(len(r.findings), 0)

    def test_s3_public_block_and_encryption(self):
        r = analyze('{"Name":"b","PublicAccessBlockConfiguration":{"BlockPublicAcls":false,'
                    '"IgnorePublicAcls":false,"BlockPublicPolicy":false,"RestrictPublicBuckets":false},'
                    '"ServerSideEncryptionConfiguration":null}')
        types = {f.issue_type for f in r.findings}
        self.assertIn("aws_s3_public_block_off", types)
        self.assertIn("aws_s3_no_encryption", types)
        self.assertTrue(all(f.platform == "aws" for f in r.findings))

    def test_iam_wildcard_admin_and_mfa(self):
        r = analyze('[{"PolicyName":"p","PolicyDocument":{"Statement":[{"Effect":"Allow",'
                    '"Action":"*","Resource":"*"}]}},{"UserName":"u","MFAActive":false}]')
        types = {f.issue_type for f in r.findings}
        self.assertIn("aws_iam_wildcard_admin", types)
        self.assertIn("aws_iam_no_mfa", types)


class TestPlatformDetection(unittest.TestCase):
    def test_mixed_input_both_platforms(self):
        mixed = ('[{"GroupId":"sg-1","IpPermissions":[{"IpProtocol":"tcp","FromPort":22,'
                 '"ToPort":22,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]}]\n'
                 '[{"name":"nsg","access":"Allow","direction":"Inbound",'
                 '"sourceAddressPrefix":"*","destinationPortRange":"3389"}]')
        r = analyze(mixed)
        self.assertEqual(set(r.detected_platforms()), {"aws", "azure"})
        pc = r.platform_counts()
        self.assertEqual(pc.get("aws"), 1)
        self.assertEqual(pc.get("azure"), 1)

    def test_azure_still_tagged_azure(self):
        r = analyze('[{"name":"nsg","access":"Allow","direction":"Inbound",'
                    '"sourceAddressPrefix":"*","destinationPortRange":"22"}]')
        self.assertTrue(all(f.platform == "azure" for f in r.findings))


class TestKnowledgeBase(unittest.TestCase):
    def test_17_controls(self):
        self.assertEqual(len(all_controls()), 17)

    def test_every_control_has_platform_fields(self):
        for c in all_controls():
            for key in ("code", "domain", "desc", "resources", "azure", "aws"):
                self.assertTrue(c.get(key) is not None, f"{c['code']} missing {key}")
            for plat in ("azure", "aws"):
                for k in ("cmd", "criteria", "fix"):
                    self.assertIn(k, c[plat], f"{c['code']} {plat} missing {k}")

    def test_control_for_platform(self):
        from auditor.knowledge_base import control_for
        az = control_for("2.6.1", "azure")
        aws = control_for("2.6.1", "aws")
        self.assertEqual(az["platform"], "azure")
        self.assertEqual(aws["platform"], "aws")
        self.assertTrue(az["fix"] and aws["fix"])
        self.assertNotEqual(az["fix"], aws["fix"])  # 플랫폼별로 다른 개선안
        # 미상 코드
        self.assertEqual(control_for("9.9.9", "aws")["criteria"], "")

    def test_collection_commands(self):
        from auditor.knowledge_base import collection_commands
        # AWS: ISMS 17항목만
        aws_cmds = collection_commands("aws")
        self.assertEqual(len(aws_cmds), 17)
        # Azure: ISMS 17 + SQL 세부 8 = 25항목
        az_cmds = collection_commands("azure")
        self.assertEqual(len(az_cmds), 25)
        sql_items = [c for c in az_cmds if c["domain"] == "SQL 보안 세부점검"]
        self.assertEqual(len(sql_items), 8)
        # 모든 항목에 명령 라인이 하나 이상
        for plat, cmds in (("aws", aws_cmds), ("azure", az_cmds)):
            self.assertTrue(all(c["cmd_lines"] for c in cmds), f"{plat}: 빈 명령 항목")
            self.assertTrue(all(c["platform"] == plat for c in cmds))
        # AWS와 Azure 명령이 실제로 다름(2.6.1)
        aws_c = next(c for c in aws_cmds if c["code"] == "2.6.1")
        az_c = next(c for c in az_cmds if c["code"] == "2.6.1" and c["domain"] != "SQL 보안 세부점검")
        self.assertNotEqual(aws_c["cmd"], az_c["cmd"])
        # SQL 항목엔 위반/개선 예시가 채워져 있음
        self.assertTrue(all(c["bad_example"] and c["good_example"] for c in sql_items))


if __name__ == "__main__":
    unittest.main(verbosity=2)
