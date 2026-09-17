"""CIS Benchmark 기반으로 추가한 신규 위반/취약점 탐지 테스트.

이번 확장에서 추가한 탐지 로직(RDS 퍼블릭, EBS 스냅샷 공개, App Service HTTPS,
디스크 CMK 미적용, VPC Flow Logs 미구성, AWS Config 레코더 비활성)이 실제 입력에서
올바르게 위반을 잡아내는지 검증한다. 또한 새로 추가한 수집 명령어가 명령어 가이드에
포함되었는지도 확인한다.
"""

import json
import unittest

from auditor.engine import analyze
from auditor.knowledge_base import collection_commands


def _issue_types(text):
    return {f["issue_type"] for f in analyze(text).to_dict()["findings"]}


class NewDetectionTest(unittest.TestCase):
    def test_aws_rds_public(self):
        txt = json.dumps([{"DBInstanceIdentifier": "prod-db", "Engine": "mysql",
                           "PubliclyAccessible": True}])
        self.assertIn("aws_rds_public", _issue_types(txt))

    def test_aws_rds_private_ok(self):
        # 퍼블릭이 아니면 탐지되지 않아야 한다(오탐 방지).
        txt = json.dumps([{"DBInstanceIdentifier": "prod-db", "Engine": "mysql",
                           "PubliclyAccessible": False}])
        self.assertNotIn("aws_rds_public", _issue_types(txt))

    def test_aws_ebs_snapshot_public(self):
        txt = json.dumps([{"SnapshotId": "snap-123",
                           "CreateVolumePermission": [{"Group": "all"}]}])
        self.assertIn("aws_ebs_snapshot_public", _issue_types(txt))

    def test_aws_ebs_snapshot_private_ok(self):
        txt = json.dumps([{"SnapshotId": "snap-123",
                           "CreateVolumePermission": [{"UserId": "123456789012"}]}])
        self.assertNotIn("aws_ebs_snapshot_public", _issue_types(txt))

    def test_azure_webapp_https_disabled(self):
        txt = json.dumps([{"name": "myweb", "httpsOnly": False,
                           "type": "Microsoft.Web/sites"}])
        self.assertIn("webapp_https_disabled", _issue_types(txt))

    def test_azure_webapp_https_ok(self):
        txt = json.dumps([{"name": "myweb", "httpsOnly": True,
                           "type": "Microsoft.Web/sites"}])
        self.assertNotIn("webapp_https_disabled", _issue_types(txt))

    def test_azure_disk_no_cmk(self):
        txt = json.dumps([{"name": "osdisk1",
                           "encryption": {"type": "EncryptionAtRestWithPlatformKey"}}])
        self.assertIn("disk_no_cmk", _issue_types(txt))

    def test_azure_disk_cmk_ok(self):
        txt = json.dumps([{"name": "osdisk1",
                           "encryption": {"type": "EncryptionAtRestWithCustomerKey"}}])
        self.assertNotIn("disk_no_cmk", _issue_types(txt))

    def test_vpc_flowlogs_missing(self):
        txt = "aws ec2 describe-flow-logs 결과: []  no flow log for vpc-abc"
        self.assertIn("vpc_flowlogs_missing", _issue_types(txt))

    def test_aws_config_recorder_off(self):
        txt = '{"name":"default","recording":false} configurationRecorder'
        self.assertIn("aws_config_recorder_off", _issue_types(txt))

    def test_mixed_aws_azure_no_dropout(self):
        # AWS·Azure 리소스가 한 입력에 섞여도 각 위반이 모두 탐지돼야 한다
        # (전체 플랫폼 hint가 한쪽으로 쏠려도 누락되지 않도록).
        txt = json.dumps([
            {"DBInstanceIdentifier": "db1", "Engine": "mysql", "PubliclyAccessible": True},
            {"SnapshotId": "snap-1", "CreateVolumePermission": [{"Group": "all"}]},
            {"name": "web1", "httpsOnly": False, "type": "Microsoft.Web/sites"},
        ])
        types = _issue_types(txt)
        self.assertIn("aws_rds_public", types)
        self.assertIn("aws_ebs_snapshot_public", types)
        self.assertIn("webapp_https_disabled", types)


class EvidenceAndExampleTest(unittest.TestCase):
    """텍스트 패턴 탐지가 '실제 근거 텍스트'를 보여주고, 예시가 채워지는지 검증."""

    def _findings(self, text):
        return analyze(text).to_dict()["findings"]

    def test_raw_text_evidence_contains_real_snippet(self):
        # 진단 설정 미구성: evidence에 입력의 실제 텍스트가 포함돼야 한다.
        txt = "az monitor diagnostic-settings list 결과: [] (no diagnostic settings for prod-vm)"
        f = [x for x in self._findings(txt) if x["issue_type"] == "diagnostic_missing"][0]
        self.assertIn("근거 텍스트", f["evidence"])
        self.assertIn("diagnostic", f["evidence"].lower())

    def test_backup_failed_evidence(self):
        txt = "lastBackupStatus: Failed (vault prod-bak)"
        f = [x for x in self._findings(txt) if x["issue_type"] == "backup_failed"][0]
        self.assertIn("Failed", f["evidence"])

    def test_new_checks_have_examples(self):
        # 신규 탐지 항목에 위반/개선 예시가 채워져야 한다.
        txt = json.dumps([{"DBInstanceIdentifier": "db1", "Engine": "mysql",
                           "PubliclyAccessible": True}])
        f = [x for x in self._findings(txt) if x["issue_type"] == "aws_rds_public"][0]
        self.assertTrue(f["bad_example"])
        self.assertTrue(f["good_example"])

    def test_text_fallback_has_examples(self):
        txt = "conditional access state: disabled mfa 없음"
        f = [x for x in self._findings(txt) if x["issue_type"] == "mfa_ca_disabled"][0]
        self.assertTrue(f["bad_example"])
        self.assertTrue(f["good_example"])

    def test_findings_have_why_and_howto(self):
        # 초보 담당자용 '왜 문제인가(why)'와 '해결 방법(how_to_fix)'이 채워져야 한다.
        txt = json.dumps([{"name": "stg1", "allowBlobPublicAccess": True}])
        f = [x for x in self._findings(txt) if x["issue_type"] == "storage_public_blob"][0]
        self.assertTrue(f["why"], "why(왜 문제인가)가 비어 있음")
        self.assertTrue(f["how_to_fix"], "how_to_fix(해결 방법)가 비어 있음")
        # 해결 방법은 단계별(번호) 안내 형태여야 한다.
        self.assertIn("1)", f["how_to_fix"])

    def test_sql_findings_have_why_and_howto(self):
        # SQL 심층 점검 항목에도 why/how_to_fix가 있어야 한다.
        txt = json.dumps([{"name": "srv1", "publicNetworkAccess": "Enabled"}])
        f = [x for x in self._findings(txt) if x["issue_type"] == "sql_public_access"][0]
        self.assertTrue(f["why"])
        self.assertTrue(f["how_to_fix"])

    def test_findings_have_concrete_steps(self):
        # 실제 변경 방법(steps)에 포털 클릭 순서와 CLI 명령어가 모두 있어야 한다.
        txt = json.dumps([{"name": "stg1", "allowBlobPublicAccess": True}])
        f = [x for x in self._findings(txt) if x["issue_type"] == "storage_public_blob"][0]
        self.assertTrue(f["steps"], "steps(따라하기)가 비어 있음")
        self.assertIn("[포털]", f["steps"])
        self.assertIn("[CLI]", f["steps"])
        self.assertIn("az storage account update", f["steps"])

    def test_aws_steps_present(self):
        txt = json.dumps([{"DBInstanceIdentifier": "db1", "Engine": "mysql",
                           "PubliclyAccessible": True}])
        f = [x for x in self._findings(txt) if x["issue_type"] == "aws_rds_public"][0]
        self.assertIn("aws rds modify-db-instance", f["steps"])

    def test_every_explained_issue_has_steps(self):
        # 설명(why/how_to_fix)이 있는 모든 이슈 유형은 따라하기(steps)도 있어야 한다.
        from auditor.engine import _EXPLAIN, _STEPS
        missing = [k for k in _EXPLAIN if k not in _STEPS]
        self.assertEqual(missing, [], f"steps 누락 이슈유형: {missing}")

    def test_text_fallback_items_have_steps(self):
        # 대표 텍스트 폴백 항목들이 steps를 갖는지.
        for txt, want in [
            ("diagnostic-settings list: [] no diagnostic", "diagnostic_missing"),
            ("lastBackupStatus: Failed", "backup_failed"),
            ("patch classificationsToInclude=[Critical,Security] 미적용", "patch_pending"),
            ("CVE-2021-44228 발견", "cve_detected"),
        ]:
            f = [x for x in self._findings(txt) if x["issue_type"] == want]
            self.assertTrue(f, f"{want} 미탐지")
            self.assertTrue(f[0]["steps"], f"{want} steps 비어 있음")

    def test_sql_items_have_steps(self):
        for obj, want in [
            ({"state": "Disabled", "transparentDataEncryption": True}, "sql_tde_disabled"),
            ({"recurringScans": {"isEnabled": False}, "vulnerabilityAssessment": True}, "sql_va_disabled"),
        ]:
            f = [x for x in self._findings(json.dumps([obj])) if x["issue_type"] == want]
            self.assertTrue(f, f"{want} 미탐지")
            self.assertTrue(f[0]["steps"], f"{want} steps 비어 있음")

    def test_evidence_is_longer_context(self):
        # 근거 텍스트가 충분한 문맥을 담는지(짧게 잘리지 않는지) 확인.
        txt = ("az monitor diagnostic-settings list 결과: [] "
               "(no diagnostic settings configured for prod-vm and prod-sql server)")
        f = [x for x in self._findings(txt) if x["issue_type"] == "diagnostic_missing"][0]
        self.assertGreater(len(f["evidence"]), 40)


class NewCommandCoverageTest(unittest.TestCase):
    """새로 추가한 수집 명령어가 명령어 가이드에 포함됐는지 확인."""

    def _all_cmd_text(self, platform):
        return "\n".join(
            ln for it in collection_commands(platform) for ln in it["cmd_lines"]
        )

    def test_aws_new_commands_present(self):
        aws = self._all_cmd_text("aws")
        for needle in [
            "PubliclyAccessible",             # RDS 퍼블릭
            "get-public-access-block",        # S3 퍼블릭 차단
            "get-bucket-acl",                 # S3 ACL 공개
            "describe-flow-logs",             # VPC Flow Logs
            "describe-configuration-recorder-status",  # Config 레코더
            "AccountAccessKeysPresent",       # root 액세스키
            "secretsmanager list-secrets",    # 시크릿 로테이션
            "describe-snapshot-attribute",    # EBS 스냅샷 공개
        ]:
            self.assertIn(needle, aws, f"AWS 명령어 누락: {needle}")

    def test_aws_ssh_rdp_port_commands_present(self):
        aws = self._all_cmd_text("aws")
        self.assertIn("22", aws)
        self.assertIn("3389", aws)

    def test_azure_new_commands_present(self):
        az = self._all_cmd_text("azure")
        for needle in [
            "allowBlobPublicAccess",   # 퍼블릭 Blob
            "enableHttpsTrafficOnly",  # HTTPS 전용
            "minimumTlsVersion",       # TLS 버전
            "httpsOnly",               # App Service HTTPS
            "security pricing list",   # Defender 플랜 전체
            "identity==null",          # 관리 ID 미사용
        ]:
            self.assertIn(needle, az, f"Azure 명령어 누락: {needle}")

    def test_azure_nsg_port_commands_present(self):
        az = self._all_cmd_text("azure")
        self.assertIn("22", az)
        self.assertIn("3389", az)


if __name__ == "__main__":
    unittest.main()
