"""boto3 수집기 테스트.

boto3가 없는 환경(로컬/CI)에서는 available()=False 이고, collector.collect가
안전하게 CLI/목업으로 폴백해야 한다. boto3가 있으면 실제 수집을 시도한다.
실제 AWS 호출은 하지 않는다(available False 경로만 결정적으로 검증).
"""

import unittest

from autoauditor import collector, collector_boto3


class Boto3AvailabilityTest(unittest.TestCase):
    def test_available_returns_bool(self):
        self.assertIsInstance(collector_boto3.available(), bool)

    def test_collect_unavailable_shape(self):
        # boto3가 없으면 unavailable 구조를 반환(예외 없이)
        if not collector_boto3.available():
            r = collector_boto3.collect()
            self.assertEqual(r["source"], "unavailable")
            self.assertIn("text", r)
            self.assertIn("threat_text", r)


class CollectorFallbackTest(unittest.TestCase):
    def test_aws_collect_has_threat_text_key(self):
        # boto3 유무와 무관하게 반환 dict에 threat_text 키가 있어야 함
        r = collector.collect("aws", use_mock=True)
        self.assertIn("threat_text", r)
        self.assertIn("source", r)

    def test_placeholder_free_filter(self):
        # 자리표시자(<RG>, NSG_NAME 등)가 있는 명령은 자동 수집에서 제외
        self.assertTrue(collector._placeholder_free("aws ec2 describe-security-groups"))
        self.assertFalse(collector._placeholder_free("az sql db tde show -g <RG>"))
        self.assertFalse(collector._placeholder_free("aws s3api get-bucket-acl --bucket BUCKET_NAME"))

    def test_mock_still_works(self):
        r = collector.collect("aws", use_mock=True)
        self.assertEqual(r["source"], "mock")


class Boto3SafeWrapperTest(unittest.TestCase):
    def test_safe_returns_default_on_error(self):
        def boom():
            raise RuntimeError("권한 없음")
        self.assertEqual(collector_boto3._safe(boom, []), [])
        self.assertIsNone(collector_boto3._safe(boom))

    def test_safe_returns_value_on_success(self):
        self.assertEqual(collector_boto3._safe(lambda: [1, 2, 3], []), [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
