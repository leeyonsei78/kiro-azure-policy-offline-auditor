"""파일 바이트 인코딩 판별·디코딩(decode_bytes) 테스트.

폐쇄망에서 파일은 UTF-8 / UTF-16(LE·BE, BOM 유무) / cp949 등 다양하게 저장된다.
특히 Windows PowerShell `>` 리다이렉트는 BOM 없는 UTF-16LE를 만들어내는데,
브라우저 TextDecoder가 이를 감지 못해 한글·영어가 모두 깨지는 버그가 있었다.
서버(파이썬)에서 판별하도록 바꾼 뒤 그 정확도를 여기서 검증한다.
"""

import unittest

from auditor.parser import decode_bytes


class DecodeBytesTest(unittest.TestCase):
    SAMPLE = "SCDSA004 정책 검토 hello world 한글 테스트\n둘째 줄 line two 123"

    def _roundtrip(self, encoding_name, encoder):
        data = encoder(self.SAMPLE)
        text, label = decode_bytes(data)
        self.assertEqual(text, self.SAMPLE, f"{encoding_name} 복원 실패 (label={label})")
        return label

    def test_utf8(self):
        self._roundtrip("utf-8", lambda s: s.encode("utf-8"))

    def test_utf8_bom(self):
        label = self._roundtrip("utf-8-sig", lambda s: s.encode("utf-8-sig"))
        self.assertIn("BOM", label)

    def test_utf16le_with_bom(self):
        label = self._roundtrip("utf-16 (LE+BOM)", lambda s: s.encode("utf-16"))
        self.assertIn("utf-16-le", label)

    def test_utf16le_no_bom(self):
        # 이 케이스가 실제 버그의 원인(PowerShell 리다이렉트 기본값).
        label = self._roundtrip("utf-16-le (no BOM)", lambda s: s.encode("utf-16-le"))
        self.assertEqual(label, "utf-16-le")

    def test_utf16be_no_bom(self):
        label = self._roundtrip("utf-16-be (no BOM)", lambda s: s.encode("utf-16-be"))
        self.assertEqual(label, "utf-16-be")

    def test_cp949(self):
        label = self._roundtrip("cp949", lambda s: s.encode("cp949"))
        self.assertIn("cp949", label)

    def test_empty(self):
        text, label = decode_bytes(b"")
        self.assertEqual(text, "")
        self.assertEqual(label, "empty")

    def test_ascii_not_misdetected_as_utf16(self):
        # 순수 ASCII(널바이트 없음)는 UTF-8로 판별돼야 한다.
        data = b"just plain ascii text without any nulls"
        text, label = decode_bytes(data)
        self.assertEqual(text, data.decode("ascii"))
        self.assertEqual(label, "utf-8")


if __name__ == "__main__":
    unittest.main()
