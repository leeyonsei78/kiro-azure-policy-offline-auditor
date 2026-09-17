"""발표용 통계 집계·차트 테스트.

- build_statistics: 심각도/플랫폼/영역/위치/MITRE별 카운트
- format_html: SVG 도넛 + 가로막대 차트 포함
- 빈 결과에서도 안전
"""

import json
import unittest

from auditor.engine import analyze, build_statistics
from auditor.report import format_html


def _report(objs):
    return analyze(json.dumps(objs)).to_dict()


_SAMPLE = [
    {"name": "r1", "resourceGroup": "rg-prod",
     "id": "/subscriptions/s1/resourceGroups/rg-prod/providers/"
           "Microsoft.Network/networkSecurityGroups/nsg1/securityRules/r1",
     "sourceAddressPrefix": "*", "destinationPortRange": "3389",
     "access": "Allow", "direction": "Inbound"},
    {"name": "stg1", "resourceGroup": "rg-data",
     "id": "/subscriptions/s1/resourceGroups/rg-data/providers/"
           "Microsoft.Storage/storageAccounts/stg1",
     "allowBlobPublicAccess": True, "supportsHttpsTrafficOnly": False},
    {"GroupId": "sg-1", "VpcId": "vpc-9", "OwnerId": "111",
     "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
]


class BuildStatisticsTest(unittest.TestCase):
    def setUp(self):
        self.st = build_statistics(_report(_SAMPLE))

    def test_has_all_sections(self):
        for k in ("total", "severity", "platform", "domain", "location", "mitre"):
            self.assertIn(k, self.st)

    def test_total_matches(self):
        self.assertEqual(self.st["total"], len(_report(_SAMPLE)["findings"]))

    def test_severity_counts_sum(self):
        s = sum(x["value"] for x in self.st["severity"])
        self.assertEqual(s, self.st["total"])

    def test_severity_order_fixed(self):
        # 심각도는 CRITICAL→INFO 순서를 유지(값 큰 순이 아님)
        order = [x["label"] for x in self.st["severity"]]
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranks = [rank[l] for l in order]
        self.assertEqual(ranks, sorted(ranks))

    def test_platform_split(self):
        labels = {x["label"] for x in self.st["platform"]}
        self.assertTrue({"AWS", "Azure"} & labels)

    def test_location_present(self):
        locs = [x["label"] for x in self.st["location"]]
        self.assertTrue(any("rg-prod" in x or "rg-data" in x or "vpc-9" in x for x in locs))

    def test_bars_sorted_desc(self):
        vals = [x["value"] for x in self.st["domain"]]
        self.assertEqual(vals, sorted(vals, reverse=True))

    def test_empty_report_safe(self):
        st = build_statistics(_report([]))
        self.assertEqual(st["total"], 0)
        self.assertEqual(st["severity"], [])


class HtmlChartTest(unittest.TestCase):
    def test_html_contains_charts(self):
        h = format_html(analyze(json.dumps(_SAMPLE)))
        self.assertIn("📊 통계 요약", h)
        self.assertIn("<svg", h)                 # 도넛 SVG
        self.assertIn("stroke-dasharray", h)     # 도넛 세그먼트
        self.assertIn("chbfill", h)              # 가로막대

    def test_html_no_charts_when_empty(self):
        # 이슈 없으면 통계 차트 섹션이 없어야(오류도 없어야)
        h = format_html(analyze(""))
        self.assertNotIn("📊 통계 요약", h)


if __name__ == "__main__":
    unittest.main()
