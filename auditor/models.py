"""판정 결과 데이터 모델.

오프라인 엔진이 산출하는 단위 발견(Finding)과 심각도를 정의한다.
표준 라이브러리만 사용(폐쇄망 전제).
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """정렬/집계가 쉬운 정수 기반 심각도."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError:
            return cls.INFO


#: 심각도별 점수 감점 가중치(100점 만점에서 차감)
SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """단일 발견(이슈).

    Attributes:
        control_code: 매핑되는 ISMS-P 통제항목 코드(예: "2.6.1").
        control_domain: 통제 영역명.
        issue_type: 이슈 유형 키(예: "nsg_open_any", "sql_tde_disabled").
        severity: 심각도.
        title: 짧은 제목.
        evidence: 근거가 된 입력 내용(리소스명/규칙 텍스트 일부).
        description: 왜 문제인지 설명(ISMS-P 판단기준 기반).
        recommendation: 개선 방안(ISMS-P 개선방안 기반).
        resource: 관련 리소스 식별자(있으면).
        platform: 대상 클라우드 플랫폼("aws" | "azure").
        bad_example: 위반(취약) 설정 예시.
        good_example: 개선(안전) 설정 예시.
        why: 왜 문제인지(위험)를 초보 담당자도 이해하도록 쉽게 설명.
        how_to_fix: 해결 방안을 단계별(1,2,3…)로 안내하는 상세 설명.
        steps: 실제 변경 방법(포털 클릭 순서 + 복사해서 실행할 CLI 명령어)을 초보자가
               그대로 따라할 수 있도록 구체적으로 안내.
    """

    control_code: str
    control_domain: str
    issue_type: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    evidence: str = ""
    resource: str = ""
    platform: str = "azure"
    bad_example: str = ""
    good_example: str = ""
    why: str = ""
    how_to_fix: str = ""
    steps: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d


@dataclass
class AuditReport:
    """전체 점검 리포트."""

    findings: list[Finding] = field(default_factory=list)
    parsed_resources: int = 0
    input_kind: str = ""
    notes: list[str] = field(default_factory=list)

    def score(self) -> int:
        """100점 만점에서 심각도별 감점(하한 0)."""
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    def grade(self) -> str:
        s = self.score()
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 60:
            return "D"
        return "F"

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
        return counts

    def platform_counts(self) -> dict[str, int]:
        """플랫폼(aws/azure)별 이슈 건수."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.platform] = counts.get(f.platform, 0) + 1
        return counts

    def detected_platforms(self) -> list[str]:
        """발견된 이슈에 등장한 플랫폼 목록(정렬)."""
        return sorted(self.platform_counts().keys())

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score(),
            "grade": self.grade(),
            "input_kind": self.input_kind,
            "parsed_resources": self.parsed_resources,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts(),
            "platform_counts": self.platform_counts(),
            "detected_platforms": self.detected_platforms(),
            "findings": [
                f.to_dict()
                for f in sorted(self.findings, key=lambda x: x.severity, reverse=True)
            ],
            "notes": list(self.notes),
        }
