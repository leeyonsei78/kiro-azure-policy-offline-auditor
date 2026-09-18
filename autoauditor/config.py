"""자동 점검 에이전트 설정.

모든 설정은 환경변수(우선) 또는 명시적 인자로 받는다.
비밀값(Slack Webhook 등)은 절대 코드에 하드코딩하지 않는다.

주요 환경변수:
  AUTOAUDITOR_PLATFORM     aws | azure         (기본: aws)
  AUTOAUDITOR_SLACK_WEBHOOK Slack Incoming Webhook URL (없으면 알림 비활성)
  AUTOAUDITOR_ALERT_MIN_SEVERITY  알림 최소 심각도 (기본: HIGH)
  AUTOAUDITOR_OUTPUT_DIR   리포트 저장 폴더    (기본: ./autoaudit_out)
  AUTOAUDITOR_REMEDIATION  off | suggest | auto  (기본: suggest = 반자동)
  AUTOAUDITOR_DRY_RUN      true | false        (기본: true = 실제 변경 안 함)
  AUTOAUDITOR_PROTECT_TAGS 차단 금지(화이트리스트) 키워드, 쉼표구분 (예: prod-critical,dns)
  AUTOAUDITOR_USE_MOCK     true 면 CLI 대신 목업 데이터로 동작(테스트/데모)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "y")


def _env_list(name: str) -> list[str]:
    v = os.environ.get(name, "")
    return [x.strip() for x in v.split(",") if x.strip()]


# 대응 모드
REMEDIATION_OFF = "off"        # 차단 명령 생성 안 함(탐지·알림만)
REMEDIATION_SUGGEST = "suggest"  # 차단 명령을 '생성'만(사람이 검토·실행) — 기본
REMEDIATION_AUTO = "auto"      # 완전 자동(위험, 안전장치 필수)

_VALID_REMEDIATION = (REMEDIATION_OFF, REMEDIATION_SUGGEST, REMEDIATION_AUTO)


@dataclass
class Config:
    platform: str = "aws"
    slack_webhook: str = ""
    alert_min_severity: str = "HIGH"     # 이 이상만 Slack 알림(CRITICAL/HIGH/MEDIUM/LOW/INFO)
    output_dir: str = "./autoaudit_out"
    remediation: str = REMEDIATION_SUGGEST
    dry_run: bool = True
    protect_tags: list[str] = field(default_factory=list)  # 차단 금지 리소스 키워드
    use_mock: bool = False
    # 침해 탐지 임계값
    login_fail_threshold: int = 5        # 실패 로그인 N회 이상 → 무차별 대입 의심

    @classmethod
    def from_env(cls) -> "Config":
        plat = (os.environ.get("AUTOAUDITOR_PLATFORM", "aws") or "aws").lower()
        if plat not in ("aws", "azure"):
            plat = "aws"
        rem = (os.environ.get("AUTOAUDITOR_REMEDIATION", REMEDIATION_SUGGEST) or "").lower()
        if rem not in _VALID_REMEDIATION:
            rem = REMEDIATION_SUGGEST
        sev = (os.environ.get("AUTOAUDITOR_ALERT_MIN_SEVERITY", "HIGH") or "HIGH").upper()
        return cls(
            platform=plat,
            slack_webhook=os.environ.get("AUTOAUDITOR_SLACK_WEBHOOK", "").strip(),
            alert_min_severity=sev,
            output_dir=os.environ.get("AUTOAUDITOR_OUTPUT_DIR", "./autoaudit_out"),
            remediation=rem,
            dry_run=_env_bool("AUTOAUDITOR_DRY_RUN", True),
            protect_tags=_env_list("AUTOAUDITOR_PROTECT_TAGS"),
            use_mock=_env_bool("AUTOAUDITOR_USE_MOCK", False),
            login_fail_threshold=int(os.environ.get("AUTOAUDITOR_LOGIN_FAIL_THRESHOLD", "5") or "5"),
        )

    def redacted(self) -> dict:
        """로그 출력용(비밀값 마스킹)."""
        return {
            "platform": self.platform,
            "slack_webhook": ("설정됨" if self.slack_webhook else "(없음)"),
            "alert_min_severity": self.alert_min_severity,
            "output_dir": self.output_dir,
            "remediation": self.remediation,
            "dry_run": self.dry_run,
            "protect_tags": self.protect_tags,
            "use_mock": self.use_mock,
        }
