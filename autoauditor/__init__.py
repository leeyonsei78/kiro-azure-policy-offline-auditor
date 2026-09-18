"""클라우드 보안 자동 점검 에이전트 (AWS/Azure).

수동 도구(auditor 패키지)의 분석 엔진을 재사용해, 클라우드에서 주기적으로:
  1) 리소스 구성을 자동 수집(collector)
  2) 오프라인 엔진으로 위험 분석(auditor.engine)
  3) 침해 징후 탐지·상관분석(threat)
  4) 심각/복합위험/침해 시 Slack 알림(notifier)
  5) 리포트 자동 생성·보관(reporter)
  6) 차단/대응 명령을 안전하게 생성(remediation, 기본 반자동)
하도록 오케스트레이션(orchestrator)한다.

설계 원칙:
- 표준 라이브러리 위주(폐쇄망·Lambda 기본 런타임에서 추가 설치 최소화).
- 자동 차단은 기본 '명령 생성(반자동)'이며, 완전 자동은 명시적 옵션 + 안전장치(드라이런/
  화이트리스트/롤백) 없이는 동작하지 않는다.
- 어떤 비밀값(Slack Webhook 등)도 코드에 하드코딩하지 않고 환경변수/설정으로 받는다.
"""

from __future__ import annotations

__version__ = "0.1.0"
