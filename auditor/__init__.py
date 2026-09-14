"""Azure 정책 오프라인 보안검토 도구 (폐쇄망 전용).

Azure CLI(`az ...`)로 추출한 정책/구성 텍스트를 인터넷 없이 분석해,
ISMS-P 클라우드 인프라 통제항목 기준으로 이슈·취약점을 찾고 개선안을 제안한다.

- knowledge_base: ISMS-P Azure 17개 통제항목 데이터
- models: Finding / AuditReport / Severity
- parser: 입력 txt(JSON/table/키밸류 혼합) 파싱
- engine: 오프라인 판정 엔진
- report: 텍스트/JSON 리포트 포매팅
"""

from __future__ import annotations

__version__ = "0.1.0"
