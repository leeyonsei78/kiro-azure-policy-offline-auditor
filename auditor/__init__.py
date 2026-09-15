"""클라우드 정책 오프라인 보안검토 도구 (AWS/Azure, 폐쇄망 전용).

AWS(`aws ...`)/Azure(`az ...`) CLI로 추출한 정책·구성 텍스트를 인터넷 없이 분석해,
ISMS-P 클라우드 인프라 통제항목 기준으로 이슈·취약점을 찾고 개선안을 제안한다.
플랫폼(aws/azure)은 자동으로 구별해 표시한다.

- knowledge_base: ISMS-P 17개 통제항목(플랫폼별 AWS/Azure 판단기준·개선안) 데이터
- models: Finding / AuditReport / Severity (platform 포함)
- parser: 입력 txt(JSON/table/키밸류 혼합) 파싱
- engine: 오프라인 판정 엔진(플랫폼 자동감지 + AWS/Azure 검사기)
- report: 텍스트/CSV/HTML 리포트 포매팅
"""

from __future__ import annotations

__version__ = "0.2.0"
