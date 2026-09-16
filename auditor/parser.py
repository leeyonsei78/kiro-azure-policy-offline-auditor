"""입력 txt 파서 (폐쇄망 전제, 표준 라이브러리만).

Azure CLI(`az ...`) 출력은 형식이 제각각이다:
  - `-o json`  : JSON 배열/객체
  - `-o table` : 헤더 + 공백정렬 행
  - `-o tsv`   : 탭 구분
  - 여러 명령 출력이 한 파일에 이어붙어 있을 수도 있음(사용자가 정책을 모두 모아 붙임)

이 파서는 입력 전체 텍스트를 받아서:
  1) JSON 블록들을 최대한 추출해 파이썬 객체 리스트로,
  2) JSON이 아닌 부분은 원시 텍스트(raw)로 보존해
엔진이 둘 다 활용하도록 (blocks, raw_text)를 돌려준다.

관대한 파싱: 한 조각이 깨져도 나머지는 살린다(실무 붙여넣기 입력이 지저분하기 때문).
"""

from __future__ import annotations

import json
import re
from typing import Any


def _try_json(text: str) -> Any | None:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _extract_json_blocks(text: str) -> list[Any]:
    """텍스트 안에서 최상위 JSON 배열/객체 블록들을 균형 괄호로 스캔해 추출."""
    blocks: list[Any] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "[{":
            close = "]" if ch == "[" else "}"
            depth = 0
            in_str = False
            esc = False
            j = i
            while j < n:
                c = text[j]
                if in_str:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == '"':
                        in_str = False
                else:
                    if c == '"':
                        in_str = True
                    elif c in "[{":
                        depth += 1
                    elif c in "]}":
                        depth -= 1
                        if depth == 0:
                            break
                j += 1
            candidate = text[i : j + 1]
            obj = _try_json(candidate)
            if obj is not None:
                blocks.append(obj)
                i = j + 1
                continue
        i += 1
    return blocks


def _flatten(obj: Any) -> list[dict]:
    """JSON 블록을 dict 리스트로 평탄화(배열이면 원소들, 객체면 자신)."""
    out: list[dict] = []
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, list):
                out.extend(_flatten(item))
    elif isinstance(obj, dict):
        out.append(obj)
    return out


def parse(text: str) -> dict:
    """입력 텍스트를 파싱해 엔진이 쓸 구조를 반환.

    반환:
      {
        "kind": "json" | "text" | "mixed",
        "objects": [dict, ...],   # JSON에서 추출한 리소스 객체들
        "raw_text": str,          # 전체 원시 텍스트(정규식 검사용)
        "object_count": int,
      }
    """
    text = text or ""
    # 1) 전체가 하나의 JSON이면 바로
    whole = _try_json(text)
    blocks: list[Any] = []
    if whole is not None:
        blocks = [whole]
    else:
        blocks = _extract_json_blocks(text)

    objects: list[dict] = []
    for b in blocks:
        objects.extend(_flatten(b))

    if objects and not re.search(r"[A-Za-z]{3,}\s{2,}[A-Za-z]", text):
        kind = "json"
    elif objects:
        kind = "mixed"
    else:
        kind = "text"

    return {
        "kind": kind,
        "objects": objects,
        "raw_text": text,
        "object_count": len(objects),
    }


def iter_dicts(obj: Any):
    """중첩 dict/list를 재귀적으로 순회하며 모든 dict를 yield(엔진 편의)."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from iter_dicts(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_dicts(item)



# --------------------------------------------------------------------------
# 바이트 → 텍스트 디코딩 (파일 업로드/불러오기용)
# --------------------------------------------------------------------------
# 폐쇄망 환경에서는 파일이 여러 인코딩으로 저장된다:
#   - UTF-8 (BOM 있음/없음)
#   - UTF-16 LE / BE (BOM 있음/없음)  ← Windows PowerShell `>` 리다이렉트 기본값
#   - cp949(euc-kr) : 한글 Windows 레거시
# 브라우저 TextDecoder는 BOM 없는 UTF-16을 감지하지 못하고 euc-kr 미지원
# 브라우저도 있어, 서버(파이썬)에서 판별·디코딩한다.


def _looks_like_utf16(data: bytes) -> str | None:
    """BOM 없는 UTF-16을 널바이트 패턴으로 추정. 'le'/'be'/None 반환."""
    if len(data) < 4:
        return None
    # ASCII 위주 텍스트를 UTF-16으로 저장하면 널바이트가 대량 발생한다.
    sample = data[:4096]
    nulls = sample.count(0)
    if nulls < len(sample) * 0.15:
        return None  # 널바이트가 적으면 UTF-16 아님(UTF-8/cp949)

    # 짝수/홀수 위치의 널바이트 분포로 LE/BE 구분.
    even_nulls = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
    odd_nulls = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
    # LE: 상위바이트(홀수 위치)가 0 → "A" = 41 00
    # BE: 하위바이트(짝수 위치)가 0 → "A" = 00 41
    if odd_nulls > even_nulls:
        return "le"
    if even_nulls > odd_nulls:
        return "be"
    return "le"  # 애매하면 Windows 기본값(LE)


def decode_bytes(data: bytes) -> tuple[str, str]:
    """파일 바이트를 텍스트로 디코딩. (text, encoding_label) 반환.

    감지 순서:
      1) BOM 검사 (UTF-8-SIG, UTF-16 LE/BE)
      2) BOM 없는 UTF-16 추정 (널바이트 패턴)
      3) 엄격 UTF-8 시도
      4) cp949(한글 Windows) 시도
      5) 최후: UTF-8 + 대체문자(손실 허용)
    """
    if not data:
        return "", "empty"

    # 1) BOM
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8 (BOM)"
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16"), "utf-16-le (BOM)"
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16"), "utf-16-be (BOM)"

    # 2) BOM 없는 UTF-16
    guess = _looks_like_utf16(data)
    if guess == "le":
        try:
            return data.decode("utf-16-le"), "utf-16-le"
        except UnicodeDecodeError:
            pass
    elif guess == "be":
        try:
            return data.decode("utf-16-be"), "utf-16-be"
        except UnicodeDecodeError:
            pass

    # 3) 엄격 UTF-8
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass

    # 4) cp949 (한글 Windows 레거시)
    try:
        return data.decode("cp949"), "cp949 (euc-kr)"
    except UnicodeDecodeError:
        pass

    # 5) 최후: 손실 허용
    return data.decode("utf-8", errors="replace"), "utf-8 (일부 손실)"
