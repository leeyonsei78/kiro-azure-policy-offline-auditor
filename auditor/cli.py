"""명령줄 인터페이스 (폐쇄망 전용, 표준 라이브러리만).

사용:
  python -m auditor <파일.txt>              # 파일 검토 → 텍스트 리포트
  python -m auditor <파일.txt> --json       # JSON 리포트
  cat policy.txt | python -m auditor        # stdin 입력
  python -m auditor --controls              # ISMS-P 통제항목 목록 출력
  python -m auditor --web [--port 8080]     # 웹 UI 실행(auditor.webui로 위임)

종료 코드:
  0 = 이슈 없음, 1 = 이슈 발견(자동화 게이트용), 2 = 실행 오류
"""

from __future__ import annotations

import argparse
import json
import sys

from .engine import analyze
from .knowledge_base import all_controls
from .report import format_text


def _read_input(path: str | None) -> str:
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    # stdin
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _print_controls(as_json: bool) -> None:
    controls = all_controls()
    if as_json:
        print(json.dumps(controls, ensure_ascii=False, indent=2))
        return
    print(f"ISMS-P 클라우드 인프라 Azure 통제항목 {len(controls)}개")
    print("=" * 60)
    for c in controls:
        print(f"[{c['code']}] {c['domain']} — {c['desc']}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Azure 정책 오프라인 보안검토 (ISMS-P 기준, 폐쇄망 전용)",
    )
    parser.add_argument("file", nargs="?", help="검토할 Azure 정책/구성 txt 파일. 생략 시 stdin 사용")
    parser.add_argument("--json", action="store_true", help="JSON 리포트 출력")
    parser.add_argument("--controls", action="store_true", help="ISMS-P 통제항목 목록 출력 후 종료")
    parser.add_argument("--web", action="store_true", help="웹 UI 실행")
    parser.add_argument("--host", default="127.0.0.1", help="웹 UI 호스트(--web)")
    parser.add_argument("--port", type=int, default=8080, help="웹 UI 포트(--web)")
    args = parser.parse_args(argv)

    if args.web:
        from .webui import main as web_main
        return web_main(["--host", args.host, "--port", str(args.port)])

    if args.controls:
        _print_controls(args.json)
        return 0

    try:
        text = _read_input(args.file)
    except OSError as e:
        print(f"파일을 읽을 수 없습니다: {e}", file=sys.stderr)
        return 2

    if not text.strip():
        print("입력이 비었습니다. 파일 경로를 지정하거나 stdin으로 텍스트를 전달하세요.\n"
              "예) python -m auditor policy.txt   또는   cat policy.txt | python -m auditor",
              file=sys.stderr)
        return 2

    report = analyze(text)

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(format_text(report))

    # 이슈가 있으면 종료코드 1(자동화 파이프라인에서 게이트로 활용 가능)
    return 1 if report.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
