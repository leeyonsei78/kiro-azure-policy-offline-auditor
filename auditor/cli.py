"""명령줄 인터페이스 (폐쇄망 전용, 표준 라이브러리만).

사용:
  python -m auditor <파일.txt>              # 파일 검토 → 텍스트 리포트
  python -m auditor <파일.txt> --json       # JSON 리포트
  python -m auditor <파일.txt> --csv --out result.csv    # CSV(엑셀)로 저장
  python -m auditor <파일.txt> --html --out report.html  # HTML(인쇄→PDF)로 저장
  python -m auditor <파일.txt> --xlsx --out report.xlsx  # 엑셀(.xlsx)로 저장(데이터 손실 없음)
  cat policy.txt | python -m auditor        # stdin 입력
  python -m auditor --controls              # ISMS-P 통제항목 목록 출력
  python -m auditor --commands              # 정보 수집 CLI 명령어(기본 AWS+Azure)
  python -m auditor --commands --platform aws   # AWS 수집 명령어만
  python -m auditor --script --platform azure --out collect-azure.sh       # 일괄 수집 스크립트(bash)
  python -m auditor --script --platform azure --shell ps1 --out collect.ps1  # PowerShell 스크립트
  python -m auditor --web [--port 8080]     # 웹 UI 실행(auditor.webui로 위임)

종료 코드:
  0 = 이슈 없음, 1 = 이슈 발견(자동화 게이트용), 2 = 실행 오류
"""

from __future__ import annotations

import argparse
import json
import sys

from .engine import analyze
from .collector_script import build_script, script_filename
from .knowledge_base import all_controls, collection_commands
from .report import format_csv, format_html, format_text, format_xlsx


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
    print(f"ISMS-P 클라우드 인프라 통제항목 (AWS/Azure) {len(controls)}개")
    print("=" * 60)
    for c in controls:
        print(f"[{c['code']}] {c['domain']} — {c['desc']}")


_PLAT_LABEL = {"aws": "AWS", "azure": "Azure"}


def _print_commands(platform: str | None, as_json: bool) -> None:
    """정보 수집 CLI 명령어 가이드 출력. platform 미지정 시 AWS+Azure 모두."""
    plats = [platform] if platform in ("aws", "azure") else ["aws", "azure"]
    if as_json:
        print(json.dumps({p: collection_commands(p) for p in plats}, ensure_ascii=False, indent=2))
        return
    for p in plats:
        cmds = collection_commands(p)
        print("=" * 64)
        print(f" [{_PLAT_LABEL[p]}] 정보 수집 명령어 가이드 (ISMS-P {len(cmds)}개 통제항목)")
        print("=" * 64)
        for c in cmds:
            print(f"\n[{c['code']}] {c['domain']} — {c['desc']}")
            for ln in c["cmd_lines"]:
                print(f"  $ {ln}")
            if c["criteria"]:
                print(f"  ⚠️ 확인 포인트: {c['criteria']}")
        print()
    print("※ <NSG>·<RG>·<BUCKET> 등 자리표시자는 실제 값으로 바꿔 사용하세요.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="클라우드 정책 오프라인 보안검토 (ISMS-P 기준, AWS/Azure, 폐쇄망 전용)",
    )
    parser.add_argument("file", nargs="?", help="검토할 AWS/Azure 정책·구성 txt 파일. 생략 시 stdin 사용")
    parser.add_argument("--json", action="store_true", help="JSON 리포트 출력")
    parser.add_argument("--csv", action="store_true", help="CSV(엑셀용) 리포트 출력")
    parser.add_argument("--html", action="store_true", help="HTML 리포트 출력(브라우저 인쇄로 PDF 저장)")
    parser.add_argument("--xlsx", action="store_true", help="엑셀(.xlsx) 리포트 저장(--out 필수)")
    parser.add_argument("--out", "-o", metavar="FILE", help="결과를 파일로 저장(미지정 시 화면 출력)")
    parser.add_argument("--controls", action="store_true", help="ISMS-P 통제항목 목록 출력 후 종료")
    parser.add_argument("--commands", action="store_true",
                        help="정보 수집 CLI 명령어 가이드 출력 후 종료")
    parser.add_argument("--platform", choices=["aws", "azure"],
                        help="--commands/--script 대상 플랫폼(--commands 미지정 시 AWS+Azure 모두, --script 미지정 시 azure)")
    parser.add_argument("--script", action="store_true",
                        help="장비/서비스별 일괄 수집 스크립트 생성 후 출력/저장")
    parser.add_argument("--shell", choices=["bash", "ps1"], default="bash",
                        help="--script 셸 종류(bash 기본, PowerShell은 ps1)")
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

    if args.commands:
        _print_commands(args.platform, args.json)
        return 0

    if args.script:
        platform = args.platform or "azure"
        content = build_script(platform, args.shell)
        if args.out:
            try:
                with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(content)
            except OSError as e:
                print(f"파일 저장 실패: {e}", file=sys.stderr)
                return 2
            print(f"저장 완료: {args.out}  (권장 파일명: {script_filename(platform, args.shell)})",
                  file=sys.stderr)
        else:
            print(content)
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

    # --- 엑셀(.xlsx)은 바이너리 → --out 필수, 별도 처리 ---
    if args.xlsx:
        if not args.out:
            print("--xlsx 는 바이너리 파일이라 --out(-o) 저장 경로가 필요합니다.\n"
                  "예) python -m auditor policy.txt --xlsx --out report.xlsx", file=sys.stderr)
            return 2
        out = args.out if args.out.lower().endswith(".xlsx") else args.out + ".xlsx"
        try:
            with open(out, "wb") as fh:
                fh.write(format_xlsx(report))
        except OSError as e:
            print(f"파일 저장 실패: {e}", file=sys.stderr)
            return 2
        print(f"저장 완료: {out}  (이슈 {len(report.findings)}건, 점수 {report.score()}/100 {report.grade()})",
              file=sys.stderr)
        return 1 if report.findings else 0

    # 출력 포맷 선택 (우선순위: csv > html > json > text)
    if args.csv:
        content = format_csv(report)
    elif args.html:
        content = format_html(report)
    elif args.json:
        content = json.dumps(report.to_dict(), ensure_ascii=False, indent=2)
    else:
        content = format_text(report)

    if args.out:
        # CSV는 BOM이 문자열에 이미 포함되어 있으므로 utf-8로 그대로 기록
        try:
            with open(args.out, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
        except OSError as e:
            print(f"파일 저장 실패: {e}", file=sys.stderr)
            return 2
        print(f"저장 완료: {args.out}  (이슈 {len(report.findings)}건, 점수 {report.score()}/100 {report.grade()})",
              file=sys.stderr)
    else:
        print(content)

    # 이슈가 있으면 종료코드 1(자동화 파이프라인에서 게이트로 활용 가능)
    return 1 if report.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
