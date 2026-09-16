"""일괄 정보 수집 스크립트 생성기.

클라우드별(AWS/Azure)로, 장비/서비스 그룹별 섹션으로 나눈 수집 스크립트를 만든다.
스크립트를 관리망 PC에서 실행하면 각 점검 명령의 결과가 out/ 폴더에 JSON으로 저장되고,
그 폴더(또는 zip)를 이 프로그램의 '보안검토' 탭에 업로드하면 자동 검토된다.

- azure: bash(`az`) 또는 PowerShell(`.ps1`)
- aws:   bash(`aws`)

각 섹션 상단에 '장비: XXX' 주석과 실행 안내를 넣고, 스크립트 맨 위에는 로그인·실행·
업로드 절차를 안내한다. 자리표시자(<RG>, <SERVER> 등)는 사용자가 실제 값으로 채운다.
"""

from __future__ import annotations

import re

from .knowledge_base import collection_commands

_PLAT_LABEL = {"aws": "AWS", "azure": "Azure"}


def _slug(text: str) -> str:
    """서비스 그룹명 → 파일명 안전한 ascii slug."""
    mapping = {
        "네트워크(NSG/방화벽)": "network", "네트워크(보안그룹)": "network",
        "IAM/Entra ID": "iam", "IAM": "iam",
        "Storage": "storage", "S3/스토리지": "storage",
        "Key Vault": "keyvault", "KMS": "kms",
        "SQL Database": "sql", "RDS": "rds",
        "모니터링/로그": "monitoring", "CloudTrail/로그": "cloudtrail",
        "거버넌스(Policy/관리그룹)": "governance", "거버넌스(Organizations/Config)": "governance",
        "패치/업데이트": "patch", "패치(SSM)": "patch",
        "Defender for Cloud": "defender", "GuardDuty/Inspector": "guardduty",
        "백업/재해복구": "backup", "기타": "etc",
    }
    if text in mapping:
        return mapping[text]
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return s or "etc"


def _group_by_service(platform: str) -> list[tuple[str, list[dict]]]:
    """(service, [항목,...]) 목록. 등장 순서 유지."""
    groups: dict[str, list[dict]] = {}
    order: list[str] = []
    for c in collection_commands(platform):
        svc = c.get("service", "기타")
        if svc not in groups:
            groups[svc] = []
            order.append(svc)
        groups[svc].append(c)
    return [(s, groups[s]) for s in order]


# ---------------------------------------------------------------------------
# bash (Azure az / AWS aws)
# ---------------------------------------------------------------------------
def _build_bash(platform: str) -> str:
    label = _PLAT_LABEL[platform]
    cli = "az" if platform == "azure" else "aws"
    login = "az login" if platform == "azure" else "aws configure  # 또는 aws sso login"
    lines: list[str] = []
    a = lines.append

    a("#!/usr/bin/env bash")
    a("# ============================================================")
    a(f"#  {label} 보안 점검 정보 일괄 수집 스크립트 (ISMS-P)")
    a("# ============================================================")
    a("#  [사용 방법]")
    a(f"#   1) {label} CLI 설치 및 로그인:  {login}")
    a("#   2) 조회 권한(읽기 전용) 계정으로 로그인되어 있어야 합니다.")
    a("#   3) 아래 자리표시자(<RG>,<SERVER>,<DB>,<NSG>,<BUCKET> 등)를")
    a("#      실제 값으로 바꾸거나, 반복이 필요하면 각 섹션을 복제해 사용하세요.")
    a("#   4) 실행:   chmod +x collect.sh && ./collect.sh    (또는  bash collect.sh)")
    a("#   5) 결과는 ./out/ 폴더에 서비스별 JSON으로 저장됩니다.")
    a("#   6) out 폴더를 zip으로 묶어 프로그램 '보안검토' 탭에 업로드하세요:")
    a("#         (Linux/mac) zip -r out.zip out")
    a("#      또는 out/ 안의 .json 파일들의 내용을 이어붙여 텍스트로 붙여넣어도 됩니다.")
    a("# ============================================================")
    a("")
    a('OUT="./out"')
    a('mkdir -p "$OUT"')
    a("")
    a("# 각 명령 실패해도 계속 진행(자리표시자 미치환 등)")
    a("run() {  # run <파일명> <명령...>")
    a('  local f="$OUT/$1"; shift')
    a('  echo "[수집] $* -> $f"')
    a('  "$@" > "$f" 2>"$f.err" || echo "  (건너뜀/오류: $f.err 확인)"')
    a("}")
    a("")

    for svc, items in _group_by_service(platform):
        slug = _slug(svc)
        a("# ------------------------------------------------------------")
        a(f"# 장비/서비스: {svc}")
        a(f"#   이 섹션의 명령을 실행해 {svc} 관련 구성을 수집합니다.")
        a("# ------------------------------------------------------------")
        n = 0
        for it in items:
            a(f"#  [{it['code']}] {it['desc']}")
            for cmd in it["cmd_lines"]:
                # bash에서 결과를 JSON 파일로: 명령이 cli로 시작하면 run으로 감싸기
                if cmd.startswith(cli + " "):
                    n += 1
                    fname = f"{slug}_{it['code'].replace('.', '_')}_{n}.json"
                    a(f'run "{fname}" {cmd}')
                else:
                    a(f"#   (참고) {cmd}")
        a("")

    a('echo "완료: $OUT 폴더의 JSON을 zip으로 묶어 업로드하세요."')
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# PowerShell (Azure)
# ---------------------------------------------------------------------------
def _build_ps1(platform: str) -> str:
    label = _PLAT_LABEL[platform]
    cli = "az" if platform == "azure" else "aws"
    login = "az login" if platform == "azure" else "aws configure"
    lines: list[str] = []
    a = lines.append

    a("# ============================================================")
    a(f"#  {label} 보안 점검 정보 일괄 수집 스크립트 (ISMS-P) - PowerShell")
    a("# ============================================================")
    a("#  [사용 방법]")
    a(f"#   1) {label} CLI 로그인:  {login}")
    a("#   2) 조회 권한(읽기 전용) 계정으로 로그인되어 있어야 합니다.")
    a("#   3) 자리표시자(<RG>,<SERVER>,<DB>,<NSG> 등)를 실제 값으로 바꾸세요.")
    a("#   4) 실행(PowerShell):")
    a("#         Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force")
    a("#         .\\collect.ps1")
    a("#   5) 결과는 .\\out\\ 폴더에 서비스별 JSON으로 저장됩니다.")
    a("#   6) out 폴더를 압축해 프로그램 '보안검토' 탭에 업로드하세요:")
    a("#         Compress-Archive -Path .\\out\\* -DestinationPath out.zip -Force")
    a("# ============================================================")
    a("")
    a('$OUT = ".\\out"')
    a('New-Item -ItemType Directory -Force -Path $OUT | Out-Null')
    a("")
    a("function Run($fname, $cmd) {")
    a('  Write-Host "[수집] $cmd -> $OUT\\$fname"')
    a('  try { Invoke-Expression "$cmd" | Out-File -Encoding utf8 "$OUT\\$fname" }')
    a('  catch { Write-Host "  (건너뜀/오류): $_" }')
    a("}")
    a("")

    for svc, items in _group_by_service(platform):
        slug = _slug(svc)
        a("# ------------------------------------------------------------")
        a(f"# 장비/서비스: {svc}")
        a("# ------------------------------------------------------------")
        n = 0
        for it in items:
            a(f"#  [{it['code']}] {it['desc']}")
            for cmd in it["cmd_lines"]:
                if cmd.startswith(cli + " "):
                    n += 1
                    fname = f"{slug}_{it['code'].replace('.', '_')}_{n}.json"
                    esc = cmd.replace('"', '`"')
                    a(f'Run "{fname}" "{esc}"')
                else:
                    a(f"#   (참고) {cmd}")
        a("")

    a('Write-Host "완료: out 폴더를 압축해 업로드하세요."')
    return "\n".join(lines) + "\n"


def build_script(platform: str = "azure", shell: str = "bash") -> str:
    """수집 스크립트 텍스트 생성.

    platform: 'aws' | 'azure'
    shell:    'bash' | 'ps1'  (aws는 bash만 권장하나 ps1도 생성 가능)
    """
    platform = platform if platform in ("aws", "azure") else "azure"
    if shell == "ps1":
        return _build_ps1(platform)
    return _build_bash(platform)


def script_filename(platform: str, shell: str) -> str:
    ext = "ps1" if shell == "ps1" else "sh"
    return f"collect-{platform}.{ext}"
