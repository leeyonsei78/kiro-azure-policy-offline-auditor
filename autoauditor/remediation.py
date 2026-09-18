"""차단/대응(remediation) 명령 생성 — 안전 우선.

이슈(취약 구성)와 침해 이벤트(악성 IP 등)에 대한 차단/대응 CLI 명령을 '생성'한다.
기본은 반자동(suggest): 명령을 만들어 사람이 검토·실행. 완전 자동(auto)은
안전장치를 모두 통과할 때만, 그리고 dry_run이 아닐 때만 실제 실행한다.

안전장치:
  - 화이트리스트(protect_tags): 대상 문자열에 보호 키워드가 있으면 절대 손대지 않음
  - dry_run: 실제 변경 없이 '실행했을 명령'만 기록(기본 True)
  - rollback: 각 조치에 되돌리기 명령을 함께 생성
  - 파괴적 작업 금지: 삭제(delete/terminate) 계열은 생성하지 않고, '제한/비활성/차단'만
표준 라이브러리만 사용.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field, asdict

from .config import REMEDIATION_OFF, REMEDIATION_SUGGEST, REMEDIATION_AUTO


@dataclass
class RemediationAction:
    title: str                    # 사람이 읽는 조치 설명
    platform: str                 # aws | azure
    command: str                  # 실행할(또는 제안할) CLI 명령
    rollback: str = ""            # 되돌리기 명령
    target: str = ""              # 대상 리소스/IP(로그용)
    reason: str = ""              # 왜 이 조치를 하는지
    destructive: bool = False     # 파괴적(삭제 등) 여부 — True면 자동 실행 절대 금지
    status: str = "suggested"     # suggested | skipped_protected | dry_run | executed | failed
    result: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _protected(target: str, protect_tags: list[str]) -> bool:
    t = (target or "").lower()
    return any(tag.lower() in t for tag in (protect_tags or []) if tag)


# ---------------------------------------------------------------------------
# 이슈(취약 구성) → 대응 명령
# ---------------------------------------------------------------------------
def _actions_for_finding(f: dict) -> list[RemediationAction]:
    it = f.get("issue_type", "")
    plat = f.get("platform", "aws")
    res = f.get("resource", "")
    loc = f.get("location", "")
    out: list[RemediationAction] = []

    if it == "aws_sg_open_sensitive_port" or it == "aws_sg_open_any":
        # 0.0.0.0/0 인바운드 규칙 회수(포트는 예시 22, 실제는 검토 필요)
        out.append(RemediationAction(
            title=f"보안그룹 {res} 전체공개 인바운드 규칙 회수",
            platform="aws",
            command=(f"aws ec2 revoke-security-group-ingress --group-id {res} "
                     f"--protocol tcp --port 22 --cidr 0.0.0.0/0"),
            rollback=(f"aws ec2 authorize-security-group-ingress --group-id {res} "
                      f"--protocol tcp --port 22 --cidr <원래CIDR>"),
            target=res, reason="관리포트가 인터넷 전체에 열려 있어 회수", destructive=False,
        ))
    elif it == "aws_rds_public":
        out.append(RemediationAction(
            title=f"RDS {res} 퍼블릭 접근 비활성화",
            platform="aws",
            command=f"aws rds modify-db-instance --db-instance-identifier {res} --no-publicly-accessible --apply-immediately",
            rollback=f"aws rds modify-db-instance --db-instance-identifier {res} --publicly-accessible --apply-immediately",
            target=res, reason="DB 인터넷 노출 차단",
        ))
    elif it in ("aws_s3_public_block_off", "aws_s3_public_policy"):
        out.append(RemediationAction(
            title=f"S3 버킷 {res} 퍼블릭 액세스 차단",
            platform="aws",
            command=(f"aws s3api put-public-access-block --bucket {res} "
                     "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                     "BlockPublicPolicy=true,RestrictPublicBuckets=true"),
            rollback=(f"aws s3api put-public-access-block --bucket {res} "
                      "--public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,"
                      "BlockPublicPolicy=false,RestrictPublicBuckets=false"),
            target=res, reason="버킷 퍼블릭 노출 차단",
        ))
    elif it == "storage_public_blob":
        out.append(RemediationAction(
            title=f"Storage {res} 퍼블릭 Blob 접근 비활성화",
            platform="azure",
            command=f"az storage account update -g <RG> -n {res} --allow-blob-public-access false",
            rollback=f"az storage account update -g <RG> -n {res} --allow-blob-public-access true",
            target=(res + " " + loc), reason="익명 Blob 접근 차단",
        ))
    elif it == "storage_https_disabled":
        out.append(RemediationAction(
            title=f"Storage {res} 보안 전송(HTTPS) 강제",
            platform="azure",
            command=f"az storage account update -g <RG> -n {res} --https-only true --min-tls-version TLS1_2",
            rollback=f"az storage account update -g <RG> -n {res} --https-only false",
            target=(res + " " + loc), reason="평문 전송 차단",
        ))
    elif it == "sql_public_access":
        out.append(RemediationAction(
            title=f"SQL 서버 {res} 퍼블릭 네트워크 접근 차단",
            platform="azure",
            command=f"az sql server update -g <RG> -n {res} --set publicNetworkAccess=Disabled",
            rollback=f"az sql server update -g <RG> -n {res} --set publicNetworkAccess=Enabled",
            target=(res + " " + loc), reason="DB 인터넷 노출 차단",
        ))
    return out


# ---------------------------------------------------------------------------
# 침해 이벤트(악성 IP 등) → 차단 명령
# ---------------------------------------------------------------------------
def _actions_for_threat(t: dict) -> list[RemediationAction]:
    plat = t.get("platform", "aws")
    ip = t.get("source_ip", "")
    out: list[RemediationAction] = []
    if not ip:
        return out
    if plat == "aws":
        # NACL/보안그룹 직접 수정은 부작용이 커서, WAF IPSet·Network Firewall 규칙 권장.
        out.append(RemediationAction(
            title=f"악성 IP {ip} 차단(WAF IPSet에 추가)",
            platform="aws",
            command=(f"aws wafv2 update-ip-set --name blocklist --scope REGIONAL "
                     f"--id <IPSET_ID> --lock-token <TOKEN> --addresses {ip}/32"),
            rollback=f"aws wafv2 update-ip-set --name blocklist --scope REGIONAL --id <IPSET_ID> --lock-token <TOKEN> (해당 IP 제외)",
            target=ip, reason="침해 출발지 IP 차단",
        ))
    else:
        out.append(RemediationAction(
            title=f"악성 IP {ip} 차단(NSG 인바운드 Deny 규칙 추가)",
            platform="azure",
            command=(f"az network nsg rule create -g <RG> --nsg-name <NSG> -n deny-{ip.replace('.', '-')} "
                     f"--priority 100 --access Deny --direction Inbound --source-address-prefixes {ip}/32 "
                     f"--destination-port-ranges '*' --protocol '*'"),
            rollback=f"az network nsg rule delete -g <RG> --nsg-name <NSG> -n deny-{ip.replace('.', '-')}",
            target=ip, reason="침해 출발지 IP 차단",
        ))
    return out


def _maybe_execute(a: RemediationAction, cfg) -> None:
    """auto 모드 + dry_run 아님 + 자리표시자 없음일 때만 실제 실행(안전 통과 후)."""
    if cfg.dry_run or "<" in a.command:
        a.status = "dry_run"
        return
    if a.destructive:
        a.status = "skipped_protected"
        a.result = "파괴적 작업은 자동 실행하지 않음"
        return
    # 보안: 셸 메타문자(파이프/리다이렉트/명령연결)가 있으면 자동 실행 거부.
    # 정상 차단 명령에는 이런 문자가 없으므로, 있으면 비정상으로 보고 수동 검토로 넘긴다.
    if any(ch in a.command for ch in ("|", "&", ";", ">", "<", "`", "$(")):
        a.status = "skipped_protected"
        a.result = "셸 메타문자 포함 명령은 자동 실행하지 않음(수동 검토)"
        return
    try:
        # shell=False(기본) + shlex 토큰화 — 셸을 거치지 않아 인젝션 위험 없음
        args = shlex.split(a.command)
        if not args:
            a.status = "failed"
            a.result = "빈 명령"
            return
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0:
            a.status = "executed"
            a.result = (proc.stdout or "").strip()[:200]
        else:
            a.status = "failed"
            a.result = (proc.stderr or "").strip()[:200]
    except Exception as e:  # noqa: BLE001
        a.status = "failed"
        a.result = str(e)[:200]


def plan(report_dict: dict, threat_events: list, cfg) -> list[dict]:
    """이슈·침해에 대한 대응 명령 목록 생성(안전장치 적용).

    - remediation=off : 빈 목록
    - suggest(기본)   : 명령만 생성(status=suggested), 실행 안 함
    - auto            : dry_run 아니고 자리표시자 없고 화이트리스트 통과 시 실제 실행
    반환: RemediationAction.to_dict() 목록
    """
    if cfg.remediation == REMEDIATION_OFF:
        return []

    actions: list[RemediationAction] = []
    # 취약 구성 대응(HIGH 이상만 — 소음/위험 축소)
    for f in report_dict.get("findings", []):
        if f.get("severity") not in ("CRITICAL", "HIGH"):
            continue
        actions.extend(_actions_for_finding(f))
    # 침해 IP 차단
    for t in (threat_events or []):
        td = t.to_dict() if hasattr(t, "to_dict") else t
        actions.extend(_actions_for_threat(td))

    # 안전장치 적용
    for a in actions:
        if _protected(a.target, cfg.protect_tags):
            a.status = "skipped_protected"
            a.result = "보호(화이트리스트) 대상이라 건드리지 않음"
            continue
        if cfg.remediation == REMEDIATION_AUTO:
            _maybe_execute(a, cfg)
        else:  # suggest
            a.status = "suggested"

    return [a.to_dict() for a in actions]
