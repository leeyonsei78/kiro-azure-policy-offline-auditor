"""오프라인 판정 엔진 (폐쇄망 전제, 표준 라이브러리만).

AWS/Azure CLI 출력 텍스트를 인터넷/AI 없이 정규식·구조 분석으로 검토해
ISMS-P 통제항목 기준의 이슈(Finding)를 산출한다. 각 이슈에는 대상 플랫폼(aws/azure)이
자동으로 태깅되어 화면/리포트에서 구별된다.

설계 원칙(ai-security-suite의 *_offline_engine 패턴 참고):
- JSON으로 파싱되는 입력은 실제 객체 구조를 따라가며 판정(오탐 최소화).
- 명시적 차단 규칙(access=Deny 등)은 '과도 허용'으로 오인하지 않도록 제외.
- 판정 근거/개선안은 knowledge_base(ISMS-P)의 플랫폼별 criteria/fix에 연결.
- 어떤 조치도 실행하지 않는다 — 검토와 제안만.
"""

from __future__ import annotations

import json
import re

from .knowledge_base import control_for
from .models import AuditReport, Finding, Severity
from .parser import iter_dicts, parse
from .sql_controls import sql_check

# --- 공통 정규식/상수 -------------------------------------------------------
_OPEN_ANY_RE = re.compile(r"(0\.0\.0\.0/0|::/0|\bany\b|internet|^\*$|\"\*\")", re.I)

_SENSITIVE_PORTS = {
    "22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL",
    "6379": "Redis", "1433": "MSSQL", "27017": "MongoDB", "445": "SMB", "23": "Telnet",
}
_MGMT_PORTS = {"22", "3389", "445", "23"}


# 이슈 유형별 위반(bad)·개선(good) 예시 카탈로그.
# 화면/리포트에서 "✗ 위반 예시 / ✓ 개선 예시"로 표시되어 조치 방향을 구체적으로 안내한다.
_EXAMPLES: dict[str, dict[str, str]] = {
    # ---- AWS 네트워크/접근 ----
    "aws_sg_open_sensitive_port": {
        "bad": "IpPermissions: FromPort=22, IpRanges=[{CidrIp: 0.0.0.0/0}]  (전체 인터넷에 SSH 개방)",
        "good": "IpRanges=[{CidrIp: 10.0.0.0/16}] 또는 관리자 IP/Bastion·SSM Session Manager 경유로 제한",
    },
    "aws_sg_open_any": {
        "bad": "IpRanges=[{CidrIp: 0.0.0.0/0}] 로 모든 출발지 허용",
        "good": "필요한 CIDR·보안그룹 참조로 출발지를 최소 범위로 제한",
    },
    "aws_rds_public": {
        "bad": "PubliclyAccessible: true  (RDS 엔드포인트가 인터넷에 노출)",
        "good": "PubliclyAccessible: false + 프라이빗 서브넷 배치 + 보안그룹으로 접근 출발지 제한",
    },
    # ---- AWS 암호화/노출 ----
    "aws_s3_public_block_off": {
        "bad": "PublicAccessBlockConfiguration: {BlockPublicAcls: false, RestrictPublicBuckets: false}",
        "good": "계정·버킷 레벨 Block Public Access 4개 옵션을 모두 true로 설정",
    },
    "aws_s3_public_policy": {
        "bad": '버킷 정책 Statement: {"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}',
        "good": '특정 주체로 제한: {"Principal":{"AWS":"arn:aws:iam::111122223333:role/app"}} 또는 CloudFront OAC 사용',
    },
    "aws_s3_no_encryption": {
        "bad": "버킷 기본 암호화(ServerSideEncryptionConfiguration) 없음",
        "good": "기본 암호화 SSE-KMS 적용 (aws s3api put-bucket-encryption ... aws:kms)",
    },
    "aws_ebs_snapshot_public": {
        "bad": "CreateVolumePermission: [{Group: all}]  (누구나 스냅샷으로 볼륨 복원 가능)",
        "good": "공개 공유 제거, 필요 시 특정 계정에만 공유 (UserId 지정)",
    },
    # ---- AWS IAM/자격증명 ----
    "aws_iam_wildcard_admin": {
        "bad": '{"Effect":"Allow","Action":"*","Resource":"*"}  (전권 부여)',
        "good": "업무별 최소권한 정책으로 분리 (예: 특정 S3 버킷·특정 액션만 Allow)",
    },
    "aws_iam_no_mfa": {
        "bad": "콘솔 접근 가능 IAM 사용자 mfa_active=false",
        "good": "MFA 등록 + IAM 정책 조건 aws:MultiFactorAuthPresent=true 강제",
    },
    "aws_root_access_key": {
        "bad": "root 계정 access_key_1_active=true  (루트 액세스 키 상시 존재)",
        "good": "루트 액세스 키 삭제, 루트는 MFA 등록 후 비상시에만 사용, 일상 작업은 IAM Role",
    },
    # ---- AWS 로깅/거버넌스 ----
    "cloudtrail_missing": {
        "bad": "다중 리전 CloudTrail 없음 또는 IsMultiRegionTrail=false",
        "good": "조직 전체 다중 리전 CloudTrail + 로그 파일 검증(LogFileValidationEnabled)+KMS 암호화",
    },
    "vpc_flowlogs_missing": {
        "bad": "VPC Flow Logs 미구성 또는 FlowLogStatus=INACTIVE",
        "good": "모든 VPC에 Flow Logs 활성화(대상: CloudWatch Logs/S3) 후 이상 트래픽 모니터링",
    },
    "aws_config_recorder_off": {
        "bad": "ConfigurationRecorder recording=false  (구성 변경 미기록)",
        "good": "전 리전 AWS Config 레코더 활성화 + 규정 준수 규칙(Conformance Pack) 적용",
    },
    # ---- Azure 네트워크/접근 ----
    "nsg_open_sensitive_port": {
        "bad": "sourceAddressPrefix='*', destinationPortRange='3389', access='Allow', direction='Inbound'",
        "good": "출발지를 회사 IP/서브넷으로 제한하거나 Azure Bastion 경유, JIT VM 액세스 사용",
    },
    "nsg_open_all_ports": {
        "bad": "sourceAddressPrefix='0.0.0.0/0', destinationPortRange='*'  (모든 포트 전체 개방)",
        "good": "필요한 포트만 명시하고 출발지 IP를 최소 범위로 제한",
    },
    "nsg_open_any": {
        "bad": "sourceAddressPrefix='Internet' 인바운드 허용",
        "good": "필요한 CIDR/서비스 태그로 출발지 제한",
    },
    "nsg_outbound_any": {
        "bad": "direction='Outbound', destinationAddressPrefix='*' 전체 허용",
        "good": "아웃바운드 목적지를 필요한 서비스 태그/IP로 제한(데이터 유출 통제)",
    },
    # ---- Azure 암호화/노출 ----
    "storage_https_disabled": {
        "bad": "supportsHttpsTrafficOnly: false  (HTTP 평문 전송 허용)",
        "good": "supportsHttpsTrafficOnly: true + minimumTlsVersion: TLS1_2",
    },
    "storage_public_blob": {
        "bad": "allowBlobPublicAccess: true  (익명 Blob 접근 허용)",
        "good": "allowBlobPublicAccess: false, 필요한 공유는 SAS 토큰·Private Endpoint로 대체",
    },
    "storage_weak_tls": {
        "bad": "minimumTlsVersion: TLS1_0",
        "good": "minimumTlsVersion: TLS1_2 이상",
    },
    "webapp_https_disabled": {
        "bad": "httpsOnly: false  (웹앱이 HTTP 평문 접근 허용)",
        "good": "httpsOnly: true + minTlsVersion 1.2, HSTS 적용",
    },
    "disk_no_cmk": {
        "bad": "encryption.type: EncryptionAtRestWithPlatformKey  (플랫폼 관리 키만)",
        "good": "규제 요건 시 Disk Encryption Set으로 고객 관리 키(CMK) 적용",
    },
    # ---- Azure Key Vault ----
    "keyvault_softdelete_off": {
        "bad": "enableSoftDelete: false",
        "good": "enableSoftDelete: true (90일 보존)",
    },
    "keyvault_purge_off": {
        "bad": "enablePurgeProtection: false",
        "good": "enablePurgeProtection: true (강제 영구삭제 차단)",
    },
    # ---- Azure RBAC/거버넌스 ----
    "rbac_privileged_assignment": {
        "bad": "roleDefinitionName='Owner' 가 다수 사용자에게 상시 부여",
        "good": "Reader/Contributor 등 최소권한 역할 + PIM으로 필요시(JIT) 승격",
    },
    # ---- 공통 텍스트 폴백 ----
    "mfa_ca_disabled": {
        "bad": "Conditional Access policy state: disabled (MFA 강제 없음)",
        "good": "전 사용자·관리자 MFA 강제 CA 정책 활성화(state: enabled) 또는 Security Defaults",
    },
    "diagnostic_missing": {
        "bad": "diagnostic-settings list 결과: [] (진단 설정 없음)",
        "good": "핵심 리소스 진단 설정을 Log Analytics/Storage로 연동, Azure Policy로 강제",
    },
    "backup_failed": {
        "bad": "lastBackupStatus: Failed",
        "good": "백업 실패 원인 조치 후 재실행, 백업 성공/실패 알림(Monitor) 구성",
    },
    "backup_lrs": {
        "bad": "storageType: LocallyRedundant (LRS)",
        "good": "GRS/RA-GRS 등 지역 중복 스토리지로 전환",
    },
    "defender_active_alert": {
        "bad": "Defender for Cloud alert status: Active (미해결)",
        "good": "경고 분류·조치 후 해결 처리, Sentinel 연동으로 상관분석·자동대응",
    },
    "assessment_unhealthy": {
        "bad": "assessment status.code: Unhealthy",
        "good": "권고 조치 반영으로 Healthy 전환, Secure Score 목표 관리",
    },
    "patch_pending": {
        "bad": "classificationsToInclude=[Critical,Security] 패치 미적용",
        "good": "Azure Update Manager로 정기 패치 일정 수립·자동 적용",
    },
    "cve_detected": {
        "bad": "CVE-2021-44228 등 알려진 취약점 식별자 존재",
        "good": "영향 자산 패치 적용, 패치 불가 시 WAF 규칙·네트워크 격리 등 완화",
    },
}


def _finding(code: str, issue_type: str, severity: Severity, title: str,
             description: str, *, platform: str = "azure", evidence: str = "",
             resource: str = "", recommendation: str = "",
             bad_example: str = "", good_example: str = "") -> Finding:
    kb = control_for(code, platform)
    # 이슈 유형별 맞춤 예시가 있으면 우선 사용, 없으면 통제항목 기본값.
    ex = _EXAMPLES.get(issue_type, {})
    return Finding(
        control_code=code,
        control_domain=kb.get("domain", ""),
        issue_type=issue_type,
        severity=severity,
        title=title,
        description=description or kb.get("criteria", ""),
        recommendation=recommendation or kb.get("fix", ""),
        evidence=(evidence or "")[:300],
        resource=resource or "",
        platform=platform,
        bad_example=bad_example or ex.get("bad", "") or kb.get("bad_example", ""),
        good_example=good_example or ex.get("good", "") or kb.get("good_example", ""),
    )


def _val(d: dict, *keys, default=None):
    """대소문자 무시하고 여러 후보 키 중 첫 값 반환."""
    lower = {k.lower(): v for k, v in d.items() if isinstance(k, str)}
    for k in keys:
        if k.lower() in lower:
            return lower[k.lower()]
    return default


def _ports_from(text: str) -> list[str]:
    hits = []
    for p in _SENSITIVE_PORTS:
        if re.search(rf"\b{p}\b", text):
            hits.append(p)
    return hits


def _looks_like(d: dict, *type_hints: str) -> bool:
    """dict가 특정 리소스 유형인지 키/type 필드로 추정."""
    t = str(_val(d, "type", default="")).lower()
    keys = " ".join(k.lower() for k in d.keys() if isinstance(k, str))
    blob = t + " " + keys
    return any(h in blob for h in type_hints)


# ---------------------------------------------------------------------------
# 플랫폼 자동 감지
# ---------------------------------------------------------------------------
_AWS_KEYS = ("groupid", "ippermissions", "cidrip", "iprotocol", "fromport", "toport",
             "policydocument", "attachedpolicies", "publicaccessblockconfiguration",
             "blockpublicacls", "serversideencryptionconfiguration", "mfaactive",
             "accesskeymetadata", "awsaccountid", "dbinstanceidentifier",
             "publiclyaccessible", "snapshotid", "createvolumepermission")
_AZURE_KEYS = ("sourceaddressprefix", "destinationportrange", "enablesoftdelete",
               "enablepurgeprotection", "supportshttpstrafficonly", "allowblobpublicaccess",
               "roledefinitionname", "principalname", "publicnetworkaccess", "minimumtlsversion")


def _detect_platform(d: dict) -> str | None:
    """단일 dict의 플랫폼(aws/azure) 추정. 판단 근거 없으면 None."""
    flat = json.dumps(d, ensure_ascii=False).lower()
    if "microsoft." in flat or "arn:aws" in flat:
        return "azure" if "microsoft." in flat and "arn:aws" not in flat else "aws"
    az = sum(1 for k in _AZURE_KEYS if k in flat)
    aws = sum(1 for k in _AWS_KEYS if k in flat)
    if aws > az:
        return "aws"
    if az > aws:
        return "azure"
    return None


# ===========================================================================
# Azure 검사기
# ===========================================================================
def _check_nsg_rule_obj(rule: dict, findings: list[Finding]) -> None:
    """Azure NSG 규칙(2.6.1 인바운드 과도 허용, 2.6.7 아웃바운드 Any)."""
    flat = json.dumps(rule, ensure_ascii=False)
    access = str(_val(rule, "access", "action", default="")).lower()
    if access in ("deny", "reject", "drop", "block"):
        return
    src = str(_val(rule, "sourceAddressPrefix", "source", "sourceAddressPrefixes", default=""))
    direction = str(_val(rule, "direction", default="")).lower()
    name = str(_val(rule, "name", default="") or "")
    dst_port = str(_val(rule, "destinationPortRange", "destinationPortRanges", "port", default=""))

    src_is_any = bool(_OPEN_ANY_RE.search(src)) or "internet" in src.lower()
    if not src_is_any:
        return

    if direction == "outbound":
        findings.append(_finding(
            "2.6.7", "nsg_outbound_any", Severity.MEDIUM,
            f"NSG 아웃바운드가 Any로 허용됨: {name or '(이름없음)'}",
            "NSG 아웃바운드 규칙의 목적지가 Any로 허용되어 내부 시스템의 인터넷 접속이 통제되지 않습니다.",
            platform="azure", evidence=flat, resource=name,
        ))
        return

    ports_text = dst_port if dst_port else flat
    sens = _ports_from(ports_text)
    is_all_ports = dst_port.strip() in ("*", "0-65535", "") and not sens
    if sens:
        worst = any(p in _MGMT_PORTS for p in sens)
        svc = ", ".join(f"{p}({_SENSITIVE_PORTS[p]})" for p in sens)
        findings.append(_finding(
            "2.6.1", "nsg_open_sensitive_port",
            Severity.CRITICAL if worst else Severity.HIGH,
            f"NSG 인바운드 전체공개 + 민감포트: {name or '(이름없음)'}",
            f"출발지가 전체공개(Any/0.0.0.0/0)인 인바운드 규칙이 민감 포트 {svc}를 허용합니다.",
            platform="azure", evidence=flat, resource=name,
        ))
    elif is_all_ports:
        findings.append(_finding(
            "2.6.1", "nsg_open_all_ports", Severity.HIGH,
            f"NSG 인바운드 전체공개(모든 포트): {name or '(이름없음)'}",
            "출발지가 전체공개(Any/0.0.0.0/0)이고 대상 포트가 전체 범위로 열려 있습니다.",
            platform="azure", evidence=flat, resource=name,
        ))
    else:
        findings.append(_finding(
            "2.6.1", "nsg_open_any", Severity.MEDIUM,
            f"NSG 인바운드 출발지 전체공개: {name or '(이름없음)'}",
            "인바운드 규칙의 출발지가 전체공개(Any/0.0.0.0/0)로 설정되어 있습니다.",
            platform="azure", evidence=flat, resource=name,
        ))


def _check_storage_obj(d: dict, findings: list[Finding]) -> None:
    name = str(_val(d, "name", default="") or "")
    flat = json.dumps(d, ensure_ascii=False)
    https_only = _val(d, "supportsHttpsTrafficOnly", "enableHttpsTrafficOnly")
    if https_only is False or str(https_only).lower() == "false":
        findings.append(_finding(
            "2.7.1", "storage_https_disabled", Severity.HIGH,
            f"Storage HTTPS 전용 미설정: {name or '(이름없음)'}",
            "Storage Account가 HTTP 평문 전송을 허용합니다(supportsHttpsTrafficOnly=false).",
            platform="azure", evidence=flat, resource=name,
            recommendation="Storage Account의 '보안 전송 필수(HTTPS only)'를 활성화하고, 최소 TLS 버전을 1.2로 설정하세요.",
        ))
    public = _val(d, "allowBlobPublicAccess")
    if public is True or str(public).lower() == "true":
        findings.append(_finding(
            "2.7.1", "storage_public_blob", Severity.HIGH,
            f"Storage 퍼블릭 Blob 접근 허용: {name or '(이름없음)'}",
            "Storage Account가 익명 Blob 퍼블릭 접근을 허용합니다(allowBlobPublicAccess=true).",
            platform="azure", evidence=flat, resource=name,
            recommendation="allowBlobPublicAccess를 false로 설정하고, 필요한 공유는 SAS·Private Endpoint로 대체하세요.",
        ))
    tls = str(_val(d, "minimumTlsVersion", "minimumTLSVersion", default=""))
    if tls and re.search(r"1[._]?0|1[._]?1|tls1_0|tls1_1", tls, re.I):
        findings.append(_finding(
            "2.7.1", "storage_weak_tls", Severity.MEDIUM,
            f"Storage 약한 TLS 버전: {name or '(이름없음)'} ({tls})",
            f"Storage Account 최소 TLS 버전이 {tls}로 취약합니다(TLS 1.2 미만).",
            platform="azure", evidence=flat, resource=name,
            recommendation="최소 TLS 버전을 1.2 이상으로 설정하세요.",
        ))


def _sql_finding(key: str, severity: Severity, findings: list[Finding],
                 name: str, flat: str, extra_desc: str = "") -> None:
    """sql_controls 카탈로그의 메타(title/criteria/fix/bad/good)로 Finding 생성."""
    meta = sql_check(key) or {}
    desc = meta.get("criteria", "")
    if extra_desc:
        desc = f"{desc} ({extra_desc})" if desc else extra_desc
    findings.append(Finding(
        control_code=meta.get("control_code", "2.7.1"),
        control_domain=control_for(meta.get("control_code", "2.7.1"), "azure").get("domain", ""),
        issue_type=key,
        severity=severity,
        title=f"{meta.get('title', key)}: {name or '(이름없음)'}",
        description=desc,
        recommendation=meta.get("fix", ""),
        evidence=(flat or "")[:300],
        resource=name,
        platform="azure",
        bad_example=meta.get("bad_example", ""),
        good_example=meta.get("good_example", ""),
    ))


def _truthy_false(v) -> bool:
    return v is False or str(v).lower() in ("false", "disabled", "off", "0")


def _check_sql_obj(d: dict, findings: list[Finding]) -> None:
    """Azure SQL 관련 dict에서 8개 보안 항목을 판정.

    입력은 az sql ... -o json 출력의 개별 객체(서버/DB/정책 등). 여러 명령 출력을
    이어붙인 입력에서도 각 객체가 자신의 키를 가지면 해당 항목만 판정된다.
    """
    name = str(_val(d, "name", default="") or _val(d, "serverName", "databaseName", default="") or "")
    flat = json.dumps(d, ensure_ascii=False)
    low = flat.lower()

    # 1) TDE 비활성화
    tde = _val(d, "state", "status")
    if ("tde" in low or "transparentdataencryption" in low) and _truthy_false(tde):
        _sql_finding("sql_tde_disabled", Severity.HIGH, findings, name, flat)

    # 2) CMK 미적용 (서비스 관리 키만)
    skt = str(_val(d, "serverKeyType", default=""))
    if skt.lower() == "servicemanaged":
        _sql_finding("sql_cmk_not_used", Severity.MEDIUM, findings, name, flat)

    # 3) 퍼블릭 네트워크 접근
    pub = str(_val(d, "publicNetworkAccess", default=""))
    if pub.lower() in ("enabled", "true"):
        _sql_finding("sql_public_access", Severity.HIGH, findings, name, flat)
    # 방화벽 규칙 0.0.0.0 전체 허용
    start_ip = str(_val(d, "startIpAddress", default=""))
    end_ip = str(_val(d, "endIpAddress", default=""))
    if start_ip == "0.0.0.0" and end_ip in ("0.0.0.0", "255.255.255.255"):
        _sql_finding("sql_public_access", Severity.HIGH, findings, name, flat,
                     extra_desc="방화벽 규칙이 0.0.0.0로 전체 허용")

    # 4) Private Endpoint 미구성 (서버 객체에 빈 연결 목록)
    pec = _val(d, "privateEndpointConnections")
    if isinstance(pec, list) and len(pec) == 0 and ("sql" in low or _val(d, "publicNetworkAccess") is not None):
        _sql_finding("sql_no_private_endpoint", Severity.MEDIUM, findings, name, flat)

    # 5) Auditing 비활성화 (audit 컨텍스트 + state Disabled)
    if ("audit" in low) and _truthy_false(_val(d, "state")):
        _sql_finding("sql_auditing_disabled", Severity.HIGH, findings, name, flat)

    # 6) Defender for SQL 비활성화 (ATP/threat protection 컨텍스트)
    if ("threatprotection" in low or "advancedthreatprotection" in low or "atp" in low) \
            and _truthy_false(_val(d, "state")):
        _sql_finding("sql_defender_disabled", Severity.HIGH, findings, name, flat)

    # 7) 취약성 평가(VA) 미구성 (recurringScans.isEnabled = false)
    rs = _val(d, "recurringScans")
    if isinstance(rs, dict) and _truthy_false(_val(rs, "isEnabled")):
        _sql_finding("sql_va_disabled", Severity.MEDIUM, findings, name, flat)

    # 8) LTR 미구성 (weekly/monthly/yearly 모두 PT0S/빈값)
    wk = str(_val(d, "weeklyRetention", default=""))
    mo = str(_val(d, "monthlyRetention", default=""))
    yr = str(_val(d, "yearlyRetention", default=""))
    if (wk or mo or yr) and all(v in ("", "PT0S", "P0D") for v in (wk, mo, yr)):
        _sql_finding("sql_ltr_not_configured", Severity.MEDIUM, findings, name, flat)


def _check_keyvault_obj(d: dict, findings: list[Finding], seen: set) -> None:
    name = str(_val(d, "name", default="") or "")
    flat = json.dumps(d, ensure_ascii=False)
    props = _val(d, "properties")
    src = props if isinstance(props, dict) else d
    soft = _val(src, "enableSoftDelete", "softDelete")
    purge = _val(src, "enablePurgeProtection", "purgeProtection")
    vault_key = name or json.dumps(src, sort_keys=True, ensure_ascii=False)[:80]
    if ("kv", vault_key) in seen:
        return
    seen.add(("kv", vault_key))
    if soft is False or str(soft).lower() == "false":
        findings.append(_finding(
            "2.7.2", "keyvault_softdelete_off", Severity.MEDIUM,
            f"Key Vault Soft-delete 비활성화: {name or '(이름없음)'}",
            "Key Vault의 Soft-delete가 비활성화되어 키·비밀이 실수로 영구 삭제될 위험이 있습니다.",
            platform="azure", evidence=flat, resource=name,
        ))
    if purge is False or str(purge).lower() == "false":
        findings.append(_finding(
            "2.7.2", "keyvault_purge_off", Severity.MEDIUM,
            f"Key Vault Purge Protection 비활성화: {name or '(이름없음)'}",
            "Key Vault의 Purge Protection이 비활성화되어 삭제 대기 중인 키를 강제 영구 삭제할 수 있습니다.",
            platform="azure", evidence=flat, resource=name,
        ))


_PRIVILEGED_ROLES = ("owner", "contributor", "user access administrator",
                     "global administrator", "글로벌 관리자", "전역 관리자")


def _check_rbac_obj(d: dict, role: str, findings: list[Finding], seen: set) -> None:
    rl = role.lower()
    if any(p in rl for p in _PRIVILEGED_ROLES):
        principal = str(_val(d, "principalName", "principalId", "principal", default="") or "")
        key = ("rbac", role, principal)
        if key in seen:
            return
        seen.add(key)
        sev = Severity.HIGH if "owner" in rl or "global" in rl or "전역" in rl else Severity.MEDIUM
        findings.append(_finding(
            "2.5.5", "rbac_privileged_assignment", sev,
            f"광범위 권한 부여: {role} → {principal or '(주체미상)'}",
            f"'{role}' 같은 광범위 권한이 부여되어 있습니다. 부여 대상과 상시 활성 여부를 최소권한 관점에서 검토가 필요합니다.",
            platform="azure", evidence=json.dumps(d, ensure_ascii=False), resource=principal,
        ))


# ===========================================================================
# AWS 검사기
# ===========================================================================
def _iter_aws_sg_rules(d: dict):
    """AWS 보안그룹 dict에서 (rule_dict, group_id) 쌍을 순회. IpPermissions 인바운드만."""
    gid = str(_val(d, "GroupId", "groupId", default="") or _val(d, "GroupName", "groupName", default="") or "")
    perms = _val(d, "IpPermissions", "ipPermissions")
    if isinstance(perms, list):
        for p in perms:
            if isinstance(p, dict):
                yield p, gid


def _aws_rule_open(perm: dict) -> bool:
    """규칙의 IpRanges/Ipv6Ranges에 0.0.0.0/0 또는 ::/0 있는지."""
    for key in ("IpRanges", "ipRanges"):
        for r in (_val(perm, key) or []):
            if isinstance(r, dict) and str(_val(r, "CidrIp", "cidrIp", default="")) in ("0.0.0.0/0",):
                return True
    for key in ("Ipv6Ranges", "ipv6Ranges"):
        for r in (_val(perm, key) or []):
            if isinstance(r, dict) and str(_val(r, "CidrIpv6", "cidrIpv6", default="")) in ("::/0",):
                return True
    return False


def _aws_rule_ports(perm: dict) -> list[str]:
    """규칙이 커버하는 민감 포트 목록. FromPort~ToPort 범위 또는 -1(all)."""
    fp = _val(perm, "FromPort", "fromPort")
    tp = _val(perm, "ToPort", "toPort")
    proto = str(_val(perm, "IpProtocol", "ipProtocol", default=""))
    if proto == "-1" or fp is None:
        return list(_SENSITIVE_PORTS)  # 전체 허용 → 모든 민감포트 포함으로 간주
    try:
        fp, tp = int(fp), int(tp if tp is not None else fp)
    except (TypeError, ValueError):
        return []
    return [p for p in _SENSITIVE_PORTS if fp <= int(p) <= tp]


def _check_aws_sg_obj(d: dict, findings: list[Finding]) -> None:
    """AWS 보안그룹(2.6.1). 0.0.0.0/0 인바운드 + 민감포트."""
    for perm, gid in _iter_aws_sg_rules(d):
        if not _aws_rule_open(perm):
            continue
        ports = _aws_rule_ports(perm)
        flat = json.dumps(perm, ensure_ascii=False)
        sens = [p for p in ports if p in _SENSITIVE_PORTS]
        if sens:
            worst = any(p in _MGMT_PORTS for p in sens)
            svc = ", ".join(f"{p}({_SENSITIVE_PORTS[p]})" for p in sens[:6])
            findings.append(_finding(
                "2.6.1", "aws_sg_open_sensitive_port",
                Severity.CRITICAL if worst else Severity.HIGH,
                f"보안그룹 인바운드 전체공개 + 민감포트: {gid or '(SG미상)'}",
                f"0.0.0.0/0(Any)에서 민감 포트 {svc} 인바운드가 허용되어 있습니다.",
                platform="aws", evidence=flat, resource=gid,
            ))
        else:
            findings.append(_finding(
                "2.6.1", "aws_sg_open_any", Severity.MEDIUM,
                f"보안그룹 인바운드 출발지 전체공개: {gid or '(SG미상)'}",
                "0.0.0.0/0(Any)에서 인바운드가 허용된 보안그룹 규칙이 있습니다.",
                platform="aws", evidence=flat, resource=gid,
            ))


def _check_aws_s3_obj(d: dict, findings: list[Finding]) -> None:
    """AWS S3 버킷(2.7.1 데이터 보호). 퍼블릭 차단 미설정 / 암호화 미설정."""
    name = str(_val(d, "Name", "name", "Bucket", "bucket", default="") or "")
    flat = json.dumps(d, ensure_ascii=False)
    pab = _val(d, "PublicAccessBlockConfiguration", "publicAccessBlockConfiguration")
    if isinstance(pab, dict):
        vals = [_val(pab, k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                       "BlockPublicPolicy", "RestrictPublicBuckets")]
        if any(v is False or str(v).lower() == "false" for v in vals):
            findings.append(_finding(
                "2.7.1", "aws_s3_public_block_off", Severity.HIGH,
                f"S3 퍼블릭 액세스 차단 미흡: {name or '(버킷미상)'}",
                "S3 버킷의 퍼블릭 액세스 차단(Block Public Access) 옵션 중 일부가 false로 설정되어 있습니다.",
                platform="aws", evidence=flat, resource=name,
                recommendation="계정·버킷 레벨 Block Public Access 4개 옵션을 모두 활성화하세요.",
            ))
    # 버킷 정책/ACL 퍼블릭
    if re.search(r'"principal"\s*:\s*"\*"|allusers|"effect"\s*:\s*"allow".{0,80}"principal"\s*:\s*"\*"', flat, re.I):
        findings.append(_finding(
            "2.7.1", "aws_s3_public_policy", Severity.HIGH,
            f"S3 버킷 정책이 퍼블릭 허용: {name or '(버킷미상)'}",
            "버킷 정책이 모든 주체(Principal:*)에 접근을 허용합니다.",
            platform="aws", evidence=flat, resource=name,
            recommendation="Principal:* 허용을 제거하고 최소 권한 주체로 제한하세요.",
        ))
    # 암호화 미설정
    enc = _val(d, "ServerSideEncryptionConfiguration", "serverSideEncryptionConfiguration", "Encryption")
    if "encryption" in flat.lower() and (enc is None or enc == {} or str(enc).lower() in ("none", "false", "disabled")):
        findings.append(_finding(
            "2.7.1", "aws_s3_no_encryption", Severity.MEDIUM,
            f"S3 기본 암호화 미설정: {name or '(버킷미상)'}",
            "S3 버킷에 기본 서버측 암호화(SSE)가 설정되어 있지 않습니다.",
            platform="aws", evidence=flat, resource=name,
            recommendation="버킷 기본 암호화(SSE-S3 또는 SSE-KMS)를 적용하세요.",
        ))


def _iter_policy_statements(doc):
    """IAM PolicyDocument에서 Statement dict들을 순회."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return
    if not isinstance(doc, dict):
        return
    stmts = doc.get("Statement") or doc.get("statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if isinstance(stmts, list):
        for s in stmts:
            if isinstance(s, dict):
                yield s


def _stmt_is_wildcard_admin(s: dict) -> bool:
    if str(s.get("Effect", s.get("effect", ""))).lower() != "allow":
        return False
    def _has_star(v):
        if v == "*":
            return True
        if isinstance(v, list):
            return "*" in v
        return False
    return _has_star(s.get("Action", s.get("action"))) and _has_star(s.get("Resource", s.get("resource")))


def _check_aws_iam_obj(d: dict, findings: list[Finding], seen: set) -> None:
    """AWS IAM(2.5.5 과다권한, 2.5.3 MFA, 2.5.6 자격증명)."""
    flat = json.dumps(d, ensure_ascii=False)
    name = str(_val(d, "UserName", "userName", "RoleName", "roleName",
                    "PolicyName", "policyName", "name", default="") or "")

    # 와일드카드 관리자 정책
    doc = _val(d, "PolicyDocument", "policyDocument")
    if doc is not None:
        for s in _iter_policy_statements(doc):
            if _stmt_is_wildcard_admin(s):
                key = ("aws_admin", name, json.dumps(s, sort_keys=True)[:80])
                if key in seen:
                    break
                seen.add(key)
                findings.append(_finding(
                    "2.5.5", "aws_iam_wildcard_admin", Severity.HIGH,
                    f"IAM 와일드카드 관리자 권한: {name or '(정책미상)'}",
                    "Action:* / Resource:* 를 Allow하는 광범위 권한 정책이 있습니다(최소권한 위배).",
                    platform="aws", evidence=flat, resource=name,
                ))
                break

    # MFA 미설정 사용자
    mfa = _val(d, "MFAActive", "mfaActive", "MfaActive")
    if mfa is False or str(mfa).lower() == "false":
        if _val(d, "UserName", "userName") or "user" in flat.lower():
            findings.append(_finding(
                "2.5.3", "aws_iam_no_mfa", Severity.HIGH,
                f"IAM 사용자 MFA 미설정: {name or '(사용자미상)'}",
                "콘솔 접근이 가능한 IAM 사용자에 MFA가 설정되어 있지 않습니다.",
                platform="aws", evidence=flat, resource=name,
            ))

    # 루트 계정 액세스 키
    if re.search(r'"?<?root_?account>?"?|"user"\s*:\s*"<root', flat, re.I) and \
            re.search(r'access[_ ]?key', flat, re.I) and \
            re.search(r'"?(?:access_key_1_active|access_key_2_active)"?\s*[:=]\s*"?true', flat, re.I):
        findings.append(_finding(
            "2.5.6", "aws_root_access_key", Severity.CRITICAL,
            "루트 계정 액세스 키 존재",
            "루트 계정에 활성 액세스 키가 있습니다. 루트 키는 유출 시 계정 전체가 노출됩니다.",
            platform="aws", evidence=flat[:200], resource="root",
        ))


def _check_aws_rds_obj(d: dict, findings: list[Finding]) -> None:
    """AWS RDS 인스턴스(2.6.1). 퍼블릭 접근 허용."""
    pub = _val(d, "PubliclyAccessible", "publiclyAccessible")
    if pub is True or str(pub).lower() == "true":
        name = str(_val(d, "DBInstanceIdentifier", "dbInstanceIdentifier", default="") or "")
        findings.append(_finding(
            "2.6.1", "aws_rds_public", Severity.HIGH,
            f"RDS 인스턴스 퍼블릭 접근 허용: {name or '(인스턴스미상)'}",
            "RDS 데이터베이스가 PubliclyAccessible=true로 설정되어 인터넷에서 직접 접근 가능합니다.",
            platform="aws", evidence=json.dumps(d, ensure_ascii=False), resource=name,
            recommendation="RDS의 퍼블릭 접근을 비활성화하고, 프라이빗 서브넷 배치 + 보안그룹으로 접근 출발지를 제한하세요.",
        ))


def _check_aws_ebs_snapshot_obj(d: dict, findings: list[Finding]) -> None:
    """AWS EBS 스냅샷(2.7.1). createVolumePermission이 all(공개)."""
    perms = _val(d, "CreateVolumePermission", "createVolumePermission")
    if isinstance(perms, dict):
        perms = [perms]
    if isinstance(perms, list):
        for p in perms:
            if isinstance(p, dict) and str(_val(p, "Group", "group", default="")).lower() == "all":
                sid = str(_val(d, "SnapshotId", "snapshotId", default="") or "")
                findings.append(_finding(
                    "2.7.1", "aws_ebs_snapshot_public", Severity.HIGH,
                    f"EBS 스냅샷 퍼블릭 공개: {sid or '(스냅샷미상)'}",
                    "EBS 스냅샷의 볼륨 생성 권한이 all(전체 공개)로 설정되어 누구나 데이터 복원이 가능합니다.",
                    platform="aws", evidence=json.dumps(d, ensure_ascii=False), resource=sid,
                    recommendation="스냅샷 공유를 비공개로 변경하고, 필요한 경우 특정 계정에만 공유하세요.",
                ))
                return


def _check_aws_object(d: dict, findings: list[Finding], seen: set) -> None:
    """AWS 리소스 dict 라우팅."""
    if _val(d, "PubliclyAccessible", "publiclyAccessible") is not None \
            and _val(d, "DBInstanceIdentifier", "dbInstanceIdentifier", "Engine", "engine") is not None:
        _check_aws_rds_obj(d, findings)
    if _val(d, "CreateVolumePermission", "createVolumePermission") is not None \
            or (_val(d, "SnapshotId", "snapshotId") is not None and _val(d, "CreateVolumePermission", "createVolumePermission") is not None):
        _check_aws_ebs_snapshot_obj(d, findings)
    if _val(d, "IpPermissions", "ipPermissions") is not None or (
        _val(d, "GroupId", "groupId") is not None and _val(d, "IpPermissions", "ipPermissions") is not None
    ):
        _check_aws_sg_obj(d, findings)
    if _val(d, "PublicAccessBlockConfiguration", "publicAccessBlockConfiguration") is not None \
            or _looks_like(d, "s3", "bucket") \
            or _val(d, "ServerSideEncryptionConfiguration") is not None:
        _check_aws_s3_obj(d, findings)
    if _val(d, "PolicyDocument", "policyDocument") is not None \
            or _val(d, "MFAActive", "mfaActive") is not None \
            or _val(d, "UserName", "userName") is not None \
            or _val(d, "AccessKeyMetadata") is not None:
        _check_aws_iam_obj(d, findings, seen)


# ===========================================================================
# Azure 리소스 dict 라우팅
# ===========================================================================
def _check_azure_webapp_obj(d: dict, findings: list[Finding]) -> None:
    """Azure App Service(2.7.1). httpsOnly=false → 평문 접근 허용."""
    https_only = _val(d, "httpsOnly", "httpsonly")
    if https_only is False or str(https_only).lower() == "false":
        name = str(_val(d, "name", default="") or _val(d, "defaultHostName", default="") or "")
        findings.append(_finding(
            "2.7.1", "webapp_https_disabled", Severity.MEDIUM,
            f"App Service HTTPS 전용 미설정: {name or '(앱미상)'}",
            "App Service(웹앱)가 httpsOnly=false로 HTTP 평문 접근을 허용합니다.",
            platform="azure", evidence=json.dumps(d, ensure_ascii=False), resource=name,
            recommendation="App Service의 'HTTPS Only'를 활성화하고 최소 TLS 버전을 1.2로 설정하세요.",
        ))


def _check_azure_disk_obj(d: dict, findings: list[Finding]) -> None:
    """Azure 관리 디스크(2.7.1). 플랫폼 관리 키만 사용(CMK 미적용)."""
    enc = _val(d, "encryption")
    etype = ""
    if isinstance(enc, dict):
        etype = str(_val(enc, "type", default=""))
    if etype == "EncryptionAtRestWithPlatformKey":
        name = str(_val(d, "name", default="") or "")
        findings.append(_finding(
            "2.7.1", "disk_no_cmk", Severity.LOW,
            f"관리 디스크 CMK 미적용: {name or '(디스크미상)'}",
            "관리 디스크가 플랫폼 관리 키(PMK)만 사용합니다. 규제 요건에 따라 고객 관리 키(CMK)가 필요할 수 있습니다.",
            platform="azure", evidence=json.dumps(d, ensure_ascii=False), resource=name,
            recommendation="규제·내부정책상 필요 시 디스크 암호화 세트(Disk Encryption Set)로 고객 관리 키(CMK)를 적용하세요.",
        ))


def _check_azure_object(d: dict, findings: list[Finding], seen: set) -> None:
    if _val(d, "sourceAddressPrefix", "sourceAddressPrefixes") is not None or (
        _val(d, "direction") is not None and _val(d, "access") is not None
    ):
        _check_nsg_rule_obj(d, findings)

    if _val(d, "httpsOnly", "httpsonly") is not None:
        _check_azure_webapp_obj(d, findings)

    if isinstance(_val(d, "encryption"), dict) and _val(_val(d, "encryption"), "type") is not None \
            and _val(d, "allowBlobPublicAccess") is None and _val(d, "supportsHttpsTrafficOnly") is None:
        _check_azure_disk_obj(d, findings)

    if _looks_like(d, "storage") or _val(d, "supportsHttpsTrafficOnly", "enableHttpsTrafficOnly") is not None \
            or _val(d, "allowBlobPublicAccess") is not None:
        _check_storage_obj(d, findings)

    _sql_flat = json.dumps(d, ensure_ascii=False).lower()
    if _looks_like(d, "sql/servers", "microsoft.sql") \
            or _val(d, "publicNetworkAccess") is not None \
            or _val(d, "serverKeyType") is not None \
            or _val(d, "recurringScans") is not None \
            or _val(d, "weeklyRetention", "monthlyRetention", "yearlyRetention") is not None \
            or _val(d, "privateEndpointConnections") is not None \
            or _val(d, "startIpAddress") is not None \
            or any(k in _sql_flat for k in ("tde", "transparentdataencryption", "audit",
                                            "threatprotection", "advancedthreatprotection",
                                            "vulnerabilityassessment", "ltr")):
        _check_sql_obj(d, findings)

    is_vault_resource = _looks_like(d, "keyvault", "vaults") or (
        _val(d, "enableSoftDelete", "enablePurgeProtection") is not None
        and (_val(d, "name") is not None or _val(d, "type") is not None)
    )
    if is_vault_resource:
        _check_keyvault_obj(d, findings, seen)

    role = str(_val(d, "roleDefinitionName", "role", default=""))
    if role:
        _check_rbac_obj(d, role, findings, seen)


def _check_object(d: dict, findings: list[Finding], seen: set, hint: str | None) -> None:
    """플랫폼 감지 후 해당 검사기로 라우팅. hint는 전체 입력 기반 추정 플랫폼."""
    plat = _detect_platform(d) or hint
    # 이 dict 자체가 어느 플랫폼 리소스인지 명확한 키가 있으면 그쪽 검사를 보장한다
    # (혼합 입력에서 전체 hint가 반대 플랫폼으로 잡혀도 누락되지 않도록).
    has_aws = any(k in {kk.lower() for kk in d if isinstance(kk, str)} for k in (
        "dbinstanceidentifier", "publiclyaccessible", "snapshotid",
        "createvolumepermission", "ippermissions", "groupid",
        "publicaccessblockconfiguration", "policydocument"))
    has_azure = any(k in {kk.lower() for kk in d if isinstance(kk, str)} for k in (
        "httpsonly", "allowblobpublicaccess", "supportshttpstrafficonly",
        "sourceaddressprefix", "roledefinitionname", "publicnetworkaccess"))

    if plat == "aws":
        _check_aws_object(d, findings, seen)
        if has_azure:
            _check_azure_object(d, findings, seen)
    elif plat == "azure":
        _check_azure_object(d, findings, seen)
        if has_aws:
            _check_aws_object(d, findings, seen)
    else:
        # 판단 불가 → 양쪽 다 시도(각 검사기가 자기 키 없으면 그냥 통과)
        _check_azure_object(d, findings, seen)
        _check_aws_object(d, findings, seen)


# ===========================================================================
# 원시 텍스트(정규식) 폴백 검사
# ===========================================================================
def _snippet(text: str, *patterns: str, width: int = 90) -> str:
    """입력 원문에서 패턴이 매칭된 위치 주변 텍스트를 잘라 근거로 반환.

    여러 패턴 중 매칭되는 첫 부분을 찾아 앞뒤 문맥과 함께 돌려준다.
    매칭이 없으면 빈 문자열. 사용자에게 '어떤 텍스트로 판단했는지' 보여주기 위함.
    """
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if not m:
            continue
        # 매칭 텍스트가 근거의 앞쪽에 오도록 앞 문맥은 조금만, 뒤 문맥은 넉넉히.
        start = max(0, m.start() - 12)
        end = min(len(text), m.end() + width)
        frag = text[start:end].strip()
        # 여러 줄이면 한 줄로 압축(가독성).
        frag = re.sub(r"\s+", " ", frag)
        prefix = "…" if start > 0 else ""
        suffix = "…" if end < len(text) else ""
        return f"{prefix}{frag}{suffix}"
    return ""


def _check_raw_text(text: str, findings: list[Finding], existing_types: set, hint: str) -> None:
    """JSON 구조로 못 잡은 부분을 키워드로 보완. 이미 잡힌 유형은 중복 억제."""
    low = text.lower()
    plat = hint or "azure"

    def add(code, itype, sev, title, desc, rec="", platform=None, evidence=""):
        if itype in existing_types:
            return
        existing_types.add(itype)
        # evidence: 입력에서 실제로 매칭된 근거 텍스트. 없으면 안내 문구로 폴백.
        ev = evidence.strip() if evidence else ""
        if not ev:
            ev = "(텍스트 패턴 감지 — 입력에서 해당 키워드 확인)"
        else:
            ev = f"[근거 텍스트] {ev}"
        findings.append(_finding(code, itype, sev, title, desc, recommendation=rec,
                                 platform=platform or plat, evidence=ev))

    # MFA / Conditional Access (Azure)
    if re.search(r"conditional\s*access|conditionalaccess", low):
        if (re.search(r'"state"\s*:\s*"disabled"|disabled', low) and "mfa" in low) or "다단계" in text:
            add("2.5.3", "mfa_ca_disabled", Severity.HIGH,
                "MFA 강제 Conditional Access 미흡",
                "Conditional Access 정책이 Disabled이거나 MFA 강제가 확인되지 않습니다.", platform="azure",
                evidence=_snippet(text, r"conditional\s*access", r"conditionalaccess", r"다단계"))
    # 진단 설정 부재
    if re.search(r"diagnostic[- ]?settings", low) and re.search(r"\[\s*\]|no diagnostic|없음|not configured", low):
        add("2.9.4", "diagnostic_missing", Severity.MEDIUM,
            "진단 설정(Diagnostic Settings) 미구성",
            "핵심 리소스에 진단 설정이 구성되지 않아 로그가 수집되지 않을 수 있습니다.",
            evidence=_snippet(text, r"diagnostic[- ]?settings"))
    # CloudTrail 미구성 (AWS)
    if re.search(r"cloudtrail", low) and re.search(r"\[\s*\]|no trail|not configured|ismultiregion.{0,6}false|미구성", low):
        add("2.9.4", "cloudtrail_missing", Severity.HIGH,
            "CloudTrail 추적 미구성/부분 구성",
            "다중 리전 CloudTrail 추적이 구성되지 않아 감사 로그 사각지대가 있습니다.", platform="aws",
            evidence=_snippet(text, r"ismultiregion[^,}\n]*false", r"no trail", r"cloudtrail"))
    # VPC Flow Logs 미구성 (AWS)
    if re.search(r"flow[- ]?logs?", low) and re.search(r"\[\s*\]|\"?flowlogstatus\"?\s*[:=]\s*\"?inactive|no flow log", low):
        add("2.9.4", "vpc_flowlogs_missing", Severity.MEDIUM,
            "VPC Flow Logs 미구성/비활성",
            "VPC Flow Logs가 구성되지 않았거나 비활성(INACTIVE) 상태로, 네트워크 트래픽 감사 사각지대가 있습니다.",
            platform="aws",
            evidence=_snippet(text, r"flowlogstatus[^,}\n]*inactive", r"no flow log", r"flow[- ]?logs?"))
    # AWS Config 레코더 비활성 (AWS)
    if re.search(r"configurationrecorder|config.{0,10}recorder", low) and \
            re.search(r'"?recording"?\s*[:=]\s*(false|0)|\[\s*\]|not recording', low):
        add("2.10.2", "aws_config_recorder_off", Severity.MEDIUM,
            "AWS Config 레코더 비활성",
            "AWS Config 구성 레코더가 비활성 상태로, 리소스 구성 변경 이력이 기록되지 않습니다.",
            platform="aws",
            evidence=_snippet(text, r"recording[^,}\n]*(false|0)", r"configurationrecorder", r"config.{0,10}recorder"))
    # 백업 실패/LRS
    if re.search(r"lastbackupstatus.{0,10}failed|backup.{0,10}failed|백업.{0,5}실패", low):
        add("2.12.1", "backup_failed", Severity.HIGH,
            "백업 실패 항목 존재", "lastBackupStatus가 Failed인 백업 항목이 있습니다.",
            evidence=_snippet(text, r"lastbackupstatus[^,}\n]*failed", r"backup[^,}\n]{0,10}failed", r"백업.{0,5}실패"))
    if re.search(r"\blrs\b|locallyredundant", low):
        add("2.12.1", "backup_lrs", Severity.MEDIUM,
            "백업 스토리지가 LRS(지역 중복 아님)",
            "백업 스토리지가 LocallyRedundant(LRS)로 지역 재해 시 손실 위험이 있습니다.",
            evidence=_snippet(text, r"locallyredundant", r"\blrs\b"))
    # Defender/GuardDuty 알림
    if (re.search(r'"status"\s*:\s*"active"|active alert', low) and "defender" in low) or "security alert" in low:
        add("2.11.3", "defender_active_alert", Severity.MEDIUM,
            "Defender for Cloud 미해결 Active Alert",
            "Defender for Cloud에 미해결(Active) 보안 경고가 존재할 수 있습니다.", platform="azure",
            evidence=_snippet(text, r"active alert", r"security alert", r'"status"\s*:\s*"active"', r"defender"))
    # 취약점 Unhealthy
    if re.search(r"unhealthy", low):
        add("2.11.2", "assessment_unhealthy", Severity.MEDIUM,
            "취약점 평가 Unhealthy 항목 존재",
            "취약점 평가에서 Unhealthy 상태 항목이 확인됩니다.",
            evidence=_snippet(text, r"unhealthy"))
    # 패치 미적용
    if re.search(r"assess-?patches|update.?management|patch", low) and \
            re.search(r"critical|security|미적용|classificationstoinclude", low):
        add("2.10.8", "patch_pending", Severity.MEDIUM,
            "미적용 보안 패치 가능성",
            "패치 평가 결과 Critical·Security 패치가 미적용 상태일 수 있습니다.",
            evidence=_snippet(text, r"classificationstoinclude[^\]\n]*", r"critical", r"assess-?patches",
                              r"update.?management", r"patch"))
    # CVE 취약점 탐지 (대소문자 무시, 표준 CVE-YYYY-NNNN 형식)
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)
    if cves and "cve_detected" not in existing_types:
        unique = sorted({c.upper() for c in cves})
        sev = Severity.CRITICAL if len(unique) >= 5 else (Severity.HIGH if len(unique) >= 2 else Severity.MEDIUM)
        cve_sample = ", ".join(unique[:10])
        if len(unique) > 10:
            cve_sample += f" 외 {len(unique) - 10}건"
        existing_types.add("cve_detected")
        findings.append(_finding(
            "2.11.2", "cve_detected", sev,
            f"CVE 취약점 {len(unique)}건 발견",
            f"입력에서 CVE 식별자가 {len(unique)}건 탐지되었습니다: {cve_sample}. "
            "해당 취약점의 패치 적용 여부와 영향 범위를 확인하세요.",
            recommendation="각 CVE의 CVSS 점수·영향 범위를 확인하고, 패치 가능한 것은 즉시 적용하세요. "
                           "패치 불가 시 WAF 규칙·네트워크 격리 등 완화 조치를 검토하세요.",
            platform=plat, evidence=cve_sample, resource=f"{len(unique)}건",
        ))


# ===========================================================================
# 엔트리
# ===========================================================================
def _overall_platform_hint(text: str, objects: list) -> str | None:
    """입력 전체 기준의 플랫폼 힌트(객체별 감지가 애매할 때 사용)."""
    votes = {"aws": 0, "azure": 0}
    for obj in objects:
        for d in iter_dicts(obj):
            if isinstance(d, dict) and d:
                p = _detect_platform(d)
                if p:
                    votes[p] += 1
    low = text.lower()
    if "arn:aws" in low or re.search(r"\baws\s+(ec2|iam|s3|cloudtrail)\b", low):
        votes["aws"] += 1
    if "microsoft." in low or re.search(r"\baz\s+(network|storage|keyvault|role|ad)\b", low):
        votes["azure"] += 1
    if votes["aws"] == 0 and votes["azure"] == 0:
        return None
    return "aws" if votes["aws"] > votes["azure"] else "azure"


def analyze(text: str) -> AuditReport:
    """입력 텍스트 전체를 검토해 AuditReport 반환(AWS/Azure 자동 구분)."""
    parsed = parse(text)
    report = AuditReport(input_kind=parsed["kind"], parsed_resources=parsed["object_count"])
    findings: list[Finding] = []
    seen: set = set()

    hint = _overall_platform_hint(parsed["raw_text"], parsed["objects"])

    # 1) JSON 객체 기반 정밀 검사(중첩 dict 모두 순회)
    for obj in parsed["objects"]:
        for d in iter_dicts(obj):
            if isinstance(d, dict) and d:
                _check_object(d, findings, seen, hint)

    # 2) 원시 텍스트 폴백(이미 잡힌 issue_type은 억제)
    existing_types = {f.issue_type for f in findings}
    _check_raw_text(parsed["raw_text"], findings, existing_types, hint or "azure")

    report.findings = findings
    if not findings:
        report.notes.append(
            "탐지된 이슈가 없습니다. 입력이 비었거나, 이 엔진의 점검 대상"
            "(AWS: SG/S3/IAM, Azure: NSG/Storage/SQL/Key Vault/RBAC, 공통: 진단·백업 등) "
            "형식이 아닐 수 있습니다. CLI를 '-o json'으로 내보낸 출력을 넣으면 정밀도가 높아집니다."
        )
    return report
