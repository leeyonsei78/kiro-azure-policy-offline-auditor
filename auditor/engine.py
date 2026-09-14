"""오프라인 판정 엔진 (폐쇄망 전제, 표준 라이브러리만).

Azure CLI 출력 텍스트를 인터넷/AI 없이 정규식·구조 분석으로 검토해
ISMS-P 통제항목 기준의 이슈(Finding)를 산출한다.

설계 원칙(ai-security-suite의 *_offline_engine 패턴 참고):
- JSON으로 파싱되는 입력은 실제 객체 구조를 따라가며 판정(오탐 최소화).
- 명시적 차단 규칙(access=Deny 등)은 '과도 허용'으로 오인하지 않도록 제외.
- 판정 근거/개선안은 knowledge_base(ISMS-P)의 criteria/fix에 연결.
- 어떤 조치도 실행하지 않는다 — 검토와 제안만.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .knowledge_base import control
from .models import AuditReport, Finding, Severity
from .parser import iter_dicts, parse

# --- 공통 정규식 ------------------------------------------------------------
_OPEN_ANY_RE = re.compile(r"(0\.0\.0\.0/0|::/0|\bany\b|internet|^\*$|\"\*\")", re.I)
_DENY_RE = re.compile(r'"?(?:access|action|ruleaction|effect)"?\s*[:=]\s*"?(?:deny|reject|drop|block)"?', re.I)
_INBOUND_RE = re.compile(r'"?direction"?\s*[:=]\s*"?inbound"?', re.I)
_OUTBOUND_RE = re.compile(r'"?direction"?\s*[:=]\s*"?outbound"?', re.I)

_SENSITIVE_PORTS = {
    "22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL",
    "6379": "Redis", "1433": "MSSQL", "27017": "MongoDB", "445": "SMB", "23": "Telnet",
}
_MGMT_PORTS = {"22", "3389", "445", "23"}


def _kb(code: str) -> dict:
    return control(code) or {"domain": "", "fix": "", "criteria": ""}


def _finding(code: str, issue_type: str, severity: Severity, title: str,
             description: str, *, evidence: str = "", resource: str = "",
             recommendation: str = "") -> Finding:
    kb = _kb(code)
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


# --- 개별 검사기 ------------------------------------------------------------
def _check_nsg_rule_obj(rule: dict, findings: list[Finding]) -> None:
    """NSG 규칙 dict 하나 검사(2.6.1 인바운드 과도 허용, 2.6.7 아웃바운드 Any)."""
    flat = json.dumps(rule, ensure_ascii=False)
    # 명시적 Deny면 스킵
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
            evidence=flat, resource=name,
        ))
        return

    # 인바운드(또는 방향 미표기) + Any 소스
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
            evidence=flat, resource=name,
        ))
    elif is_all_ports:
        findings.append(_finding(
            "2.6.1", "nsg_open_all_ports", Severity.HIGH,
            f"NSG 인바운드 전체공개(모든 포트): {name or '(이름없음)'}",
            "출발지가 전체공개(Any/0.0.0.0/0)이고 대상 포트가 전체 범위로 열려 있습니다.",
            evidence=flat, resource=name,
        ))
    else:
        findings.append(_finding(
            "2.6.1", "nsg_open_any", Severity.MEDIUM,
            f"NSG 인바운드 출발지 전체공개: {name or '(이름없음)'}",
            "인바운드 규칙의 출발지가 전체공개(Any/0.0.0.0/0)로 설정되어 있습니다.",
            evidence=flat, resource=name,
        ))


def _looks_like(d: dict, *type_hints: str) -> bool:
    """dict가 특정 리소스 유형인지 키/type 필드로 추정."""
    t = str(_val(d, "type", default="")).lower()
    keys = " ".join(k.lower() for k in d.keys() if isinstance(k, str))
    blob = (t + " " + keys)
    return any(h in blob for h in type_hints)


def _check_object(d: dict, findings: list[Finding], seen: set) -> None:
    """단일 리소스 dict를 유형 추정 후 해당 검사기로 라우팅."""
    # NSG 규칙: sourceAddressPrefix/destinationPortRange/direction 키가 있으면 규칙으로 간주
    if _val(d, "sourceAddressPrefix", "sourceAddressPrefixes") is not None or (
        _val(d, "direction") is not None and _val(d, "access") is not None
    ):
        _check_nsg_rule_obj(d, findings)

    # Storage account
    if _looks_like(d, "storage") or _val(d, "supportsHttpsTrafficOnly", "enableHttpsTrafficOnly") is not None \
            or _val(d, "allowBlobPublicAccess") is not None:
        _check_storage_obj(d, findings)

    # SQL DB / TDE
    if _looks_like(d, "sql/servers", "microsoft.sql") or _val(d, "publicNetworkAccess") is not None \
            or "tde" in json.dumps(d).lower():
        _check_sql_obj(d, findings)

    # Key Vault — name/type가 있는 '리소스 레벨' dict에서만 검사(중첩 properties 조각은 상위에서 이미 처리)
    is_vault_resource = _looks_like(d, "keyvault", "vaults") or (
        _val(d, "enableSoftDelete", "enablePurgeProtection") is not None
        and (_val(d, "name") is not None or _val(d, "type") is not None)
    )
    if is_vault_resource:
        _check_keyvault_obj(d, findings, seen)

    # RBAC role assignment
    role = str(_val(d, "roleDefinitionName", "role", default=""))
    if role:
        _check_rbac_obj(d, role, findings, seen)


def _check_storage_obj(d: dict, findings: list[Finding]) -> None:
    name = str(_val(d, "name", default="") or "")
    flat = json.dumps(d, ensure_ascii=False)
    https_only = _val(d, "supportsHttpsTrafficOnly", "enableHttpsTrafficOnly")
    if https_only is False or str(https_only).lower() == "false":
        findings.append(_finding(
            "2.7.1", "storage_https_disabled", Severity.HIGH,
            f"Storage HTTPS 전용 미설정: {name or '(이름없음)'}",
            "Storage Account가 HTTP 평문 전송을 허용합니다(supportsHttpsTrafficOnly=false).",
            evidence=flat, resource=name,
            recommendation="Storage Account의 '보안 전송 필수(HTTPS only)'를 활성화하고, 최소 TLS 버전을 1.2로 설정하세요.",
        ))
    public = _val(d, "allowBlobPublicAccess")
    if public is True or str(public).lower() == "true":
        findings.append(_finding(
            "2.7.1", "storage_public_blob", Severity.HIGH,
            f"Storage 퍼블릭 Blob 접근 허용: {name or '(이름없음)'}",
            "Storage Account가 익명 Blob 퍼블릭 접근을 허용합니다(allowBlobPublicAccess=true).",
            evidence=flat, resource=name,
            recommendation="allowBlobPublicAccess를 false로 설정하고, 필요한 공유는 SAS·Private Endpoint로 대체하세요.",
        ))
    tls = str(_val(d, "minimumTlsVersion", "minimumTLSVersion", default=""))
    if tls and re.search(r"1[._]?0|1[._]?1|tls1_0|tls1_1", tls, re.I):
        findings.append(_finding(
            "2.7.1", "storage_weak_tls", Severity.MEDIUM,
            f"Storage 약한 TLS 버전: {name or '(이름없음)'} ({tls})",
            f"Storage Account 최소 TLS 버전이 {tls}로 취약합니다(TLS 1.2 미만).",
            evidence=flat, resource=name,
            recommendation="최소 TLS 버전을 1.2 이상으로 설정하세요.",
        ))


def _check_sql_obj(d: dict, findings: list[Finding]) -> None:
    name = str(_val(d, "name", default="") or "")
    flat = json.dumps(d, ensure_ascii=False)
    # TDE 상태
    tde = _val(d, "state", "status")
    tde_ctx = "tde" in flat.lower() or "transparentdataencryption" in flat.lower()
    if tde_ctx and str(tde).lower() in ("disabled", "false", "off"):
        findings.append(_finding(
            "2.7.1", "sql_tde_disabled", Severity.HIGH,
            f"SQL TDE 비활성화: {name or '(이름없음)'}",
            "SQL Database의 투명한 데이터 암호화(TDE)가 비활성화되어 저장 데이터가 암호화되지 않습니다.",
            evidence=flat, resource=name,
        ))
    pub = str(_val(d, "publicNetworkAccess", default=""))
    if pub.lower() in ("enabled", "true"):
        findings.append(_finding(
            "2.6.1", "sql_public_access", Severity.HIGH,
            f"SQL 퍼블릭 네트워크 접근 허용: {name or '(이름없음)'}",
            "SQL 서버/DB가 퍼블릭 네트워크 접근을 허용합니다(publicNetworkAccess=Enabled).",
            evidence=flat, resource=name,
            recommendation="publicNetworkAccess를 Disabled로 두고 Private Endpoint·서비스 엔드포인트로만 접근하도록 제한하세요.",
        ))


def _check_keyvault_obj(d: dict, findings: list[Finding], seen: set) -> None:
    name = str(_val(d, "name", default="") or "")
    flat = json.dumps(d, ensure_ascii=False)
    props = _val(d, "properties")
    src = props if isinstance(props, dict) else d
    soft = _val(src, "enableSoftDelete", "softDelete")
    purge = _val(src, "enablePurgeProtection", "purgeProtection")
    # 이름 기준(없으면 내용 해시) 중복 억제 — vault dict와 그 properties dict가 이중 순회되어도 1회만
    vault_key = name or json.dumps(src, sort_keys=True, ensure_ascii=False)[:80]
    if ("kv", vault_key) in seen:
        return
    seen.add(("kv", vault_key))
    if soft is False or str(soft).lower() == "false":
        findings.append(_finding(
            "2.7.2", "keyvault_softdelete_off", Severity.MEDIUM,
            f"Key Vault Soft-delete 비활성화: {name or '(이름없음)'}",
            "Key Vault의 Soft-delete가 비활성화되어 키·비밀이 실수로 영구 삭제될 위험이 있습니다.",
            evidence=flat, resource=name,
        ))
    if purge is False or str(purge).lower() == "false":
        findings.append(_finding(
            "2.7.2", "keyvault_purge_off", Severity.MEDIUM,
            f"Key Vault Purge Protection 비활성화: {name or '(이름없음)'}",
            "Key Vault의 Purge Protection이 비활성화되어 삭제 대기 중인 키를 강제 영구 삭제할 수 있습니다.",
            evidence=flat, resource=name,
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
            evidence=json.dumps(d, ensure_ascii=False), resource=principal,
        ))


# --- 원시 텍스트(정규식) 폴백 검사 -----------------------------------------
def _check_raw_text(text: str, findings: list[Finding], existing_types: set) -> None:
    """JSON 구조로 못 잡은 부분을 키워드로 보완. 이미 잡힌 유형은 중복 억제."""
    low = text.lower()

    def add(code, itype, sev, title, desc, rec=""):
        if itype in existing_types:
            return
        existing_types.add(itype)
        findings.append(_finding(code, itype, sev, title, desc, recommendation=rec, evidence="(텍스트 패턴 감지)"))

    # MFA / Conditional Access
    if re.search(r"conditional\s*access|conditionalaccess", low):
        if re.search(r'"state"\s*:\s*"disabled"|disabled', low) and "mfa" in low or "다단계" in text:
            add("2.5.3", "mfa_ca_disabled", Severity.HIGH,
                "MFA 강제 Conditional Access 미흡",
                "Conditional Access 정책이 Disabled이거나 MFA 강제가 확인되지 않습니다.")
    # 진단 설정 부재 힌트
    if re.search(r"diagnostic[- ]?settings", low) and re.search(r"\[\s*\]|no diagnostic|없음|not configured", low):
        add("2.9.4", "diagnostic_missing", Severity.MEDIUM,
            "진단 설정(Diagnostic Settings) 미구성",
            "핵심 리소스에 진단 설정이 구성되지 않아 로그가 수집되지 않을 수 있습니다.")
    # 백업 실패/LRS
    if re.search(r"lastbackupstatus.{0,10}failed|backup.{0,10}failed|백업.{0,5}실패", low):
        add("2.12.1", "backup_failed", Severity.HIGH,
            "백업 실패 항목 존재",
            "lastBackupStatus가 Failed인 백업 항목이 있습니다.")
    if re.search(r"\blrs\b|locallyredundant", low):
        add("2.12.1", "backup_lrs", Severity.MEDIUM,
            "백업 스토리지가 LRS(지역 중복 아님)",
            "백업 스토리지가 LocallyRedundant(LRS)로 지역 재해 시 손실 위험이 있습니다.")
    # Defender 미해결 알림
    if re.search(r'"status"\s*:\s*"active"|active alert', low) and "defender" in low or "security alert" in low:
        add("2.11.3", "defender_active_alert", Severity.MEDIUM,
            "Defender for Cloud 미해결 Active Alert",
            "Defender for Cloud에 미해결(Active) 보안 경고가 존재할 수 있습니다.")
    # 취약점 Unhealthy
    if re.search(r"unhealthy", low):
        add("2.11.2", "assessment_unhealthy", Severity.MEDIUM,
            "취약점 평가 Unhealthy 항목 존재",
            "Defender 취약점 평가에서 Unhealthy 상태 항목이 확인됩니다.")
    # 패치 미적용
    if re.search(r"assess-?patches|update.?management|patch", low) and re.search(r"critical|security|미적용|classificationstoinclude", low):
        add("2.10.8", "patch_pending", Severity.MEDIUM,
            "미적용 보안 패치 가능성",
            "패치 평가 결과 Critical·Security 패치가 미적용 상태일 수 있습니다.")


def analyze(text: str) -> AuditReport:
    """입력 텍스트 전체를 검토해 AuditReport 반환."""
    parsed = parse(text)
    report = AuditReport(input_kind=parsed["kind"], parsed_resources=parsed["object_count"])
    findings: list[Finding] = []
    seen: set = set()

    # 1) JSON 객체 기반 정밀 검사(중첩 dict 모두 순회)
    for obj in parsed["objects"]:
        for d in iter_dicts(obj):
            if isinstance(d, dict) and d:
                _check_object(d, findings, seen)

    # 2) 원시 텍스트 폴백(이미 잡힌 issue_type은 억제)
    existing_types = {f.issue_type for f in findings}
    _check_raw_text(parsed["raw_text"], findings, existing_types)

    report.findings = findings
    if not findings:
        report.notes.append(
            "탐지된 이슈가 없습니다. 입력이 비었거나, 이 엔진의 점검 대상(NSG/Storage/SQL/"
            "Key Vault/RBAC/진단·백업·Defender 등) 형식이 아닐 수 있습니다. "
            "az CLI를 '-o json'으로 내보낸 출력을 함께 넣으면 정밀도가 높아집니다."
        )
    return report
