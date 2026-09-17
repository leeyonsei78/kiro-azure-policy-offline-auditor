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


# ---------------------------------------------------------------------------
# 개인정보(PII)·시크릿(자격증명) 탐지 패턴 (ISMS-P 개인정보 보호 강화)
# 폐쇄망 전제로 정규식만 사용. 오탐을 줄이기 위해 형식이 뚜렷한 것만 탐지한다.
# ---------------------------------------------------------------------------
# (라벨, 정규식, 심각도)
_PII_PATTERNS = [
    # 주민등록번호: 6자리-7자리, 뒷자리 첫 숫자 1~4(내국인)/5~8(외국인)
    ("주민등록번호", re.compile(r"\b\d{6}[-\s]?[1-8]\d{6}\b"), "CRITICAL"),
    # 신용카드번호: 4-4-4-4 (공백/하이픈 허용). 이후 Luhn으로 2차 검증
    ("신용카드번호", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "CRITICAL"),
    # 이메일
    ("이메일주소", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "MEDIUM"),
    # 휴대전화번호 (한국): 010-XXXX-XXXX 등
    ("휴대전화번호", re.compile(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b"), "MEDIUM"),
]

# 시크릿/자격증명 하드코딩 패턴
_SECRET_PATTERNS = [
    ("AWS 액세스 키 ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "CRITICAL"),
    ("AWS 시크릿 액세스 키", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"), "CRITICAL"),
    ("비밀번호 하드코딩", re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\";,}]{4,}"), "HIGH"),
    ("커넥션 문자열 비밀번호", re.compile(r"(?i)(?:pwd|password)\s*=\s*[^;'\"\s]{4,}"), "HIGH"),
    ("Bearer/JWT 토큰", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"), "HIGH"),
    ("Private Key 블록", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "CRITICAL"),
    ("Slack 토큰", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "HIGH"),
    ("Azure 저장소 키(AccountKey)", re.compile(r"(?i)AccountKey\s*=\s*[A-Za-z0-9/+=]{40,}"), "CRITICAL"),
]


def _luhn_ok(number: str) -> bool:
    """신용카드번호 Luhn 체크(오탐 감소). 숫자만 남겨 13~16자리일 때만 검증."""
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not (13 <= len(digits) <= 16):
        return False
    total, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _mask(s: str) -> str:
    """근거로 보여줄 때 민감값을 부분 마스킹(앞 2~4자만 노출)."""
    s = s.strip()
    if len(s) <= 4:
        return "*" * len(s)
    keep = 4 if len(s) > 8 else 2
    return s[:keep] + "*" * (len(s) - keep)


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
    "pii_exposed": {
        "bad": "로그/설정에 평문: 주민번호 900101-1234567, 이메일 hong@corp.com",
        "good": "개인정보는 저장·로그에서 마스킹(9001**-*******)·암호화, 수집 최소화",
    },
    "secret_exposed": {
        "bad": "코드/설정에 평문: password=P@ssw0rd!, AKIAIOSFODNN7EXAMPLE",
        "good": "Secrets Manager/Key Vault로 이전, 코드엔 참조만, 노출 키 즉시 폐기·교체",
    },
    "eks_public_api": {
        "bad": "endpointPublicAccess: true, publicAccessCidrs: [0.0.0.0/0]",
        "good": "endpointPublicAccess: false(프라이빗) 또는 publicAccessCidrs를 회사 IP로 제한",
    },
    "aks_public_api": {
        "bad": "enablePrivateCluster: false, authorizedIpRanges: [] (전체 공개)",
        "good": "enablePrivateCluster: true 또는 authorizedIpRanges에 회사 IP만 등록",
    },
    "aks_rbac_disabled": {
        "bad": "enableRbac: false",
        "good": "enableRbac: true (+ Azure AD 통합 RBAC 권장)",
    },
    "apigw_no_auth": {
        "bad": "API Gateway 메서드 authorizationType: NONE, apiKeyRequired: false",
        "good": "IAM/Cognito/Lambda Authorizer 적용, 또는 최소한 API Key + 사용량 계획",
    },
}


# 이슈 유형별 '왜 문제인지(why)'와 '어떻게 해결하는지(how_to_fix, 단계별)' 설명.
# 초보 담당자가 배경지식 없이도 위험과 조치 절차를 이해하도록 쉬운 말로 작성한다.
_EXPLAIN: dict[str, dict[str, str]] = {
    # ---- AWS 네트워크/접근 ----
    "aws_sg_open_sensitive_port": {
        "why": "서버 관리용 포트(SSH 22·RDP 3389 등)가 전 세계 인터넷(0.0.0.0/0)에 열려 있습니다. "
               "공격자는 이런 포트를 자동으로 찾아 무차별 대입(비밀번호 추측)·알려진 취약점 공격을 시도합니다. "
               "즉 계정 하나만 뚫려도 서버가 통째로 장악될 수 있는 상태입니다.",
        "how_to_fix": "1) 이 규칙이 정말 전체 공개가 필요한지 확인합니다(대부분 불필요).\n"
                      "2) 출발지(Source)를 회사 고정 IP나 내부 서브넷(예: 10.0.0.0/16)으로 좁힙니다.\n"
                      "3) 관리 접속은 Bastion 호스트나 SSM Session Manager를 경유하도록 바꿉니다.\n"
                      "4) 변경 후 실제 접속이 되는지 확인하고, 불필요한 규칙은 삭제합니다.",
    },
    "aws_sg_open_any": {
        "why": "보안그룹이 모든 출발지(0.0.0.0/0)의 접근을 허용합니다. 열린 포트에 따라 위험도가 달라지지만, "
               "출발지 제한이 없으면 공격 표면이 불필요하게 넓어집니다.",
        "how_to_fix": "1) 이 규칙으로 어떤 서비스가 외부에 노출되는지 확인합니다.\n"
                      "2) 웹 서비스(80/443)처럼 공개가 필요한 것만 남기고, 나머지는 출발지를 제한합니다.\n"
                      "3) 공개가 필요한 경우에도 WAF·CloudFront 등을 앞단에 두는 것을 검토합니다.",
    },
    "aws_rds_public": {
        "why": "데이터베이스가 인터넷에서 직접 접근 가능하도록 설정돼 있습니다. DB에는 보통 개인정보·업무 핵심 "
               "데이터가 들어 있어, 노출되면 유출·랜섬웨어의 1순위 표적이 됩니다.",
        "how_to_fix": "1) RDS 콘솔에서 해당 인스턴스의 '퍼블릭 액세스 가능'을 '아니오'로 변경합니다.\n"
                      "2) DB를 프라이빗 서브넷에 두고, 애플리케이션 서버에서만 접근하도록 보안그룹을 설정합니다.\n"
                      "3) 외부 접속이 꼭 필요하면 VPN이나 Bastion을 경유하게 합니다.",
    },
    # ---- AWS 암호화/노출 ----
    "aws_s3_public_block_off": {
        "why": "S3 버킷의 퍼블릭 접근 차단이 일부 꺼져 있습니다. 이 상태에서 실수로 공개 ACL·정책이 붙으면 "
               "버킷 안 파일이 인터넷 누구에게나 노출됩니다(데이터 유출 사고의 대표 원인).",
        "how_to_fix": "1) S3 콘솔 > 해당 버킷 > 권한 > '퍼블릭 액세스 차단' 4개 옵션을 모두 켭니다.\n"
                      "2) 계정 레벨에서도 퍼블릭 차단을 켜 조직 전체에 안전망을 둡니다.\n"
                      "3) 외부 공유가 필요한 파일은 CloudFront(OAC)나 서명된 URL로 대체합니다.",
    },
    "aws_s3_public_policy": {
        "why": "버킷 정책이 모든 사용자(Principal:*)에게 접근을 허용합니다. 인증 없이 누구나 파일을 읽거나 "
               "쓸 수 있어, 데이터 유출·변조 위험이 매우 큽니다.",
        "how_to_fix": "1) 버킷 정책에서 \"Principal\":\"*\" 를 제거합니다.\n"
                      "2) 접근이 필요한 특정 IAM 역할/사용자만 명시적으로 허용합니다.\n"
                      "3) 웹 배포용이면 CloudFront + OAC 조합으로 바꿉니다.",
    },
    "aws_s3_no_encryption": {
        "why": "버킷에 기본 암호화가 없어, 저장된 데이터가 평문으로 보관됩니다. 저장 매체 유출·권한 오설정 시 "
               "내용이 그대로 노출됩니다.",
        "how_to_fix": "1) S3 콘솔 > 버킷 > 속성 > '기본 암호화'를 켭니다(SSE-KMS 권장).\n"
                      "2) 민감 데이터는 전용 KMS 키를 사용하고 키 접근 권한을 최소화합니다.",
    },
    "aws_ebs_snapshot_public": {
        "why": "디스크 스냅샷이 전체 공개(all)로 공유돼 있습니다. 누구나 이 스냅샷으로 볼륨을 만들어 원본 "
               "디스크의 모든 데이터를 복원해 볼 수 있습니다.",
        "how_to_fix": "1) EC2 콘솔 > 스냅샷 > 권한 수정에서 '퍼블릭' 공유를 해제합니다.\n"
                      "2) 공유가 필요하면 특정 AWS 계정 ID에만 공유합니다.\n"
                      "3) 실수 재발 방지를 위해 '스냅샷 퍼블릭 공유 차단' 계정 설정을 켭니다.",
    },
    # ---- AWS IAM/자격증명 ----
    "aws_iam_wildcard_admin": {
        "why": "모든 작업(Action:*)을 모든 리소스(Resource:*)에 허용하는 전권 정책입니다. 이 자격증명이 "
               "유출되면 공격자가 계정 전체를 마음대로 할 수 있습니다(최소권한 원칙 위배).",
        "how_to_fix": "1) 이 정책을 실제로 필요한 작업·리소스만 허용하도록 분리합니다.\n"
                      "2) 관리자 권한은 소수의 담당자에게만, 그것도 역할(Role) 전환 방식으로 부여합니다.\n"
                      "3) IAM Access Analyzer로 실제 사용된 권한을 확인해 과다 권한을 줄입니다.",
    },
    "aws_iam_no_mfa": {
        "why": "콘솔에 로그인할 수 있는 사용자가 MFA(2단계 인증) 없이 비밀번호만으로 접근합니다. 비밀번호가 "
               "유출되면 바로 계정이 탈취됩니다.",
        "how_to_fix": "1) 해당 사용자에게 MFA 기기(앱 OTP 등)를 등록하게 합니다.\n"
                      "2) IAM 정책 조건(aws:MultiFactorAuthPresent)으로 MFA 없는 접근을 차단합니다.\n"
                      "3) 가능하면 IAM Identity Center(SSO)로 통합해 MFA를 일괄 강제합니다.",
    },
    "aws_root_access_key": {
        "why": "루트 계정에 액세스 키가 있습니다. 루트는 계정의 모든 권한을 갖기 때문에, 이 키가 유출되면 "
               "청구·계정 삭제까지 포함해 무엇이든 가능해집니다(가장 위험).",
        "how_to_fix": "1) 루트 액세스 키를 즉시 삭제합니다(콘솔 > 내 보안 자격 증명).\n"
                      "2) 루트에는 MFA를 등록하고 평소에는 사용하지 않습니다.\n"
                      "3) 일상 작업은 권한을 나눈 IAM 사용자·역할로 수행합니다.",
    },
    # ---- AWS 로깅/거버넌스 ----
    "cloudtrail_missing": {
        "why": "누가 언제 무엇을 했는지 기록하는 감사 로그(CloudTrail)가 없거나 일부 리전만 켜져 있습니다. "
               "사고가 나도 원인 추적·법적 대응이 어렵습니다.",
        "how_to_fix": "1) 모든 리전을 포함하는 CloudTrail 추적을 하나 만듭니다.\n"
                      "2) 로그 파일 무결성 검증과 KMS 암호화를 켭니다.\n"
                      "3) 조직 계정이면 Organization Trail로 전 계정을 한 번에 기록합니다.",
    },
    "vpc_flowlogs_missing": {
        "why": "네트워크 통신 기록(Flow Logs)이 없습니다. 침해 시 어떤 IP가 어디로 접속했는지 확인할 수 "
               "없어 사고 분석이 힘듭니다. AWS에서는 VPC Flow Logs, Azure에서는 NSG Flow Logs를 활성화해야 합니다.",
        "how_to_fix": "1) 각 VPC/NSG에 Flow Logs를 켜고 저장 대상(S3/CloudWatch 또는 Storage/Log Analytics)을 지정합니다.\n"
                      "2) 로그를 정기적으로 검토하거나 이상 탐지에 연동합니다.",
    },
    "aws_config_recorder_off": {
        "why": "리소스 설정 변경 이력을 기록하는 AWS Config가 꺼져 있습니다. 언제 누가 설정을 바꿔 보안 구멍이 "
               "생겼는지 추적할 수 없습니다.",
        "how_to_fix": "1) 전 리전에서 AWS Config 레코더를 활성화합니다.\n"
                      "2) 규정 준수 규칙(Conformance Pack)을 적용해 위반 설정을 자동 감지합니다.",
    },
    # ---- Azure 네트워크/접근 ----
    "nsg_open_sensitive_port": {
        "why": "관리용 포트(SSH 22·RDP 3389 등)가 인터넷 전체에 열려 있습니다. 공격자가 자동 스캔으로 찾아 "
               "무차별 대입·취약점 공격을 시도하므로, 서버 탈취로 이어지기 쉽습니다.",
        "how_to_fix": "1) NSG 규칙의 원본(Source)을 회사 IP/서브넷으로 좁힙니다.\n"
                      "2) 관리 접속은 Azure Bastion을 경유하도록 바꿉니다.\n"
                      "3) 상시 개방 대신 JIT(Just-In-Time) VM 액세스로 필요할 때만 잠깐 엽니다.",
    },
    "nsg_open_all_ports": {
        "why": "출발지도 전체(Any)이고 대상 포트도 전 범위로 열려 있습니다. 사실상 방화벽이 없는 것과 같아 "
               "모든 서비스가 인터넷에 노출됩니다.",
        "how_to_fix": "1) 이 규칙을 삭제하거나, 꼭 필요한 포트만 남깁니다.\n"
                      "2) 원본 IP를 최소 범위로 제한합니다.\n"
                      "3) 규칙 우선순위를 점검해 광범위 허용 규칙이 앞서지 않도록 합니다.",
    },
    "nsg_open_any": {
        "why": "인바운드 규칙의 출발지가 인터넷 전체(Any)입니다. 열린 포트에 따라 위험이 커지므로 출발지 제한이 필요합니다.",
        "how_to_fix": "1) 필요한 CIDR·서비스 태그로 출발지를 제한합니다.\n"
                      "2) 공개가 필요한 서비스는 앞단에 WAF/Application Gateway를 둡니다.",
    },
    "nsg_outbound_any": {
        "why": "내부에서 인터넷으로 나가는 통신이 전부 허용돼 있습니다. 서버가 감염되면 데이터를 외부로 빼내거나(유출) "
               "공격 서버와 통신하는 것을 막지 못합니다.",
        "how_to_fix": "1) 아웃바운드 목적지를 업무에 필요한 서비스 태그/IP로 제한합니다.\n"
                      "2) 인터넷 접근이 필요한 경우 프록시/방화벽을 경유하게 합니다.",
    },
    # ---- Azure 암호화/노출 ----
    "storage_https_disabled": {
        "why": "저장소가 HTTP(평문) 전송을 허용합니다. 중간에서 통신을 가로채면(스니핑) 데이터·접근 키가 그대로 "
               "노출될 수 있습니다.",
        "how_to_fix": "1) 저장소 계정 > 구성에서 '보안 전송 필수(HTTPS only)'를 켭니다.\n"
                      "2) 최소 TLS 버전을 1.2로 설정합니다.",
    },
    "storage_public_blob": {
        "why": "익명 사용자가 인증 없이 Blob(파일)에 접근할 수 있습니다. 저장된 파일이 인터넷에 그대로 공개될 수 있어 "
               "데이터 유출의 흔한 원인입니다.",
        "how_to_fix": "1) 저장소 계정 > 구성에서 'Blob 공용 액세스 허용'을 사용 안 함으로 바꿉니다.\n"
                      "2) 공유가 필요하면 만료 시간이 있는 SAS 토큰이나 Private Endpoint를 사용합니다.",
    },
    "storage_weak_tls": {
        "why": "낮은 TLS 버전(1.0/1.1)을 허용합니다. 오래된 암호화는 알려진 공격에 취약해 통신 내용이 해독될 수 있습니다.",
        "how_to_fix": "1) 저장소 계정의 최소 TLS 버전을 1.2 이상으로 설정합니다.\n"
                      "2) 오래된 클라이언트가 있으면 업그레이드 후 적용합니다.",
    },
    "webapp_https_disabled": {
        "why": "웹앱이 HTTP 평문 접속을 허용합니다. 로그인 정보·세션이 중간에서 탈취될 수 있습니다.",
        "how_to_fix": "1) App Service > 구성에서 'HTTPS 전용'을 켭니다.\n"
                      "2) 최소 TLS 1.2, HSTS 헤더 적용을 검토합니다.",
    },
    "disk_no_cmk": {
        "why": "디스크가 플랫폼 기본 키로만 암호화됩니다. 데이터 자체는 암호화되어 있으나, 금융·규제 환경에서는 "
               "키를 직접 관리(CMK)하도록 요구하는 경우가 많습니다.",
        "how_to_fix": "1) 규제·내부정책상 CMK가 필요한지 확인합니다.\n"
                      "2) 필요 시 디스크 암호화 세트(Disk Encryption Set)로 고객 관리 키(CMK)를 적용합니다.",
    },
    # ---- Azure Key Vault ----
    "keyvault_softdelete_off": {
        "why": "키 저장소의 소프트 삭제가 꺼져 있어, 키·비밀을 실수로 지우면 즉시 영구 삭제되어 복구할 수 없습니다.",
        "how_to_fix": "1) Key Vault의 Soft-delete를 활성화합니다(기본 보존 90일).\n"
                      "2) 함께 Purge Protection도 켜 강제 영구삭제를 막습니다.",
    },
    "keyvault_purge_off": {
        "why": "삭제 대기 중인 키를 강제로 완전 삭제(purge)할 수 있는 상태입니다. 악의적/실수로 키가 사라지면 "
               "암호화된 데이터를 영영 열 수 없게 됩니다.",
        "how_to_fix": "1) Key Vault의 Purge Protection을 활성화합니다.\n"
                      "2) 키 관리 권한을 최소한의 담당자에게만 부여합니다.",
    },
    # ---- Azure RBAC ----
    "rbac_privileged_assignment": {
        "why": "Owner처럼 광범위한 권한이 여러 사람에게 상시 부여돼 있습니다. 계정 하나만 탈취돼도 피해 범위가 "
               "구독 전체로 커집니다.",
        "how_to_fix": "1) 실제 업무에 맞는 최소 권한 역할(Reader/Contributor 등)로 낮춥니다.\n"
                      "2) 관리 권한은 PIM으로 필요할 때만 승격받도록(JIT) 바꿉니다.\n"
                      "3) 정기적으로 액세스 검토(Access Review)를 수행합니다.",
    },
    # ---- 공통 텍스트 폴백 ----
    "mfa_ca_disabled": {
        "why": "MFA(2단계 인증)를 강제하는 정책이 없거나 꺼져 있습니다. 비밀번호만으로 로그인하면 유출 시 바로 "
               "계정이 탈취됩니다.",
        "how_to_fix": "1) Conditional Access 정책으로 전 사용자·관리자에게 MFA를 강제합니다.\n"
                      "2) 간단히 하려면 Security Defaults를 켭니다.\n"
                      "3) 특권 계정은 승격 시 MFA 재인증을 필수화합니다.",
    },
    "diagnostic_missing": {
        "why": "리소스의 진단 로그가 수집되지 않습니다. 문제가 생겨도 원인을 파악할 로그가 없어 대응이 늦어집니다.",
        "how_to_fix": "1) 핵심 리소스의 진단 설정을 Log Analytics/Storage로 보냅니다.\n"
                      "2) Azure Policy(Deploy if not exists)로 신규 리소스에 자동 적용합니다.",
    },
    "backup_failed": {
        "why": "백업이 실패한 항목이 있습니다. 이 상태에서 장애·랜섬웨어가 발생하면 데이터를 복구하지 못할 수 있습니다.",
        "how_to_fix": "1) 실패 원인(권한·용량·네트워크)을 확인해 조치 후 재실행합니다.\n"
                      "2) 백업 성공/실패 알림을 구성해 실패를 즉시 인지합니다.\n"
                      "3) 주기적으로 복구 테스트를 수행합니다.",
    },
    "backup_lrs": {
        "why": "백업이 같은 지역에만 저장(LRS)됩니다. 지역 단위 재해가 발생하면 원본과 백업이 함께 손실될 수 있습니다.",
        "how_to_fix": "1) 백업 스토리지를 지역 중복(GRS/RA-GRS)으로 전환합니다.\n"
                      "2) 중요 데이터는 별도 리전 복제본을 검토합니다.",
    },
    "defender_active_alert": {
        "why": "보안 위협 경고가 해결되지 않은 채 남아 있습니다. 실제 공격이 진행 중일 수 있어 방치하면 피해가 커집니다.",
        "how_to_fix": "1) 각 경고의 심각도·영향을 확인해 우선순위대로 조치합니다.\n"
                      "2) 조치 후 경고를 '해결' 처리해 현황을 명확히 유지합니다.\n"
                      "3) Microsoft Sentinel과 연동해 상관분석·자동대응을 구성합니다.",
    },
    "assessment_unhealthy": {
        "why": "취약점 평가에서 '비정상(Unhealthy)' 항목이 확인됐습니다. 알려진 약점이 방치되면 침해 통로가 됩니다.",
        "how_to_fix": "1) Defender for Cloud 권고 사항을 확인해 하나씩 조치합니다.\n"
                      "2) 보안 점수(Secure Score) 목표를 세워 지속 관리합니다.",
    },
    "patch_pending": {
        "why": "중요(Critical/Security) 보안 패치가 적용되지 않았습니다. 미적용 취약점은 공격자의 주요 침투 경로입니다.",
        "how_to_fix": "1) Azure Update Manager로 대상 시스템의 패치 현황을 확인합니다.\n"
                      "2) 정기 패치 일정을 수립해 자동 적용합니다.\n"
                      "3) 즉시 적용이 어려우면 임시 완화책(접근 제한)을 둡니다.",
    },
    "cve_detected": {
        "why": "입력에서 알려진 취약점 식별자(CVE)가 발견됐습니다. CVE는 공개된 약점이라 공격 코드가 이미 도는 "
               "경우가 많아 신속한 대응이 필요합니다.",
        "how_to_fix": "1) 각 CVE의 심각도(CVSS)와 영향 범위를 확인합니다.\n"
                      "2) 패치가 있으면 우선순위대로 적용합니다.\n"
                      "3) 패치가 없으면 WAF 규칙·네트워크 격리 등 완화책을 적용합니다.",
    },
    "pii_exposed": {
        "why": "주민등록번호·카드번호·이메일 같은 개인정보가 로그·설정·환경변수에 평문으로 남아 있습니다. "
               "이런 곳은 접근 통제가 느슨해 유출 시 그대로 노출되고, ISMS-P·개인정보보호법 위반이 됩니다.",
        "how_to_fix": "1) 해당 개인정보가 왜 여기 저장/기록되는지 원인을 찾습니다(로그 과다 기록 등).\n"
                      "2) 로그·설정에서 개인정보를 제거하거나 마스킹(예: 뒷자리 ***)합니다.\n"
                      "3) 저장이 꼭 필요하면 암호화(TDE/컬럼 암호화)하고 접근 권한을 최소화합니다.\n"
                      "4) 개인정보 수집·보관 최소화 원칙을 적용합니다.",
    },
    "secret_exposed": {
        "why": "비밀번호·API 키·토큰 같은 자격증명이 코드·설정·로그에 그대로 적혀 있습니다. "
               "이 값이 유출되면 공격자가 바로 로그인·API 호출을 할 수 있어 계정 탈취로 직결됩니다.",
        "how_to_fix": "1) 노출된 키·비밀번호를 즉시 폐기하고 새로 발급(rotate)합니다 — 이미 유출됐다고 가정.\n"
                      "2) 시크릿을 AWS Secrets Manager / Azure Key Vault로 옮기고, 코드에서는 참조만 합니다.\n"
                      "3) 소스 이력(git)에 남았으면 이력에서도 제거합니다.\n"
                      "4) 커밋 전 시크릿 검사(pre-commit hook 등)를 도입합니다.",
    },
    "eks_public_api": {
        "why": "쿠버네티스 클러스터의 관리 API(kube-apiserver)가 인터넷에 공개돼 있습니다. "
               "공격자가 API 취약점·탈취된 토큰으로 접근하면 클러스터 전체(모든 컨테이너)를 장악할 수 있습니다.",
        "how_to_fix": "1) 클러스터 API 엔드포인트를 프라이빗으로 전환하거나,\n"
                      "2) 퍼블릭 접근이 필요하면 접근 허용 CIDR를 회사 IP로 제한합니다.\n"
                      "3) 감사 로그(Audit)와 RBAC을 함께 강화합니다.",
    },
    "aks_public_api": {
        "why": "AKS 관리 API가 인터넷에 공개돼 있습니다. 프라이빗 클러스터가 아니고 승인 IP 제한도 없으면 "
               "누구나 API에 접근 시도가 가능해 클러스터 침해 위험이 큽니다.",
        "how_to_fix": "1) 프라이빗 클러스터로 만들거나(신규 생성 시),\n"
                      "2) 기존 클러스터는 '승인된 IP 범위'에 회사 IP만 등록합니다.\n"
                      "3) Azure AD 통합 RBAC을 활성화합니다.",
    },
    "aks_rbac_disabled": {
        "why": "쿠버네티스 RBAC이 꺼져 있어 세분화된 권한 통제가 안 됩니다. 한 계정이 뚫리면 "
               "클러스터 전체 리소스에 접근할 수 있습니다.",
        "how_to_fix": "1) RBAC은 클러스터 생성 시 활성화해야 합니다(기존 클러스터는 재생성 필요).\n"
                      "2) Azure AD 통합 인증 + 네임스페이스별 최소권한 Role을 적용합니다.",
    },
    "apigw_no_auth": {
        "why": "API Gateway 엔드포인트에 인증이 없어 누구나 호출할 수 있습니다. 백엔드 데이터 조회·변경, "
               "요금 폭탄(과도한 호출)으로 이어질 수 있습니다.",
        "how_to_fix": "1) 메서드에 인증(IAM/Cognito/Lambda Authorizer)을 적용합니다.\n"
                      "2) 최소한 API Key + 사용량 계획(Usage Plan)으로 호출을 제한합니다.\n"
                      "3) 앞단에 WAF를 두어 악성 요청을 차단합니다.",
    },
}


# 이슈 유형별 '실제 변경/설정 방법'. 초보 담당자가 그대로 따라할 수 있도록
# [포털 클릭 순서]와 [CLI 명령어]를 함께 제공한다. 명령의 <RG>·<이름> 등은
# 사용자가 자기 환경 값으로 바꿔 넣는 자리표시자.
_STEPS: dict[str, str] = {
    # ---- AWS ----
    "aws_sg_open_sensitive_port": (
        "[포털] AWS 콘솔 → EC2 → 좌측 '보안 그룹' → 해당 보안그룹 선택 → '인바운드 규칙' 탭 "
        "→ '인바운드 규칙 편집' → 문제 규칙의 소스를 '내 IP' 또는 회사 CIDR로 변경 → '규칙 저장'.\n"
        "[CLI] 잘못된 규칙 제거:\n"
        "  aws ec2 revoke-security-group-ingress --group-id <SG-ID> --protocol tcp --port 22 --cidr 0.0.0.0/0\n"
        "  아래처럼 허용 IP만 다시 추가:\n"
        "  aws ec2 authorize-security-group-ingress --group-id <SG-ID> --protocol tcp --port 22 --cidr <내IP>/32"
    ),
    "aws_rds_public": (
        "[포털] AWS 콘솔 → RDS → 데이터베이스 → 해당 DB 선택 → '수정' → '연결' 섹션의 "
        "'추가 구성' → '퍼블릭 액세스'를 '퍼블릭 액세스 불가'로 → '계속' → '즉시 적용' → '수정'.\n"
        "[CLI]\n"
        "  aws rds modify-db-instance --db-instance-identifier <DB이름> --no-publicly-accessible --apply-immediately"
    ),
    "aws_s3_public_block_off": (
        "[포털] AWS 콘솔 → S3 → 해당 버킷 → '권한' 탭 → '퍼블릭 액세스 차단' → '편집' "
        "→ 4개 체크박스 모두 선택 → '변경 사항 저장'(확인 문구 입력).\n"
        "[CLI]\n"
        "  aws s3api put-public-access-block --bucket <버킷이름> "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ),
    "aws_s3_public_policy": (
        "[포털] AWS 콘솔 → S3 → 버킷 → '권한' 탭 → '버킷 정책' → '편집' → Principal:\"*\" 가 있는 "
        "Statement 삭제 또는 특정 주체로 변경 → '변경 사항 저장'.\n"
        "[CLI] 현재 정책 확인 후 수정:\n"
        "  aws s3api get-bucket-policy --bucket <버킷이름>\n"
        "  (필요 시) aws s3api delete-bucket-policy --bucket <버킷이름>"
    ),
    "aws_ebs_snapshot_public": (
        "[포털] AWS 콘솔 → EC2 → '스냅샷' → 해당 스냅샷 선택 → 작업 → '권한 수정' "
        "→ '비공개' 선택(또는 특정 계정만) → 저장.\n"
        "[CLI]\n"
        "  aws ec2 reset-snapshot-attribute --snapshot-id <스냅샷ID> --attribute createVolumePermission"
    ),
    "aws_iam_no_mfa": (
        "[포털] AWS 콘솔 → IAM → 사용자 → 해당 사용자 → '보안 자격 증명' 탭 → 'MFA 디바이스 할당' "
        "→ 인증 앱(Authenticator) 등록 → 완료.\n"
        "[CLI] 가상 MFA 생성:\n"
        "  aws iam create-virtual-mfa-device --virtual-mfa-device-name <사용자>-mfa --outfile qrcode.png --bootstrap-method QRCodePNG\n"
        "  aws iam enable-mfa-device --user-name <사용자> --serial-number <MFA-ARN> --authentication-code1 <코드1> --authentication-code2 <코드2>"
    ),
    "aws_root_access_key": (
        "[포털] AWS 콘솔 우측 상단 계정명 → '보안 자격 증명'(루트로 로그인) → '액세스 키' 섹션 "
        "→ 해당 키 '삭제'. 이후 같은 화면에서 'MFA 할당'.\n"
        "[CLI] 루트 키는 콘솔에서만 삭제하는 것을 권장(루트 CLI 사용 자체를 피함)."
    ),
    "cloudtrail_missing": (
        "[포털] AWS 콘솔 → CloudTrail → '추적 생성' → 이름 입력 → '모든 리전에 적용' 체크 "
        "→ 로그 저장 S3 지정 → 'KMS 암호화'·'로그 파일 검증' 활성화 → 생성.\n"
        "[CLI]\n"
        "  aws cloudtrail create-trail --name org-trail --s3-bucket-name <로그버킷> --is-multi-region-trail\n"
        "  aws cloudtrail start-logging --name org-trail"
    ),
    # ---- Azure ----
    "nsg_open_sensitive_port": (
        "[포털] Azure Portal → '네트워크 보안 그룹' → 해당 NSG → '인바운드 보안 규칙' → 문제 규칙 클릭 "
        "→ '소스'를 'IP Addresses'로 바꾸고 회사 IP 입력(또는 규칙 삭제) → 저장.\n"
        "[CLI] 규칙 소스 제한:\n"
        "  az network nsg rule update -g <RG> --nsg-name <NSG> -n <규칙이름> --source-address-prefixes <회사IP>/32\n"
        "  또는 삭제: az network nsg rule delete -g <RG> --nsg-name <NSG> -n <규칙이름>"
    ),
    "nsg_open_all_ports": (
        "[포털] Azure Portal → NSG → '인바운드 보안 규칙' → 전체 허용(*) 규칙 클릭 → 필요한 포트/소스로 "
        "좁히거나 '삭제' → 저장.\n"
        "[CLI]\n"
        "  az network nsg rule delete -g <RG> --nsg-name <NSG> -n <규칙이름>"
    ),
    "storage_public_blob": (
        "[포털] Azure Portal → '저장소 계정' → 해당 계정 → 설정 '구성' → 'Blob 공용 액세스 허용'을 "
        "'사용 안 함' → 저장.\n"
        "[CLI]\n"
        "  az storage account update -g <RG> -n <저장소계정> --allow-blob-public-access false"
    ),
    "storage_https_disabled": (
        "[포털] Azure Portal → 저장소 계정 → '구성' → '보안 전송 필요'를 '사용' → '최소 TLS 버전' 1.2 → 저장.\n"
        "[CLI]\n"
        "  az storage account update -g <RG> -n <저장소계정> --https-only true --min-tls-version TLS1_2"
    ),
    "storage_weak_tls": (
        "[포털] Azure Portal → 저장소 계정 → '구성' → '최소 TLS 버전'을 'Version 1.2'로 → 저장.\n"
        "[CLI]\n"
        "  az storage account update -g <RG> -n <저장소계정> --min-tls-version TLS1_2"
    ),
    "webapp_https_disabled": (
        "[포털] Azure Portal → 'App Service' → 해당 앱 → 설정 '구성' → '일반 설정' → 'HTTPS 전용'을 '켜기' "
        "→ '최소 TLS 버전' 1.2 → 저장.\n"
        "[CLI]\n"
        "  az webapp update -g <RG> -n <앱이름> --https-only true\n"
        "  az webapp config set -g <RG> -n <앱이름> --min-tls-version 1.2"
    ),
    "keyvault_softdelete_off": (
        "[포털] Azure Portal → 'Key Vault' → 해당 자격 증명 모음 → '속성' → '삭제 취소'(Soft delete) 확인 "
        "→ '보호 제거'(Purge protection) '사용'으로 → 저장.\n"
        "[CLI]\n"
        "  az keyvault update -g <RG> -n <키볼트이름> --enable-soft-delete true --enable-purge-protection true"
    ),
    "keyvault_purge_off": (
        "[포털] Azure Portal → Key Vault → '속성' → '보호 제거'(Purge protection)를 '사용' → 저장.\n"
        "[CLI]\n"
        "  az keyvault update -g <RG> -n <키볼트이름> --enable-purge-protection true"
    ),
    "mfa_ca_disabled": (
        "[포털-간편] Azure Portal → 'Microsoft Entra ID' → '속성' → '보안 기본값 관리' → '사용'으로 → 저장.\n"
        "[포털-정밀] Entra ID → '보안' → '조건부 액세스' → '새 정책' → 대상 사용자/앱 지정 → "
        "'권한 부여'에서 '다단계 인증 필요' 체크 → '사용' → 만들기."
    ),
    "sql_public_access": (
        "[포털] Azure Portal → 'SQL 서버' → 해당 서버 → 보안 '네트워킹' → '공용 네트워크 액세스'를 "
        "'사용 안 함'으로 → 기존 0.0.0.0 방화벽 규칙 삭제 → 저장.\n"
        "[CLI]\n"
        "  az sql server update -g <RG> -n <서버> --set publicNetworkAccess=Disabled\n"
        "  az sql server firewall-rule delete -g <RG> -s <서버> -n AllowAllWindowsAzureIps"
    ),
    "sql_tde_disabled": (
        "[포털] Azure Portal → 'SQL 데이터베이스' → 해당 DB → 보안 '투명한 데이터 암호화' → '켜기' → 저장.\n"
        "[CLI]\n"
        "  az sql db tde set -g <RG> -s <서버> -n <DB> --status Enabled"
    ),
    "sql_auditing_disabled": (
        "[포털] Azure Portal → SQL 서버 → 보안 '감사' → '켜기' → 로그 대상(Log Analytics/Storage) 선택 → 저장.\n"
        "[CLI]\n"
        "  az sql server audit-policy update -g <RG> -n <서버> --state Enabled --bsts Enabled --storage-account <저장소계정>"
    ),
    "sql_defender_disabled": (
        "[포털] Azure Portal → SQL 서버 → 보안 'Microsoft Defender for Cloud' → 'Microsoft Defender for SQL 사용' → 저장.\n"
        "[CLI]\n"
        "  az sql server advanced-threat-protection-setting update -g <RG> -n <서버> --state Enabled"
    ),
    # ---- AWS 추가 ----
    "aws_sg_open_any": (
        "[포털] AWS 콘솔 → EC2 → '보안 그룹' → 해당 SG → '인바운드 규칙' 탭 → '인바운드 규칙 편집' "
        "→ 소스 0.0.0.0/0 규칙을 필요한 CIDR로 변경하거나 삭제 → '규칙 저장'.\n"
        "[CLI]\n"
        "  aws ec2 revoke-security-group-ingress --group-id <SG-ID> --protocol tcp --port <포트> --cidr 0.0.0.0/0"
    ),
    "aws_s3_no_encryption": (
        "[포털] AWS 콘솔 → S3 → 버킷 → '속성' 탭 → '기본 암호화' → '편집' → 'SSE-KMS' 선택 "
        "→ KMS 키 지정 → '변경 사항 저장'.\n"
        "[CLI]\n"
        "  aws s3api put-bucket-encryption --bucket <버킷이름> "
        "--server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"
    ),
    "aws_iam_wildcard_admin": (
        "[포털] AWS 콘솔 → IAM → 정책 → 해당 정책 → '편집' → Action:* / Resource:* 를 "
        "필요한 서비스·리소스로 좁힘 → '다음' → '변경 사항 저장'. (또는 사용자/역할에서 해당 정책 분리)\n"
        "[CLI] 과다 권한 정책 분리:\n"
        "  aws iam detach-user-policy --user-name <사용자> --policy-arn <정책ARN>\n"
        "  실제 필요한 권한은 IAM Access Analyzer의 '정책 생성'으로 최소 권한 정책을 만들어 부여"
    ),
    "vpc_flowlogs_missing": (
        "[AWS 포털] AWS 콘솔 → VPC → 해당 VPC 선택 → '흐름 로그' 탭 → '흐름 로그 생성' "
        "→ 필터 'All' → 대상(CloudWatch Logs 또는 S3) 지정 → '흐름 로그 생성'.\n"
        "[AWS CLI]\n"
        "  aws ec2 create-flow-logs --resource-type VPC --resource-ids <VPC-ID> "
        "--traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::<로그버킷>\n"
        "[Azure 포털] Azure Portal → 'Network Watcher' → 'NSG 흐름 로그' → '+만들기' "
        "→ 대상 NSG 선택 → 저장소 계정 지정 → 보존 기간 설정 → 만들기.\n"
        "[Azure CLI]\n"
        "  az network watcher flow-log create -g <RG> --nsg <NSG이름> -n <흐름로그이름> "
        "--storage-account <저장소계정ID> --enabled true --retention 90"
    ),
    "aws_config_recorder_off": (
        "[포털] AWS 콘솔 → AWS Config → '설정' → '기록 켜기'(Recording on) → 기록할 리소스 유형 "
        "선택 → S3·역할 지정 → 저장. (모든 리전에서 반복)\n"
        "[CLI]\n"
        "  aws configservice start-configuration-recorder --configuration-recorder-name default"
    ),
    # ---- Azure 추가 ----
    "nsg_open_any": (
        "[포털] Azure Portal → '네트워크 보안 그룹' → 해당 NSG → '인바운드 보안 규칙' → 소스가 "
        "'Any/Internet'인 규칙 클릭 → '소스'를 'IP Addresses'로 바꿔 회사 IP 입력 → 저장.\n"
        "[CLI]\n"
        "  az network nsg rule update -g <RG> --nsg-name <NSG> -n <규칙이름> --source-address-prefixes <회사IP>/32"
    ),
    "nsg_outbound_any": (
        "[포털] Azure Portal → NSG → '아웃바운드 보안 규칙' → 목적지 '*' 규칙 클릭 → 대상을 "
        "필요한 서비스 태그/IP로 변경 → 저장.\n"
        "[CLI]\n"
        "  az network nsg rule update -g <RG> --nsg-name <NSG> -n <규칙이름> --destination-address-prefixes <서비스태그 또는 IP>"
    ),
    "disk_no_cmk": (
        "[포털] Azure Portal → '디스크 암호화 집합' → '만들기'(Key Vault 키 지정) → 이후 대상 디스크 "
        "→ '암호화' → '고객 관리형 키' 선택 → 방금 만든 암호화 집합 지정 → 저장.\n"
        "[CLI]\n"
        "  az disk-encryption-set create -g <RG> -n <암호화집합> --key-url <KeyVault키URL> --source-vault <KeyVaultID>\n"
        "  az disk update -g <RG> -n <디스크> --disk-encryption-set <암호화집합>"
    ),
    "rbac_privileged_assignment": (
        "[포털] Azure Portal → 대상 구독/리소스그룹 → '액세스 제어(IAM)' → '역할 할당' 탭 → 과다 "
        "권한(Owner 등) 할당 선택 → '제거', 필요한 최소 역할(Reader/Contributor)로 재할당.\n"
        "[CLI] 과다 권한 제거:\n"
        "  az role assignment delete --assignee <주체> --role \"Owner\" --scope <범위>\n"
        "  최소 권한 재부여: az role assignment create --assignee <주체> --role \"Reader\" --scope <범위>\n"
        "  상시 권한 대신 PIM(Privileged Identity Management)으로 필요할 때만 승격 권장"
    ),
    "diagnostic_missing": (
        "[포털] Azure Portal → 대상 리소스 → 모니터링 '진단 설정' → '진단 설정 추가' → 로그/메트릭 "
        "카테고리 선택 → 대상(Log Analytics 작업 영역 또는 저장소) 지정 → 저장.\n"
        "[CLI]\n"
        "  az monitor diagnostic-settings create --name diag --resource <리소스ID> "
        "--workspace <LogAnalytics작업영역ID> --logs '[{\"category\":\"AuditEvent\",\"enabled\":true}]'"
    ),
    "backup_failed": (
        "[포털] Azure Portal → 'Recovery Services 자격 증명 모음' → '백업 항목' → 실패 항목 클릭 "
        "→ '지금 백업'으로 재시도, 실패 원인(오류 메시지) 확인 후 조치.\n"
        "[CLI] 백업 즉시 실행:\n"
        "  az backup protection backup-now -g <RG> -v <자격증명모음> -c <컨테이너> -i <항목> --retain-until <날짜>"
    ),
    "backup_lrs": (
        "[포털] Azure Portal → Recovery Services 자격 증명 모음 → 설정 '속성' → '백업 구성' "
        "→ 저장소 복제 종류를 'geo-redundant(GRS)'로 변경 → 저장. (백업 항목 등록 전에만 변경 가능)\n"
        "[CLI]\n"
        "  az backup vault backup-properties set -g <RG> -n <자격증명모음> --backup-storage-redundancy GeoRedundant"
    ),
    "defender_active_alert": (
        "[포털] Azure Portal → 'Microsoft Defender for Cloud' → '보안 경고' → 각 Active 경고 클릭 "
        "→ 권장 조치 수행 → 처리 후 '상태 변경'에서 '해결됨'으로.\n"
        "[CLI] 경고 목록 확인(조치는 포털 권장):\n"
        "  az security alert list --query \"[?properties.status=='Active']\""
    ),
    "assessment_unhealthy": (
        "[포털] Azure Portal → Defender for Cloud → '권장 사항' → Unhealthy 항목 클릭 → '수정' "
        "(Fix) 버튼이 있으면 클릭, 없으면 안내된 단계 수행 → Healthy 전환 확인.\n"
        "[CLI] 항목 확인:\n"
        "  az security assessment list --query \"[?status.code=='Unhealthy']\""
    ),
    "patch_pending": (
        "[포털] Azure Portal → 'Azure Update Manager' → '컴퓨터' → 대상 VM 선택 → '한 번 업데이트 "
        "설치'로 즉시 적용, 또는 '정기 업데이트'로 유지 관리 일정 등록.\n"
        "[CLI] 평가/설치:\n"
        "  az vm assess-patches -g <RG> -n <VM이름>\n"
        "  az vm install-patches -g <RG> -n <VM이름> --maximum-duration PT2H --reboot-setting IfRequired "
        "--classifications-to-include-linux Critical Security"
    ),
    "cve_detected": (
        "[공통] 1) 발견된 CVE 번호를 NVD(nvd.nist.gov)나 벤더 공지에서 검색해 영향 제품·버전 확인.\n"
        "2) 해당 소프트웨어/OS를 패치 버전으로 업데이트(OS 패키지 관리자, 벤더 업데이트).\n"
        "[Azure] Azure Update Manager로 VM 패치 적용:  az vm install-patches -g <RG> -n <VM> ...\n"
        "[AWS] SSM Patch Manager로 적용:  aws ssm send-command --document-name AWS-RunPatchBaseline ...\n"
        "3) 즉시 패치 불가 시 WAF 규칙 추가·네트워크 접근 차단 등 임시 완화."
    ),
    "pii_exposed": (
        "[공통] 1) 개인정보가 발견된 위치(로그 파일·설정·환경변수)를 특정합니다.\n"
        "2) 로그의 경우: 애플리케이션 로깅에서 개인정보 필드를 마스킹하거나 기록하지 않도록 코드를 수정합니다.\n"
        "3) 이미 저장된 로그는 삭제 또는 마스킹 처리합니다.\n"
        "[Azure] 저장 데이터는 SQL TDE + 컬럼 암호화(Always Encrypted), 로그는 Log Analytics 접근권한 최소화.\n"
        "[AWS] RDS 암호화 + 필드 암호화, CloudWatch Logs 접근 IAM 최소화.\n"
        "4) 개인정보 영향평가(PIA)·수집 최소화 원칙을 점검합니다."
    ),
    "secret_exposed": (
        "[즉시] 1) 노출된 키/비밀번호를 즉시 무효화하고 새로 발급합니다(유출 가정).\n"
        "[Azure] az keyvault secret set 으로 Key Vault에 저장 → 앱은 Managed Identity로 참조.\n"
        "  az keyvault secret set --vault-name <키볼트> --name <이름> --value <새값>\n"
        "[AWS] Secrets Manager에 저장 → 앱은 IAM 역할로 참조.\n"
        "  aws secretsmanager create-secret --name <이름> --secret-string <새값>\n"
        "2) 코드/설정에서 하드코딩 값을 제거하고 시크릿 저장소 참조로 교체합니다.\n"
        "3) git 이력에 남았으면 이력에서도 제거(git filter-repo 등)하고, 커밋 전 시크릿 스캔을 도입합니다."
    ),
    "eks_public_api": (
        "[포털] AWS 콘솔 → EKS → 해당 클러스터 → '네트워킹' → '관리' → API 서버 엔드포인트 액세스 "
        "→ '프라이빗'으로 변경하거나 '퍼블릭' 유지 시 CIDR를 회사 IP로 제한 → 저장.\n"
        "[CLI]\n"
        "  aws eks update-cluster-config --name <클러스터> "
        "--resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true\n"
        "  (퍼블릭 유지 시) ...endpointPublicAccess=true,publicAccessCidrs=<회사IP>/32"
    ),
    "aks_public_api": (
        "[포털] Azure Portal → 'Kubernetes 서비스' → 해당 클러스터 → '네트워킹' → "
        "'권한이 부여된 IP 범위 설정'에 회사 IP를 등록 → 저장. (프라이빗 클러스터는 생성 시 지정)\n"
        "[CLI]\n"
        "  az aks update -g <RG> -n <AKS> --api-server-authorized-ip-ranges <회사IP>/32"
    ),
    "aks_rbac_disabled": (
        "[안내] Kubernetes RBAC은 AKS 생성 시에만 켤 수 있어, 기존 클러스터는 RBAC 활성 상태로 재생성해야 합니다.\n"
        "[CLI] 신규 생성 예:\n"
        "  az aks create -g <RG> -n <AKS> --enable-aad --enable-azure-rbac\n"
        "기존 워크로드는 새 클러스터로 마이그레이션합니다."
    ),
    "apigw_no_auth": (
        "[포털] AWS 콘솔 → API Gateway → 해당 API → 리소스 → 메서드 선택 → '메서드 요청' "
        "→ '권한 부여'를 IAM/Cognito/Authorizer로 설정 → API 배포.\n"
        "[CLI] Lambda Authorizer/IAM 적용은 콘솔 권장. 최소한 API Key 요구:\n"
        "  aws apigateway update-method --rest-api-id <API> --resource-id <RES> "
        "--http-method GET --patch-operations op=replace,path=/apiKeyRequired,value=true"
    ),
}


# 이슈 유형 → MITRE ATT&CK Technique 매핑 (ID, 이름).
# 위협 관점에서 "이 취약점이 어떤 공격 기법에 악용되는가"를 보여준다.
_MITRE: dict[str, tuple[str, str]] = {
    # 인터넷 노출 → 외부 접근/원격 서비스 악용
    "aws_sg_open_sensitive_port": ("T1190", "Exploit Public-Facing Application"),
    "aws_sg_open_any": ("T1190", "Exploit Public-Facing Application"),
    "nsg_open_sensitive_port": ("T1190", "Exploit Public-Facing Application"),
    "nsg_open_all_ports": ("T1190", "Exploit Public-Facing Application"),
    "nsg_open_any": ("T1190", "Exploit Public-Facing Application"),
    "aws_rds_public": ("T1190", "Exploit Public-Facing Application"),
    "sql_public_access": ("T1190", "Exploit Public-Facing Application"),
    "webapp_https_disabled": ("T1040", "Network Sniffing"),
    "storage_https_disabled": ("T1040", "Network Sniffing"),
    "storage_weak_tls": ("T1040", "Network Sniffing"),
    "eks_public_api": ("T1190", "Exploit Public-Facing Application"),
    "aks_public_api": ("T1190", "Exploit Public-Facing Application"),
    "apigw_no_auth": ("T1190", "Exploit Public-Facing Application"),
    # 데이터 노출 → 클라우드 스토리지/데이터 수집
    "aws_s3_public_block_off": ("T1530", "Data from Cloud Storage"),
    "aws_s3_public_policy": ("T1530", "Data from Cloud Storage"),
    "storage_public_blob": ("T1530", "Data from Cloud Storage"),
    "aws_ebs_snapshot_public": ("T1530", "Data from Cloud Storage"),
    "aws_s3_no_encryption": ("T1530", "Data from Cloud Storage"),
    "sql_tde_disabled": ("T1530", "Data from Cloud Storage"),
    "disk_no_cmk": ("T1530", "Data from Cloud Storage"),
    "pii_exposed": ("T1552", "Unsecured Credentials / Sensitive Data"),
    "secret_exposed": ("T1552", "Unsecured Credentials"),
    # 계정/권한 → 유효 계정·권한 상승
    "aws_iam_no_mfa": ("T1078", "Valid Accounts"),
    "mfa_ca_disabled": ("T1078", "Valid Accounts"),
    "aws_root_access_key": ("T1078.004", "Valid Accounts: Cloud Accounts"),
    "aws_iam_wildcard_admin": ("T1098", "Account Manipulation / Privilege Escalation"),
    "rbac_privileged_assignment": ("T1098", "Account Manipulation / Privilege Escalation"),
    "aks_rbac_disabled": ("T1098", "Account Manipulation"),
    # 키/암호화
    "sql_cmk_not_used": ("T1552", "Unsecured Credentials"),
    "keyvault_softdelete_off": ("T1485", "Data Destruction"),
    "keyvault_purge_off": ("T1485", "Data Destruction"),
    # 로깅/방어 무력화 → 방어 회피
    "cloudtrail_missing": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "diagnostic_missing": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "vpc_flowlogs_missing": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "aws_config_recorder_off": ("T1562", "Impair Defenses"),
    "sql_auditing_disabled": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
    "nsg_outbound_any": ("T1048", "Exfiltration Over Alternative Protocol"),
    # 탐지/대응 미비
    "sql_defender_disabled": ("T1562", "Impair Defenses"),
    "defender_active_alert": ("T1078", "Valid Accounts"),
    # 취약점/패치
    "cve_detected": ("T1210", "Exploitation of Remote Services"),
    "assessment_unhealthy": ("T1210", "Exploitation of Remote Services"),
    "patch_pending": ("T1210", "Exploitation of Remote Services"),
    "sql_va_disabled": ("T1210", "Exploitation of Remote Services"),
    # 백업/재해
    "backup_failed": ("T1490", "Inhibit System Recovery"),
    "backup_lrs": ("T1490", "Inhibit System Recovery"),
    "sql_ltr_not_configured": ("T1490", "Inhibit System Recovery"),
    "sql_no_private_endpoint": ("T1190", "Exploit Public-Facing Application"),
}


def _location_from_dict(d: dict) -> str:
    """리소스 dict에서 '어디에 있는지'(위치) 정보를 사람이 읽기 쉬운 문자열로 추출.

    Azure: 구독/리소스그룹/리전, AWS: 계정/리전/VPC. 조치 대상을 특정하기 위함.
    """
    if not isinstance(d, dict):
        return ""
    parts: list[str] = []

    # Azure resource ID(/subscriptions/.../resourceGroups/.../providers/...)에서 추출
    rid = str(_val(d, "id", default="") or "")
    m_sub = re.search(r"/subscriptions/([^/]+)", rid, re.I)
    m_rg = re.search(r"/resourceGroups/([^/]+)", rid, re.I)
    sub = _val(d, "subscriptionId", "subscription") or (m_sub.group(1) if m_sub else "")
    rg = _val(d, "resourceGroup", "resourcegroup") or (m_rg.group(1) if m_rg else "")
    loc = _val(d, "location", "region")
    if sub:
        parts.append(f"구독 {sub}")
    if rg:
        parts.append(f"리소스그룹 {rg}")
    if loc:
        parts.append(f"리전 {loc}")

    # AWS: 계정/리전/VPC
    acct = _val(d, "OwnerId", "ownerId", "AwsAccountId", "awsAccountId")
    vpc = _val(d, "VpcId", "vpcId")
    region = _val(d, "Region", "region", "AvailabilityZone", "availabilityZone")
    arn = str(_val(d, "Arn", "arn", default="") or "")
    m_arn = re.match(r"arn:aws:[^:]*:([^:]*):(\d+):", arn)
    if not region and m_arn and m_arn.group(1):
        region = m_arn.group(1)
    if not acct and m_arn and m_arn.group(2):
        acct = m_arn.group(2)
    if acct:
        parts.append(f"계정 {acct}")
    if region:
        parts.append(f"리전 {region}")
    if vpc:
        parts.append(f"VPC {vpc}")

    return " > ".join(parts)


def _finding(code: str, issue_type: str, severity: Severity, title: str,
             description: str, *, platform: str = "azure", evidence: str = "",
             resource: str = "", recommendation: str = "",
             bad_example: str = "", good_example: str = "",
             why: str = "", how_to_fix: str = "", steps: str = "",
             location: str = "") -> Finding:
    kb = control_for(code, platform)
    # 이슈 유형별 맞춤 예시가 있으면 우선 사용, 없으면 통제항목 기본값.
    ex = _EXAMPLES.get(issue_type, {})
    expl = _EXPLAIN.get(issue_type, {})
    mitre = _MITRE.get(issue_type, ("", ""))
    # location이 없으면 evidence가 JSON일 때 자동 추출(대부분의 객체 기반 탐지가 해당)
    loc = location
    if not loc and evidence and evidence.lstrip()[:1] in ("{", "["):
        try:
            parsed = json.loads(evidence)
            if isinstance(parsed, list) and parsed:
                parsed = parsed[0]
            loc = _location_from_dict(parsed) if isinstance(parsed, dict) else ""
        except (ValueError, TypeError):
            loc = ""
    return Finding(
        control_code=code,
        control_domain=kb.get("domain", ""),
        issue_type=issue_type,
        severity=severity,
        title=title,
        description=description or kb.get("criteria", ""),
        recommendation=recommendation or kb.get("fix", ""),
        evidence=(evidence or "")[:600],
        resource=resource or "",
        location=loc,
        platform=platform,
        bad_example=bad_example or ex.get("bad", "") or kb.get("bad_example", ""),
        good_example=good_example or ex.get("good", "") or kb.get("good_example", ""),
        why=why or expl.get("why", ""),
        how_to_fix=how_to_fix or expl.get("how_to_fix", ""),
        steps=steps or _STEPS.get(issue_type, ""),
        mitre_id=mitre[0],
        mitre_name=mitre[1],
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
    # flat(JSON 문자열)에서 위치 정보 추출
    loc = ""
    try:
        parsed = json.loads(flat) if flat and flat.lstrip()[:1] in ("{", "[") else None
        if isinstance(parsed, list) and parsed:
            parsed = parsed[0]
        loc = _location_from_dict(parsed) if isinstance(parsed, dict) else ""
    except (ValueError, TypeError):
        loc = ""
    findings.append(Finding(
        control_code=meta.get("control_code", "2.7.1"),
        control_domain=control_for(meta.get("control_code", "2.7.1"), "azure").get("domain", ""),
        issue_type=key,
        severity=severity,
        title=f"{meta.get('title', key)}: {name or '(이름없음)'}",
        description=desc,
        recommendation=meta.get("fix", ""),
        evidence=(flat or "")[:600],
        resource=name,
        location=loc,
        platform="azure",
        bad_example=meta.get("bad_example", ""),
        good_example=meta.get("good_example", ""),
        why=meta.get("why", ""),
        how_to_fix=meta.get("how_to_fix", ""),
        steps=meta.get("steps", "") or _STEPS.get(key, ""),
        mitre_id=_MITRE.get(key, ("", ""))[0],
        mitre_name=_MITRE.get(key, ("", ""))[1],
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
    # 그룹 레벨 위치(VpcId/OwnerId/GroupName)를 규칙별 finding에 함께 표기
    grp_loc = _location_from_dict(d)
    gname = str(_val(d, "GroupName", "groupName", default="") or "")
    if gname and gname not in grp_loc:
        grp_loc = (grp_loc + " > " if grp_loc else "") + f"SG {gname}"
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
                platform="aws", evidence=flat, resource=gid, location=grp_loc,
            ))
        else:
            findings.append(_finding(
                "2.6.1", "aws_sg_open_any", Severity.MEDIUM,
                f"보안그룹 인바운드 출발지 전체공개: {gid or '(SG미상)'}",
                "0.0.0.0/0(Any)에서 인바운드가 허용된 보안그룹 규칙이 있습니다.",
                platform="aws", evidence=flat, resource=gid, location=grp_loc,
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


def _check_aws_eks_obj(d: dict, findings: list[Finding], seen: set) -> None:
    """AWS EKS 클러스터(2.6.1). API 서버 엔드포인트 퍼블릭 접근."""
    vpc = _val(d, "resourcesVpcConfig", "resourcesvpcconfig")
    src = vpc if isinstance(vpc, dict) else d
    pub = _val(src, "endpointPublicAccess", "publicAccess")
    if pub is True or str(pub).lower() == "true":
        cidrs = _val(src, "publicAccessCidrs", "publicCidrs") or []
        wide_open = (not cidrs) or ("0.0.0.0/0" in [str(c) for c in cidrs])
        name = str(_val(d, "name", "clusterName", default="") or "")
        # 중복 방지: 같은 클러스터(외부 객체 + 중첩 vpc 설정)가 두 번 잡히지 않도록
        key = ("eks", name, str(sorted([str(c) for c in cidrs])))
        if wide_open and key not in seen:
            seen.add(key)
            findings.append(_finding(
                "2.6.1", "eks_public_api", Severity.HIGH,
                f"EKS API 서버 퍼블릭 노출: {name or '(클러스터미상)'}",
                "EKS 클러스터의 Kubernetes API 서버가 인터넷 전체(0.0.0.0/0)에 공개되어 있습니다.",
                platform="aws", evidence=json.dumps(d, ensure_ascii=False), resource=name,
            ))


def _check_aws_object(d: dict, findings: list[Finding], seen: set) -> None:
    """AWS 리소스 dict 라우팅."""
    # EKS 클러스터 객체(resourcesVpcConfig를 가진 상위 객체)만 검사 —
    # 중첩된 vpc 설정 dict 단독으로는 중복 검사하지 않도록 제한.
    if _val(d, "resourcesVpcConfig", "resourcesvpcconfig") is not None:
        _check_aws_eks_obj(d, findings, seen)
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


def _check_azure_aks_obj(d: dict, findings: list[Finding]) -> None:
    """Azure AKS(2.6.1). API 서버 퍼블릭(프라이빗 클러스터 아님) + RBAC 미사용."""
    prof = _val(d, "apiServerAccessProfile")
    prof = prof if isinstance(prof, dict) else d
    private = _val(prof, "enablePrivateCluster", "privateCluster")
    auth_ranges = _val(prof, "authorizedIpRanges", "authorizedIPRanges")
    name = str(_val(d, "name", default="") or "")
    # 프라이빗 클러스터가 아니고 승인 IP 범위도 없으면 API가 전체 공개
    is_private = private is True or str(private).lower() == "true"
    if not is_private and not auth_ranges:
        findings.append(_finding(
            "2.6.1", "aks_public_api", Severity.HIGH,
            f"AKS API 서버 퍼블릭 노출: {name or '(클러스터미상)'}",
            "AKS 클러스터가 프라이빗 클러스터가 아니고 승인 IP 범위도 없어, Kubernetes API 서버가 인터넷에 공개됩니다.",
            platform="azure", evidence=json.dumps(d, ensure_ascii=False), resource=name,
        ))
    # RBAC 비활성
    rbac = _val(d, "enableRbac", "enableRBAC")
    if rbac is False or str(rbac).lower() == "false":
        findings.append(_finding(
            "2.5.5", "aks_rbac_disabled", Severity.MEDIUM,
            f"AKS Kubernetes RBAC 비활성: {name or '(클러스터미상)'}",
            "AKS 클러스터의 Kubernetes RBAC이 비활성이라 세분화된 권한 통제가 되지 않습니다.",
            platform="azure", evidence=json.dumps(d, ensure_ascii=False), resource=name,
        ))


def _check_azure_object(d: dict, findings: list[Finding], seen: set) -> None:
    if _val(d, "sourceAddressPrefix", "sourceAddressPrefixes") is not None or (
        _val(d, "direction") is not None and _val(d, "access") is not None
    ):
        _check_nsg_rule_obj(d, findings)

    if _val(d, "apiServerAccessProfile") is not None or _val(d, "enableRbac", "enableRBAC") is not None \
            or _looks_like(d, "managedclusters", "microsoft.containerservice"):
        _check_azure_aks_obj(d, findings)

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
def _snippet(text: str, *patterns: str, width: int = 220) -> str:
    """입력 원문에서 패턴이 매칭된 위치 주변 텍스트를 잘라 근거로 반환.

    여러 패턴 중 매칭되는 첫 부분을 찾아 앞뒤 문맥과 함께 돌려준다.
    매칭이 없으면 빈 문자열. 사용자에게 '어떤 텍스트로 판단했는지' 보여주기 위함.
    """
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if not m:
            continue
        # 매칭 텍스트가 근거의 앞쪽에 오도록 앞 문맥은 조금만, 뒤 문맥은 넉넉히.
        start = max(0, m.start() - 20)
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
    # Flow Logs 미구성 (AWS VPC Flow Logs / Azure NSG Flow Logs — 입력에서 플랫폼 자동 구분)
    if re.search(r"flow[- ]?logs?", low) and re.search(r"\[\s*\]|\"?flowlogstatus\"?\s*[:=]\s*\"?inactive|no flow log|not configured|enabled.{0,6}false", low):
        # Azure 키워드가 함께 있으면 Azure NSG Flow Logs
        is_azure_flow = bool(re.search(r"nsg|networkwatcher|microsoft\.network|az\s+network|network-watcher", low))
        is_aws_flow = bool(re.search(r"\bvpc\b|\bec2\b|\baws\b", low))
        if is_azure_flow and not is_aws_flow:
            flow_plat = "azure"
            flow_title = "NSG Flow Logs 미구성/비활성"
            flow_desc = "NSG Flow Logs가 구성되지 않았거나 비활성 상태로, 네트워크 트래픽 감사 사각지대가 있습니다."
        elif is_aws_flow and not is_azure_flow:
            flow_plat = "aws"
            flow_title = "VPC Flow Logs 미구성/비활성"
            flow_desc = "VPC Flow Logs가 구성되지 않았거나 비활성(INACTIVE) 상태로, 네트워크 트래픽 감사 사각지대가 있습니다."
        else:
            # 명확하지 않으면 전체 플랫폼 힌트 사용
            flow_plat = plat
            flow_title = ("NSG" if plat == "azure" else "VPC") + " Flow Logs 미구성/비활성"
            flow_desc = "Flow Logs가 구성되지 않았거나 비활성 상태로, 네트워크 트래픽 감사 사각지대가 있습니다."
        add("2.9.4", "vpc_flowlogs_missing", Severity.MEDIUM,
            flow_title, flow_desc, platform=flow_plat,
            evidence=_snippet(text, r"flowlogstatus[^,}\n]*inactive", r"no flow log", r"enabled[^,}\n]*false", r"flow[- ]?logs?"))
    # AWS Config 레코더 비활성 (AWS)
    if re.search(r"configurationrecorder|config.{0,10}recorder", low) and \
            re.search(r'"?recording"?\s*[:=]\s*(false|0)|\[\s*\]|not recording', low):
        add("2.10.2", "aws_config_recorder_off", Severity.MEDIUM,
            "AWS Config 레코더 비활성",
            "AWS Config 구성 레코더가 비활성 상태로, 리소스 구성 변경 이력이 기록되지 않습니다.",
            platform="aws",
            evidence=_snippet(text, r"recording[^,}\n]*(false|0)", r"configurationrecorder", r"config.{0,10}recorder"))
    # API Gateway 인증 없음 (AWS)
    if re.search(r"authorizationtype", low) and re.search(r'"?authorizationtype"?\s*[:=]\s*"?none', low):
        add("2.6.1", "apigw_no_auth", Severity.HIGH,
            "API Gateway 인증 없는 메서드",
            "API Gateway 메서드의 authorizationType이 NONE으로, 인증 없이 누구나 호출할 수 있습니다.",
            platform="aws",
            evidence=_snippet(text, r"authorizationtype[^,}\n]*none"))
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

    # ── 개인정보(PII) 노출 탐지 (ISMS-P 개인정보 보호) ──
    if "pii_exposed" not in existing_types:
        pii_hits: dict[str, list[str]] = {}
        for label, pat, _sev in _PII_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(0)
                # 신용카드는 Luhn 통과분만 인정(오탐 감소)
                if label == "신용카드번호" and not _luhn_ok(val):
                    continue
                pii_hits.setdefault(label, [])
                if len(pii_hits[label]) < 5 and val not in pii_hits[label]:
                    pii_hits[label].append(val)
        if pii_hits:
            # 심각도: 주민번호/카드번호 있으면 CRITICAL, 이메일/전화만이면 MEDIUM
            has_critical = any(k in pii_hits for k in ("주민등록번호", "신용카드번호"))
            sev = Severity.CRITICAL if has_critical else Severity.MEDIUM
            summary = ", ".join(f"{k} {len(v)}건" for k, v in pii_hits.items())
            masked = "; ".join(
                f"{k}: " + ", ".join(_mask(x) for x in v[:3]) for k, v in pii_hits.items()
            )
            existing_types.add("pii_exposed")
            findings.append(_finding(
                "2.7.1", "pii_exposed", sev,
                f"개인정보 평문 노출 의심 ({summary})",
                f"입력(정책·설정·로그)에서 개인정보로 보이는 값이 발견되었습니다: {summary}. "
                "개인정보가 로그·구성 파일·환경변수 등에 평문으로 남아 있으면 유출 위험이 큽니다.",
                platform=plat, evidence=masked, resource=summary,
            ))

    # ── 시크릿/자격증명 하드코딩 탐지 ──
    if "secret_exposed" not in existing_types:
        secret_hits: dict[str, list[str]] = {}
        worst = Severity.MEDIUM
        for label, pat, sev_name in _SECRET_PATTERNS:
            for m in pat.finditer(text):
                secret_hits.setdefault(label, [])
                if len(secret_hits[label]) < 3:
                    secret_hits[label].append(m.group(0))
                s = Severity.from_name(sev_name)
                if s > worst:
                    worst = s
        if secret_hits:
            summary = ", ".join(f"{k} {len(v)}건" for k, v in secret_hits.items())
            masked = "; ".join(
                f"{k}: " + ", ".join(_mask(x) for x in v[:2]) for k, v in secret_hits.items()
            )
            existing_types.add("secret_exposed")
            findings.append(_finding(
                "2.7.2", "secret_exposed", worst,
                f"시크릿·자격증명 하드코딩 의심 ({summary})",
                f"입력에서 하드코딩된 자격증명으로 보이는 값이 발견되었습니다: {summary}. "
                "키·비밀번호·토큰이 코드·설정·로그에 노출되면 계정 탈취로 직결됩니다.",
                platform=plat, evidence=masked, resource=summary,
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


# 심각도별 위험 기본 점수(0~100 스케일의 출발점)
_SEV_BASE = {
    Severity.CRITICAL: 60,
    Severity.HIGH: 45,
    Severity.MEDIUM: 25,
    Severity.LOW: 10,
    Severity.INFO: 0,
}

# 이슈 유형별 '인터넷 직접 노출' 성격(외부에서 바로 도달 가능 → 위험 가중 최대)
_INTERNET_EXPOSED_TYPES = {
    "aws_sg_open_sensitive_port", "aws_sg_open_any", "aws_rds_public",
    "aws_s3_public_block_off", "aws_s3_public_policy", "aws_ebs_snapshot_public",
    "nsg_open_sensitive_port", "nsg_open_all_ports", "nsg_open_any",
    "storage_public_blob", "webapp_https_disabled", "sql_public_access",
    "eks_public_api", "aks_public_api", "apigw_no_auth",
}
# 민감 데이터/자격증명 직접 노출 성격
_DATA_EXPOSURE_TYPES = {
    "pii_exposed", "secret_exposed", "aws_root_access_key",
    "aws_s3_no_encryption", "sql_tde_disabled",
}
# 인증·계정 통제 약화 성격
_AUTH_WEAK_TYPES = {
    "aws_iam_no_mfa", "aws_iam_wildcard_admin", "mfa_ca_disabled",
    "rbac_privileged_assignment", "aws_root_access_key",
}


def _compute_risk(f: Finding) -> None:
    """조치 우선순위용 위험 점수(0~100)와 가중 근거를 산정해 Finding에 기록.

    심각도 기본점수 + 상황 가중치(인터넷 노출/민감데이터/인증약화/관리포트 등).
    """
    score = _SEV_BASE.get(f.severity, 0)
    factors: list[str] = []
    low = (f.evidence + " " + f.description + " " + f.title).lower()

    if f.issue_type in _INTERNET_EXPOSED_TYPES or "0.0.0.0/0" in low or "internet" in low or "public" in low:
        score += 20
        factors.append("인터넷 직접 노출")
    if f.issue_type in _DATA_EXPOSURE_TYPES:
        score += 18
        factors.append("민감데이터/자격증명 노출")
    if f.issue_type in _AUTH_WEAK_TYPES:
        score += 12
        factors.append("인증·계정 통제 약화")
    # 관리 포트(SSH/RDP) 개방은 즉시 악용 위험
    if any(f"({_SENSITIVE_PORTS[p]})" in low or f"'{p}'" in low or f'"{p}"' in low
           for p in _MGMT_PORTS):
        if "port" in low or "포트" in low or f.issue_type.endswith("sensitive_port"):
            score += 8
            factors.append("관리포트(SSH/RDP) 개방")
    # 암호화 미적용
    if "암호화" in f.title or "encrypt" in low or f.issue_type in ("sql_tde_disabled", "aws_s3_no_encryption"):
        if f.issue_type not in _DATA_EXPOSURE_TYPES:
            score += 6
            factors.append("암호화 미적용")

    f.risk_score = max(0, min(100, score))
    f.risk_factors = factors


# 상관 분석 규칙: (필요 이슈유형 집합, 제목, 설명/공격경로, 권고)
# 개별로는 중간이어도 '조합'되면 실제 침해 경로가 되는 위험을 별도로 경고한다.
_CORRELATION_RULES = [
    {
        "need": {"aws_sg_open_sensitive_port", "aws_iam_no_mfa"},
        "any": False,
        "title": "공격 경로: 관리포트 개방 + MFA 없는 계정",
        "path": "인터넷에 열린 SSH/RDP로 접속 시도 → MFA 없는 IAM 계정 비밀번호 탈취 → 내부 침투. "
                "두 취약점이 결합하면 외부에서 서버까지 한 번에 뚫릴 수 있습니다.",
        "fix": "① 관리포트 출발지를 제한(Bastion/SSM)하고 ② 모든 콘솔 계정에 MFA를 강제하세요.",
    },
    {
        "need": {"nsg_open_sensitive_port", "mfa_ca_disabled"},
        "any": False,
        "title": "공격 경로: NSG 관리포트 개방 + MFA 미강제",
        "path": "인터넷에 열린 RDP/SSH → MFA 없는 계정으로 로그인 → VM 장악. "
                "네트워크 노출과 약한 인증이 겹쳐 침해 가능성이 큽니다.",
        "fix": "① NSG 출발지를 제한(Azure Bastion/JIT)하고 ② Conditional Access로 MFA를 강제하세요.",
    },
    {
        "need": {"aws_s3_public_block_off", "aws_s3_no_encryption"},
        "any": False,
        "title": "공격 경로: S3 퍼블릭 노출 + 암호화 없음",
        "path": "퍼블릭 접근이 열린 버킷의 데이터가 암호화도 안 돼 있어, 유출 시 내용이 그대로 노출됩니다(데이터 유출 직결).",
        "fix": "① Block Public Access 4종을 켜고 ② 기본 암호화(SSE-KMS)를 적용하세요.",
    },
    {
        "need": {"storage_public_blob", "pii_exposed"},
        "any": False,
        "title": "공격 경로: 퍼블릭 저장소 + 개인정보 노출",
        "path": "익명 접근이 열린 저장소에 개인정보가 있어, 외부에서 개인정보를 그대로 조회할 수 있습니다(개인정보 유출·법 위반).",
        "fix": "① 퍼블릭 Blob 접근을 끄고 ② 개인정보를 마스킹/암호화하며 저장 최소화하세요.",
    },
    {
        "need": {"aws_rds_public"},
        "with_any": {"pii_exposed", "aws_s3_no_encryption", "sql_tde_disabled"},
        "title": "공격 경로: 퍼블릭 DB + 데이터 보호 미흡",
        "path": "인터넷에서 접근 가능한 데이터베이스에 민감데이터·미암호화가 겹쳐, 유출 표적이 됩니다.",
        "fix": "① DB 퍼블릭 접근을 차단하고 ② 저장 암호화·개인정보 보호 조치를 적용하세요.",
    },
    {
        "need": {"secret_exposed"},
        "with_any": {"aws_iam_wildcard_admin", "rbac_privileged_assignment", "aws_root_access_key"},
        "title": "공격 경로: 자격증명 노출 + 과다 권한",
        "path": "노출된 시크릿이 과다 권한 계정의 것이면, 탈취 시 계정·구독 전체가 장악됩니다(권한 상승·전면 침해).",
        "fix": "① 노출 시크릿을 즉시 폐기·교체하고 ② 최소권한 원칙으로 권한을 축소하세요.",
    },
]


def _correlate(findings: list[Finding]) -> list[dict]:
    """개별 이슈들의 조합으로 성립하는 복합 위험(공격 경로)을 산출."""
    types = {f.issue_type for f in findings}
    out: list[dict] = []
    for rule in _CORRELATION_RULES:
        need = rule.get("need", set())
        if not need.issubset(types):
            continue
        with_any = rule.get("with_any")
        if with_any and not (with_any & types):
            continue
        out.append({
            "title": rule["title"],
            "attack_path": rule["path"],
            "recommendation": rule["fix"],
            "related_types": sorted(need | (with_any & types if with_any else set())),
        })
    return out


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

    # 3) 위험 점수 산정(조치 우선순위)
    for f in findings:
        _compute_risk(f)

    # 4) 상관 분석(복합 위험 경로)
    report.correlations = _correlate(findings)

    report.findings = findings
    if not findings:
        report.notes.append(
            "탐지된 이슈가 없습니다. 입력이 비었거나, 이 엔진의 점검 대상"
            "(AWS: SG/S3/IAM, Azure: NSG/Storage/SQL/Key Vault/RBAC, 공통: 진단·백업 등) "
            "형식이 아닐 수 있습니다. CLI를 '-o json'으로 내보낸 출력을 넣으면 정밀도가 높아집니다."
        )
    return report


def group_by_location(report_dict: dict) -> list[dict]:
    """이슈를 위치(구독/리소스그룹/VPC 등)별로 묶어 반환.

    반환: [{location, count, findings:[...]}, ...] — 위치명 정렬.
    조치 담당자가 '어느 위치를 먼저 손봐야 하는지' 한눈에 보기 위함.
    """
    buckets: dict[str, list] = {}
    for f in report_dict.get("findings", []):
        loc = f.get("location") or "(위치 미상)"
        buckets.setdefault(loc, []).append(f)
    out = []
    for loc in sorted(buckets):
        fs = buckets[loc]
        # 그룹 대표 위험도 = 그룹 내 최고 위험 점수
        top = max((x.get("risk_score", 0) for x in fs), default=0)
        out.append({"location": loc, "count": len(fs), "max_risk": top, "findings": fs})
    # 위험 높은 위치가 위로
    out.sort(key=lambda g: g["max_risk"], reverse=True)
    return out


def _finding_key(f: dict) -> str:
    """추세 비교용 이슈 고유키(플랫폼|통제코드|이슈유형|리소스)."""
    return "|".join([
        str(f.get("platform", "")), str(f.get("control_code", "")),
        str(f.get("issue_type", "")), str(f.get("resource", "")),
    ])


def diff_reports(current: dict, previous: dict) -> dict:
    """두 점검 결과(to_dict)를 비교해 신규/해결/유지 이슈와 점수 변화를 산출.

    화면·CLI에서 추세(이전 대비 개선/악화)를 보여주기 위한 순수 함수.
    반환: {added, resolved, kept, score_delta, ...}
    """
    cur = {_finding_key(f): f for f in current.get("findings", [])}
    prev = {_finding_key(f): f for f in previous.get("findings", [])}
    added = [cur[k] for k in cur if k not in prev]
    resolved = [prev[k] for k in prev if k not in cur]
    kept = [cur[k] for k in cur if k in prev]
    cs, ps = current.get("score", 0), previous.get("score", 0)
    return {
        "added": added,
        "resolved": resolved,
        "kept_count": len(kept),
        "added_count": len(added),
        "resolved_count": len(resolved),
        "score_current": cs,
        "score_previous": ps,
        "score_delta": cs - ps,
    }
