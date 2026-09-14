"""ISMS-P(2022) 클라우드 인프라 점검 매트릭스 — Azure 통제항목 지식 베이스.

영역 2 '보호대책 요구사항'의 클라우드 인프라 직결 7개 영역·17개 통제항목.
각 항목: code(통제번호), domain(영역명), desc(점검목적),
azure_cmd(참고 CLI), criteria(문제 판단기준), fix(개선방안), resources(관련 리소스 태그).

출처: 사내 참고자료 'isms-cloud-audit-matrix'(ISMS-P 인증기준 재구성). KISA 공식 심사자료를 대체하지 않음.
이 모듈은 인터넷 없이 동작하도록 데이터를 코드에 임베드한다(폐쇄망 전제).
"""

from __future__ import annotations

# code -> 통제항목 상세
CONTROLS: list[dict] = [
    {
        "code": "2.5.1",
        "desc": "사용자 등록·해지 및 권한부여 절차의 적정성과 미사용(휴면) 계정의 존재 여부를 점검한다.",
        "azure_cmd": "az ad user list --query \"[].{name:displayName,upn:userPrincipalName}\"\naz role assignment list --all --query \"[].{principal:principalName,role:roleDefinitionName}\" -o table",
        "criteria": "Entra ID 로그인 활동 기록(signInActivity) 상 90일 이상 미로그인 계정에 Owner·Contributor 등 역할이 남아있음, 퇴사자 계정 미삭제",
        "fix": "Entra ID Access Reviews(PIM)로 정기 계정·권한 검토 자동화, 미사용 계정 비활성화, HR 연동 SCIM 자동 프로비저닝·디프로비저닝 적용",
        "domain": "인증 및 권한관리",
        "resources": ["rbac", "entra"],
    },
    {
        "code": "2.5.3",
        "desc": "로그인 시 사용자를 안전하게 인증하는 절차(다중인증 등)가 적용되고 있는지 점검한다.",
        "azure_cmd": "az rest --method get --url \"https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails\"\naz rest --method get --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\"",
        "criteria": "전역 관리자 등 특권 역할 계정 중 MFA 미등록자 존재, MFA를 강제하는 Conditional Access 정책이 없거나 Disabled 상태",
        "fix": "Conditional Access로 전 사용자·관리자 MFA 강제 또는 Security Defaults 활성화, 특권 역할은 PIM 승격 시 MFA 재인증 필수화",
        "domain": "인증 및 권한관리",
        "resources": ["entra", "mfa"],
    },
    {
        "code": "2.5.4",
        "desc": "비밀번호의 생성·저장·변경 기준이 조직의 비밀번호 정책에 부합하는지 점검한다.",
        "azure_cmd": "az rest --method get --url \"https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy\"",
        "criteria": "Entra ID 기본 정책(8자 이상) 외 조직이 요구하는 Smart Lockout 임계값·금지어 목록 등 강화 설정이 미적용, 하이브리드 환경에서 온프레미스 AD 정책과 불일치",
        "fix": "Smart Lockout 임계값 강화, Azure AD Password Protection(맞춤 금지어 목록) 활성화, 하이브리드 환경은 온프레미스 AD 정책과 정합성 점검",
        "domain": "인증 및 권한관리",
        "resources": ["entra", "password"],
    },
    {
        "code": "2.5.5",
        "desc": "root·전역관리자 등 특수 계정과 과다 권한 부여 현황을 식별하고 최소권한 원칙 준수 여부를 점검한다.",
        "azure_cmd": "az role assignment list --role \"Owner\" --all -o table\naz rest --method get --url \"https://graph.microsoft.com/v1.0/directoryRoles\"",
        "criteria": "구독 Owner 역할이 다수 사용자·그룹에 광범위 부여, 전역 관리자(Global Administrator) 인원이 권고 범위(2~4명)를 초과하고 상시 활성 상태로 유지됨",
        "fix": "Reader·Contributor 등 세분화된 RBAC 역할과 사용자 지정 역할로 전환, 전역 관리자는 최소 인원만 유지하고 PIM으로 필요시(Just-In-Time) 승격 방식 적용",
        "domain": "인증 및 권한관리",
        "resources": ["rbac", "entra"],
    },
    {
        "code": "2.5.6",
        "desc": "사용자 접근권한 및 자격증명(액세스 키 등)이 정기적으로 검토·회수되는지 점검한다.",
        "azure_cmd": "az ad sp credential list --id SP_OBJECT_ID --query \"[].{keyId:keyId,endDate:endDateTime}\"\naz role assignment list --all -o table",
        "criteria": "서비스 프린시펄 시크릿 만료일이 1년 이상으로 설정되거나 이미 만료된 자격증명이 남아있음, 정기 Access Review가 구성되어 있지 않음",
        "fix": "서비스 프린시펄은 관리 ID(Managed Identity) 또는 인증서로 전환, 부득이 시크릿 사용 시 수명을 180일 이하로 단축, Entra ID Access Reviews를 분기 단위로 자동화",
        "domain": "인증 및 권한관리",
        "resources": ["rbac", "serviceprincipal"],
    },
    {
        "code": "2.6.1",
        "desc": "네트워크 대역별 접근통제(보안그룹·NSG 등)가 최소 허용 원칙으로 구성되어 있는지 점검한다.",
        "azure_cmd": "az network nsg list -o table\naz network nsg rule list --nsg-name NSG_NAME -g RESOURCE_GROUP --query \"[?sourceAddressPrefix=='*']\"",
        "criteria": "NSG 규칙의 Source가 Any(*)로 설정되어 인터넷 전체로부터 인바운드가 허용됨, 특히 22·3389 포트가 전면 개방",
        "fix": "NSG Source를 특정 IP·서비스 태그로 제한, Azure Bastion 또는 Just-In-Time VM Access(Defender for Cloud) 적용, Azure Policy로 Any 허용 규칙 탐지·차단",
        "domain": "접근통제",
        "resources": ["nsg"],
    },
    {
        "code": "2.6.6",
        "desc": "원격 운영 접속 경로가 안전하게 통제(전용회선, Bastion 등)되고 있는지 점검한다.",
        "azure_cmd": "az vm list-ip-addresses -o table\naz network bastion list -o table",
        "criteria": "VM에 퍼블릭 IP가 직결되어 있고 RDP·SSH가 열려 있으며, Bastion·Azure AD 로그인 없이 접속이 가능한 구조",
        "fix": "Azure Bastion 또는 Just-In-Time VM Access로 전환, 불필요한 퍼블릭 IP 제거, Azure AD 기반 VM 로그인(Login with Azure AD) 적용",
        "domain": "접근통제",
        "resources": ["nsg", "bastion", "publicip"],
    },
    {
        "code": "2.6.7",
        "desc": "내부 정보시스템의 인터넷 접속(아웃바운드)이 업무 목적에 맞게 통제되는지 점검한다.",
        "azure_cmd": "az network route-table list -o table\naz network nsg rule list --nsg-name NSG_NAME -g RESOURCE_GROUP --query \"[?direction=='Outbound']\"",
        "criteria": "사용자 정의 경로(UDR)가 없어 전체 아웃바운드가 인터넷으로 직접 나감, NSG 아웃바운드 규칙이 Any로 허용됨",
        "fix": "Azure Firewall·NVA로 아웃바운드를 강제 라우팅(UDR), Private Endpoint로 PaaS 접근 시 인터넷 우회, NSG 아웃바운드 규칙 최소화",
        "domain": "접근통제",
        "resources": ["nsg", "firewall"],
    },
    {
        "code": "2.7.1",
        "desc": "개인정보 및 중요정보의 저장·전송 구간에 적절한 암호화가 적용되는지 점검한다.",
        "azure_cmd": "az disk list --query \"[?encryption.type=='EncryptionAtRestWithPlatformKey']\" -o table\naz storage account show -n STORAGE_ACCOUNT --query \"encryption\"\naz sql db tde show -g RESOURCE_GROUP -s SQL_SERVER -n DB_NAME",
        "criteria": "SQL Database의 TDE(투명한 데이터 암호화)가 Disabled 상태, 규제상 고객관리키(CMK)가 요구되는 자원에 플랫폼 기본 키만 적용되어 있음",
        "fix": "비활성화된 DB의 TDE 즉시 재활성화, 규제상 요구되는 자원은 Key Vault 연동 Customer-Managed Key로 전환, Storage Service Encryption 적용 여부 상시 확인",
        "domain": "암호화 적용",
        "resources": ["storage", "sql", "tls"],
    },
    {
        "code": "2.7.2",
        "desc": "암호화에 사용되는 키의 생성·저장·배포·파기 및 로테이션 관리가 안전하게 이루어지는지 점검한다.",
        "azure_cmd": "az keyvault list -o table\naz keyvault key list --vault-name KEYVAULT_NAME\naz keyvault show --name KEYVAULT_NAME --query \"properties.{purgeProtection:enablePurgeProtection,softDelete:enableSoftDelete}\"",
        "criteria": "Key Vault의 Soft-delete·Purge Protection이 비활성화되어 키가 영구 삭제될 위험, 키에 만료일(expiry)이 설정되지 않아 무기한 사용됨",
        "fix": "Soft-delete·Purge Protection 필수 활성화, 키에 만료일 및 자동 로테이션 정책 설정, RBAC·액세스 정책으로 최소권한 부여",
        "domain": "암호화 적용",
        "resources": ["keyvault"],
    },
    {
        "code": "2.9.4",
        "desc": "정보시스템의 이용·접속기록이 법적 요구사항에 맞게 생성·보존되는지 점검한다.",
        "azure_cmd": "az monitor diagnostic-settings list --resource RESOURCE_ID\naz monitor log-analytics workspace list -o table\naz monitor activity-log list --start-time 2026-05-01",
        "criteria": "핵심 리소스(구독, 주요 VM·DB)에 진단 설정(Diagnostic Settings)이 구성되지 않아 로그가 수집되지 않음, Activity Log 보존기간이 기본값(90일)에 그쳐 법정 보관기간 미달",
        "fix": "전 구독·핵심 리소스에 Diagnostic Settings를 Log Analytics·Storage Account로 연동, Storage 수명주기 정책으로 장기보관(2년 이상), Azure Policy(Deploy if not exists)로 진단설정 강제",
        "domain": "시스템 및 서비스 운영관리",
        "resources": ["diagnostic", "activitylog"],
    },
    {
        "code": "2.9.5",
        "desc": "저장된 로그의 위·변조 방지 조치와 정기적인 점검·분석이 이루어지는지 점검한다.",
        "azure_cmd": "az storage account blob-service-properties show -n STORAGE_ACCOUNT --query \"{immutability:immutableStorageWithVersioning,softDelete:deleteRetentionPolicy}\"\naz role assignment list --scope WORKSPACE_ID -o table",
        "criteria": "로그 저장 Storage Account에 불변성(Immutable Blob Storage)이 설정되지 않아 변조·삭제가 가능, Log Analytics Workspace에 과다한 사용자가 편집 권한을 보유",
        "fix": "Immutable Blob Storage(WORM) 정책 적용, Workspace RBAC를 Reader 중심으로 최소화, 관리자 로그인·권한변경 기준 쿼리로 정기 로그 점검 자동화(Sentinel·Workbook)",
        "domain": "시스템 및 서비스 운영관리",
        "resources": ["diagnostic", "loganalytics"],
    },
    {
        "code": "2.10.2",
        "desc": "클라우드 서비스 이용에 따른 책임분계, 콘솔 접근통제, 설정변경 관리 등 클라우드 특화 보안통제를 점검한다.",
        "azure_cmd": "az account management-group list -o table\naz policy assignment list -o table\naz security regulatory-compliance-standards list",
        "criteria": "관리 그룹·Azure Policy가 미적용되어 구독 간 보안기준이 불일치, Defender for Cloud 보안 점수(Secure Score)가 저조하거나 규제 준수 표준 항목이 미충족",
        "fix": "관리 그룹 단위 Azure Policy(Deny·Audit)로 조직 전체 가드레일 구성, Defender for Cloud 상시 활성화 및 Secure Score 개선항목 조치, 구독 소유자 변경 등 주요 이벤트 알림(Action Group) 설정",
        "domain": "시스템 및 서비스 보안관리",
        "resources": ["policy", "managementgroup"],
    },
    {
        "code": "2.10.8",
        "desc": "운영체제 및 소프트웨어의 보안 패치가 적시에 식별·적용되는지 점검한다.",
        "azure_cmd": "az vm assess-patches -g RESOURCE_GROUP -n VM_NAME\naz automation software-update-configuration list --automation-account-name AUTOMATION_ACCOUNT -g RESOURCE_GROUP",
        "criteria": "Automatic VM Guest Patching이 미설정, Update Management(Azure Automation)에 등록되지 않은 VM이 존재, 평가 결과 Critical·Security 패치가 다수 미적용",
        "fix": "Automatic Guest Patching 활성화 또는 Azure Update Manager로 일원화, Maintenance Configuration으로 정기 패치 일정 수립, 패치 준수율 대시보드로 상시 추적",
        "domain": "시스템 및 서비스 보안관리",
        "resources": ["patch", "updatemgmt"],
    },
    {
        "code": "2.11.2",
        "desc": "정기적인 취약점 점검을 수행하고 발견된 취약점이 기준에 따라 조치되는지 점검한다.",
        "azure_cmd": "az security assessment list --query \"[?status.code=='Unhealthy']\"\naz security sub-assessment list",
        "criteria": "Defender for Cloud 취약점 평가가 일부 리소스에 구성되지 않음, Unhealthy 평가 항목이 장기간 조치되지 않고 누적됨",
        "fix": "Defender for Servers·Containers 등 플랜을 활성화해 취약점 스캔을 자동화, Unhealthy 항목을 SLA로 관리하고 Secure Score에 반영, 월 1회 이상 취약점 리포트 검토",
        "domain": "사고 예방 및 대응",
        "resources": ["defender", "assessment"],
    },
    {
        "code": "2.11.3",
        "desc": "침해사고 징후를 탐지하기 위한 이상행위 분석·모니터링 체계가 구축·운영되는지 점검한다.",
        "azure_cmd": "az security alert list --query \"[?status=='Active']\"\naz security auto-provisioning-setting list",
        "criteria": "Defender for Cloud Active Alert이 다수 미해결 상태로 누적됨, 자동 프로비저닝(모니터링 에이전트 배포)이 비활성화되어 일부 리소스가 모니터링 사각지대에 있음",
        "fix": "Defender for Cloud 전체 플랜과 Auto-provisioning 활성화, Microsoft Sentinel 연동으로 상관분석·자동대응(Playbook) 구성, Active Alert 대응 SLA 수립",
        "domain": "사고 예방 및 대응",
        "resources": ["defender", "alert"],
    },
    {
        "code": "2.12.1",
        "desc": "재해·재난 발생에 대비한 백업 및 이중화 조치가 마련되어 있는지 점검한다.",
        "azure_cmd": "az backup policy list -g RESOURCE_GROUP --vault-name VAULT_NAME\naz backup item list -g RESOURCE_GROUP --vault-name VAULT_NAME --query \"[?properties.lastBackupStatus=='Failed']\"\naz backup vault list --query \"[].properties.storageType\"",
        "criteria": "Recovery Services Vault에 정책이 연결되지 않은 자원이 존재, lastBackupStatus가 Failed인 항목이 다수, StorageType이 LocallyRedundant(LRS)로 지역 재해 시 손실 위험",
        "fix": "Recovery Services Vault를 GRS(Geo-Redundant)로 구성, 백업 실패 알림(Azure Monitor Alert) 설정, 연 1회 이상 DR 복구 모의훈련을 수행하고 결과 문서화",
        "domain": "재해복구",
        "resources": ["backup"],
    },
]


_BY_CODE = {c["code"]: c for c in CONTROLS}


def all_controls() -> list[dict]:
    return list(CONTROLS)


def control(code: str) -> dict | None:
    return _BY_CODE.get(code)


def controls_for_resource(resource_tag: str) -> list[dict]:
    """리소스 태그(nsg/rbac/storage 등)에 관련된 통제항목 목록."""
    return [c for c in CONTROLS if resource_tag in c.get("resources", [])]
