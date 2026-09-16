"""ISMS-P(2022) 클라우드 인프라 점검 매트릭스 — AWS/Azure 통제항목 지식 베이스.

영역 2 '보호대책 요구사항'의 클라우드 인프라 직결 7개 영역·17개 통제항목.
각 항목: code(통제번호), domain(영역명), desc(점검목적), resources(관련 리소스 태그),
그리고 플랫폼별(azure/aws) {cmd(참고 CLI), criteria(문제 판단기준), fix(개선방안)}.

출처: 사내 참고자료 'isms-cloud-audit-matrix'(ISMS-P 인증기준 재구성). KISA 공식 심사자료를 대체하지 않음.
이 모듈은 인터넷 없이 동작하도록 데이터를 코드에 임베드한다(폐쇄망 전제).
"""

from __future__ import annotations

# code -> 통제항목 상세(플랫폼별 criteria/fix/cmd 포함)
CONTROLS: list[dict] = [
    {
        "code": "2.5.1",
        "domain": "인증 및 권한관리",
        "desc": "사용자 등록·해지 및 권한부여 절차의 적정성과 미사용(휴면) 계정의 존재 여부를 점검한다.",
        "resources": [
            "rbac",
            "entra"
        ],
        "azure": {
            "cmd": "az ad user list --query \"[].{name:displayName,upn:userPrincipalName}\"\naz role assignment list --all --query \"[].{principal:principalName,role:roleDefinitionName}\" -o table",
            "criteria": "Entra ID 로그인 활동 기록(signInActivity) 상 90일 이상 미로그인 계정에 Owner·Contributor 등 역할이 남아있음, 퇴사자 계정 미삭제",
            "fix": "Entra ID Access Reviews(PIM)로 정기 계정·권한 검토 자동화, 미사용 계정 비활성화, HR 연동 SCIM 자동 프로비저닝·디프로비저닝 적용"
        },
        "aws": {
            "cmd": "aws iam generate-credential-report\naws iam get-credential-report --query 'Content' --output text | base64 --decode\naws iam list-users --query 'Users[*].[UserName,PasswordLastUsed]' --output table",
            "criteria": "credential report의 password_last_used·access_key_last_used가 90일 이상이거나, 퇴사·전보자 계정이 Active 상태로 남아있음",
            "fix": "90일 이상 미사용 IAM 사용자 비활성화·삭제, IAM Identity Center(SSO)로 개별 계정 최소화, 계정 발급·회수를 승인 이력이 남는 절차로 문서화"
        }
    },
    {
        "code": "2.5.3",
        "domain": "인증 및 권한관리",
        "desc": "로그인 시 사용자를 안전하게 인증하는 절차(다중인증 등)가 적용되고 있는지 점검한다.",
        "resources": [
            "entra",
            "mfa"
        ],
        "azure": {
            "cmd": "az rest --method get --url \"https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails\"\naz rest --method get --url \"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\"",
            "criteria": "전역 관리자 등 특권 역할 계정 중 MFA 미등록자 존재, MFA를 강제하는 Conditional Access 정책이 없거나 Disabled 상태",
            "fix": "Conditional Access로 전 사용자·관리자 MFA 강제 또는 Security Defaults 활성화, 특권 역할은 PIM 승격 시 MFA 재인증 필수화"
        },
        "aws": {
            "cmd": "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'\naws iam list-virtual-mfa-devices\naws iam get-credential-report --query 'Content' --output text | base64 --decode",
            "criteria": "root 계정 AccountMFAEnabled 값이 0(미설정), 콘솔 접근 권한이 있는 IAM 사용자 중 credential report의 mfa_active가 false인 사용자가 다수 존재",
            "fix": "root 계정 하드웨어·가상 MFA 필수 등록 후 평상시 미사용, IAM 정책 조건(aws:MultiFactorAuthPresent)으로 콘솔·API 접근 시 MFA 강제, IAM Identity Center 전환 시 SSO+MFA 일원화"
        }
    },
    {
        "code": "2.5.4",
        "domain": "인증 및 권한관리",
        "desc": "비밀번호의 생성·저장·변경 기준이 조직의 비밀번호 정책에 부합하는지 점검한다.",
        "resources": [
            "entra",
            "password"
        ],
        "azure": {
            "cmd": "az rest --method get --url \"https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy\"",
            "criteria": "Entra ID 기본 정책(8자 이상) 외 조직이 요구하는 Smart Lockout 임계값·금지어 목록 등 강화 설정이 미적용, 하이브리드 환경에서 온프레미스 AD 정책과 불일치",
            "fix": "Smart Lockout 임계값 강화, Azure AD Password Protection(맞춤 금지어 목록) 활성화, 하이브리드 환경은 온프레미스 AD 정책과 정합성 점검"
        },
        "aws": {
            "cmd": "aws iam get-account-password-policy",
            "criteria": "정책 자체가 없음(NoSuchEntity 오류) 또는 MinimumPasswordLength가 8 미만, RequireSymbols·RequireNumbers가 false, PasswordReusePrevention 미설정",
            "fix": "계정 비밀번호 정책을 조직 기준(예: 최소 10자 이상, 복합문자, 재사용 방지 12회, 90일 만료)으로 설정하고 정기 점검"
        }
    },
    {
        "code": "2.5.5",
        "domain": "인증 및 권한관리",
        "desc": "root·전역관리자 등 특수 계정과 과다 권한 부여 현황을 식별하고 최소권한 원칙 준수 여부를 점검한다.",
        "resources": [
            "rbac",
            "entra"
        ],
        "azure": {
            "cmd": "az role assignment list --role \"Owner\" --all -o table\naz rest --method get --url \"https://graph.microsoft.com/v1.0/directoryRoles\"",
            "criteria": "구독 Owner 역할이 다수 사용자·그룹에 광범위 부여, 전역 관리자(Global Administrator) 인원이 권고 범위(2~4명)를 초과하고 상시 활성 상태로 유지됨",
            "fix": "Reader·Contributor 등 세분화된 RBAC 역할과 사용자 지정 역할로 전환, 전역 관리자는 최소 인원만 유지하고 PIM으로 필요시(Just-In-Time) 승격 방식 적용"
        },
        "aws": {
            "cmd": "aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root\naws iam list-attached-user-policies --user-name USER_NAME\naws iam list-policies --scope Local --only-attached --query \"Policies[*].PolicyName\"",
            "criteria": "root 계정으로 일상 업무(콘솔 로그인·API 호출) 이력 존재, 다수 사용자에게 AdministratorAccess 등 광범위한 권한이 그대로 부여됨",
            "fix": "root는 최초 설정·비상시에만 사용하도록 절차화, 일상 관리 업무는 Assume Role 기반 IAM Role로 전환, 업무별 최소권한 Customer Managed Policy로 세분화"
        }
    },
    {
        "code": "2.5.6",
        "domain": "인증 및 권한관리",
        "desc": "사용자 접근권한 및 자격증명(액세스 키 등)이 정기적으로 검토·회수되는지 점검한다.",
        "resources": [
            "rbac",
            "serviceprincipal"
        ],
        "azure": {
            "cmd": "az ad sp credential list --id SP_OBJECT_ID --query \"[].{keyId:keyId,endDate:endDateTime}\"\naz role assignment list --all -o table",
            "criteria": "서비스 프린시펄 시크릿 만료일이 1년 이상으로 설정되거나 이미 만료된 자격증명이 남아있음, 정기 Access Review가 구성되어 있지 않음",
            "fix": "서비스 프린시펄은 관리 ID(Managed Identity) 또는 인증서로 전환, 부득이 시크릿 사용 시 수명을 180일 이하로 단축, Entra ID Access Reviews를 분기 단위로 자동화"
        },
        "aws": {
            "cmd": "aws iam get-credential-report --query 'Content' --output text | base64 --decode\naws iam list-access-keys --user-name USER_NAME\naws accessanalyzer list-findings",
            "criteria": "액세스 키 생성 후 90일 이상 미교체, 사용하지 않는 액세스 키가 활성 상태로 존재, Access Analyzer가 외부 계정·퍼블릭 공유 리소스를 탐지",
            "fix": "액세스 키 90일 주기 교체 및 미사용 키 즉시 삭제, IAM Access Analyzer 상시 활성화, 분기별 권한 검토(Access Review) 절차 수립"
        }
    },
    {
        "code": "2.6.1",
        "domain": "접근통제",
        "desc": "네트워크 대역별 접근통제(보안그룹·NSG 등)가 최소 허용 원칙으로 구성되어 있는지 점검한다.",
        "resources": [
            "nsg"
        ],
        "azure": {
            "cmd": "az network nsg list -o table\naz network nsg rule list --nsg-name NSG_NAME -g RESOURCE_GROUP --query \"[?sourceAddressPrefix=='*']\"",
            "criteria": "NSG 규칙의 Source가 Any(*)로 설정되어 인터넷 전체로부터 인바운드가 허용됨, 특히 22·3389 포트가 전면 개방",
            "fix": "NSG Source를 특정 IP·서비스 태그로 제한, Azure Bastion 또는 Just-In-Time VM Access(Defender for Cloud) 적용, Azure Policy로 Any 허용 규칙 탐지·차단"
        },
        "aws": {
            "cmd": "aws ec2 describe-security-groups --query \"SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].[GroupId,GroupName]\"",
            "criteria": "0.0.0.0/0(Any)로부터 전체 포트 또는 관리 포트(22, 3389, 3306, 5432 등)가 인바운드로 열려 있음",
            "fix": "보안그룹 인바운드를 업무상 필요한 출발지 IP·대역으로 제한, 관리 포트는 사내 VPN·Bastion 대역만 허용, AWS Config 규칙(restricted-ssh 등)으로 상시 탐지"
        }
    },
    {
        "code": "2.6.6",
        "domain": "접근통제",
        "desc": "원격 운영 접속 경로가 안전하게 통제(전용회선, Bastion 등)되고 있는지 점검한다.",
        "resources": [
            "nsg",
            "bastion",
            "publicip"
        ],
        "azure": {
            "cmd": "az vm list-ip-addresses -o table\naz network bastion list -o table",
            "criteria": "VM에 퍼블릭 IP가 직결되어 있고 RDP·SSH가 열려 있으며, Bastion·Azure AD 로그인 없이 접속이 가능한 구조",
            "fix": "Azure Bastion 또는 Just-In-Time VM Access로 전환, 불필요한 퍼블릭 IP 제거, Azure AD 기반 VM 로그인(Login with Azure AD) 적용"
        },
        "aws": {
            "cmd": "aws ec2 describe-instances --query \"Reservations[].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress]\"",
            "criteria": "퍼블릭 IP가 부여된 인스턴스에 22·3389 인바운드가 함께 열려 있어(2.6.1 결과와 교차 확인) Bastion·VPN을 거치지 않고 직접 접속 가능",
            "fix": "Bastion Host 또는 Systems Manager Session Manager로 원격 접속을 일원화, 불필요한 퍼블릭 IP 회수, Session Manager 접속기록은 CloudWatch Logs로 연동"
        }
    },
    {
        "code": "2.6.7",
        "domain": "접근통제",
        "desc": "내부 정보시스템의 인터넷 접속(아웃바운드)이 업무 목적에 맞게 통제되는지 점검한다.",
        "resources": [
            "nsg",
            "firewall"
        ],
        "azure": {
            "cmd": "az network route-table list -o table\naz network nsg rule list --nsg-name NSG_NAME -g RESOURCE_GROUP --query \"[?direction=='Outbound']\"",
            "criteria": "사용자 정의 경로(UDR)가 없어 전체 아웃바운드가 인터넷으로 직접 나감, NSG 아웃바운드 규칙이 Any로 허용됨",
            "fix": "Azure Firewall·NVA로 아웃바운드를 강제 라우팅(UDR), Private Endpoint로 PaaS 접근 시 인터넷 우회, NSG 아웃바운드 규칙 최소화"
        },
        "aws": {
            "cmd": "aws ec2 describe-route-tables --query \"RouteTables[].Routes[?GatewayId!=null]\"\naws ec2 describe-nat-gateways --query \"NatGateways[*].[NatGatewayId,State]\"",
            "criteria": "DB 등 민감 서브넷이 인터넷 게이트웨이(IGW)로 직접 라우팅되어 있음, 보안그룹 아웃바운드가 0.0.0.0/0 전면 허용 상태",
            "fix": "민감 자원은 Private Subnet + NAT Gateway 구조로 전환, 아웃바운드도 필요한 목적지·포트로 제한, VPC Endpoint로 AWS 서비스 접근 시 인터넷 경유 최소화"
        }
    },
    {
        "code": "2.7.1",
        "domain": "암호화 적용",
        "desc": "개인정보 및 중요정보의 저장·전송 구간에 적절한 암호화가 적용되는지 점검한다.",
        "resources": [
            "storage",
            "sql",
            "tls"
        ],
        "azure": {
            "cmd": "az disk list --query \"[?encryption.type=='EncryptionAtRestWithPlatformKey']\" -o table\naz storage account show -n STORAGE_ACCOUNT --query \"encryption\"\naz sql db tde show -g RESOURCE_GROUP -s SQL_SERVER -n DB_NAME",
            "criteria": "SQL Database의 TDE(투명한 데이터 암호화)가 Disabled 상태, 규제상 고객관리키(CMK)가 요구되는 자원에 플랫폼 기본 키만 적용되어 있음",
            "fix": "비활성화된 DB의 TDE 즉시 재활성화, 규제상 요구되는 자원은 Key Vault 연동 Customer-Managed Key로 전환, Storage Service Encryption 적용 여부 상시 확인"
        },
        "aws": {
            "cmd": "aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].VolumeId'\naws s3api get-bucket-encryption --bucket BUCKET_NAME\naws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`].DBInstanceIdentifier'",
            "criteria": "EBS 볼륨·RDS·S3 버킷 중 암호화가 적용되지 않은 자원이 존재(특히 개인정보·중요정보 저장소), get-bucket-encryption 조회 시 NoSuchEncryption 오류 반환",
            "fix": "계정 단위 EBS 기본 암호화 활성화, S3 기본 암호화(SSE-S3·SSE-KMS)를 강제하고 버킷 정책으로 미암호화 업로드 거부, RDS는 스냅샷 복사 후 암호화 옵션으로 재생성"
        }
    },
    {
        "code": "2.7.2",
        "domain": "암호화 적용",
        "desc": "암호화에 사용되는 키의 생성·저장·배포·파기 및 로테이션 관리가 안전하게 이루어지는지 점검한다.",
        "resources": [
            "keyvault"
        ],
        "azure": {
            "cmd": "az keyvault list -o table\naz keyvault key list --vault-name KEYVAULT_NAME\naz keyvault show --name KEYVAULT_NAME --query \"properties.{purgeProtection:enablePurgeProtection,softDelete:enableSoftDelete}\"",
            "criteria": "Key Vault의 Soft-delete·Purge Protection이 비활성화되어 키가 영구 삭제될 위험, 키에 만료일(expiry)이 설정되지 않아 무기한 사용됨",
            "fix": "Soft-delete·Purge Protection 필수 활성화, 키에 만료일 및 자동 로테이션 정책 설정, RBAC·액세스 정책으로 최소권한 부여"
        },
        "aws": {
            "cmd": "aws kms list-keys\naws kms get-key-rotation-status --key-id KEY_ID\naws kms get-key-policy --key-id KEY_ID --policy-name default",
            "criteria": "고객관리형 키(CMK)의 자동 로테이션이 비활성화, 키 정책의 Principal이 과도하게 넓게(예: 계정 전체 또는 *) 허용되어 있음",
            "fix": "KMS 키 자동 로테이션(연 1회) 활성화, 키 정책을 특정 Role·서비스로 최소권한화, CloudTrail 데이터 이벤트로 키 사용 이력 감사"
        }
    },
    {
        "code": "2.9.4",
        "domain": "시스템 및 서비스 운영관리",
        "desc": "정보시스템의 이용·접속기록이 법적 요구사항에 맞게 생성·보존되는지 점검한다.",
        "resources": [
            "diagnostic",
            "activitylog"
        ],
        "azure": {
            "cmd": "az monitor diagnostic-settings list --resource RESOURCE_ID\naz monitor log-analytics workspace list -o table\naz monitor activity-log list --start-time 2026-05-01",
            "criteria": "핵심 리소스(구독, 주요 VM·DB)에 진단 설정(Diagnostic Settings)이 구성되지 않아 로그가 수집되지 않음, Activity Log 보존기간이 기본값(90일)에 그쳐 법정 보관기간 미달",
            "fix": "전 구독·핵심 리소스에 Diagnostic Settings를 Log Analytics·Storage Account로 연동, Storage 수명주기 정책으로 장기보관(2년 이상), Azure Policy(Deploy if not exists)로 진단설정 강제"
        },
        "aws": {
            "cmd": "aws cloudtrail describe-trails --query \"trailList[*].[Name,IsMultiRegionTrail,IsOrganizationTrail]\"\naws cloudtrail get-trail-status --name TRAIL_NAME\naws cloudtrail get-event-selectors --trail-name TRAIL_NAME",
            "criteria": "CloudTrail이 일부 리전에서 비활성화되어 있거나 IsMultiRegionTrail이 false, 로그 보관 기간이 법정 요구(접속기록 2년 이상 등)에 미달",
            "fix": "전 리전 CloudTrail 활성화 및 Organizations 단위 통합 추적 구성, S3 로그 버킷에 수명주기 정책으로 법정 보관기간 이상 보존, CloudWatch Logs 연동으로 실시간 모니터링"
        }
    },
    {
        "code": "2.9.5",
        "domain": "시스템 및 서비스 운영관리",
        "desc": "저장된 로그의 위·변조 방지 조치와 정기적인 점검·분석이 이루어지는지 점검한다.",
        "resources": [
            "diagnostic",
            "loganalytics"
        ],
        "azure": {
            "cmd": "az storage account blob-service-properties show -n STORAGE_ACCOUNT --query \"{immutability:immutableStorageWithVersioning,softDelete:deleteRetentionPolicy}\"\naz role assignment list --scope WORKSPACE_ID -o table",
            "criteria": "로그 저장 Storage Account에 불변성(Immutable Blob Storage)이 설정되지 않아 변조·삭제가 가능, Log Analytics Workspace에 과다한 사용자가 편집 권한을 보유",
            "fix": "Immutable Blob Storage(WORM) 정책 적용, Workspace RBAC를 Reader 중심으로 최소화, 관리자 로그인·권한변경 기준 쿼리로 정기 로그 점검 자동화(Sentinel·Workbook)"
        },
        "aws": {
            "cmd": "aws cloudtrail get-trail-status --name TRAIL_NAME --query \"LogFileValidationEnabled\"\naws s3api get-bucket-policy --bucket LOG_BUCKET\naws s3api get-public-access-block --bucket LOG_BUCKET",
            "criteria": "로그파일 무결성 검증(Log File Validation)이 비활성화, 로그 버킷이 일반 관리자에게 삭제·수정 권한을 부여하거나 퍼블릭 접근이 가능",
            "fix": "Log File Validation 활성화(SHA-256 다이제스트 서명), 로그 버킷을 별도 계정으로 분리 후 Object Lock(WORM)·최소권한 정책 적용, 월 1회 이상 로그 검토·이상탐지 자동화(Athena 등)"
        }
    },
    {
        "code": "2.10.2",
        "domain": "시스템 및 서비스 보안관리",
        "desc": "클라우드 서비스 이용에 따른 책임분계, 콘솔 접근통제, 설정변경 관리 등 클라우드 특화 보안통제를 점검한다.",
        "resources": [
            "policy",
            "managementgroup"
        ],
        "azure": {
            "cmd": "az account management-group list -o table\naz policy assignment list -o table\naz security regulatory-compliance-standards list",
            "criteria": "관리 그룹·Azure Policy가 미적용되어 구독 간 보안기준이 불일치, Defender for Cloud 보안 점수(Secure Score)가 저조하거나 규제 준수 표준 항목이 미충족",
            "fix": "관리 그룹 단위 Azure Policy(Deny·Audit)로 조직 전체 가드레일 구성, Defender for Cloud 상시 활성화 및 Secure Score 개선항목 조치, 구독 소유자 변경 등 주요 이벤트 알림(Action Group) 설정"
        },
        "aws": {
            "cmd": "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin\naws organizations describe-organization\naws securityhub get-findings --filters '{\"ComplianceStatus\":[{\"Value\":\"FAILED\",\"Comparison\":\"EQUALS\"}]}'",
            "criteria": "콘솔 로그인 이벤트에 비정상 위치·시간대 접속 존재, Organizations SCP 등 계정 간 가드레일 미설정, Security Hub 컴플라이언스 FAILED 항목 다수",
            "fix": "Organizations + SCP로 계정 단위 가드레일 설정, Security Hub·Config Conformance Pack으로 CIS AWS Foundations 벤치마크 상시 점검, 콘솔 로그인 이상탐지에 GuardDuty 연계"
        }
    },
    {
        "code": "2.10.8",
        "domain": "시스템 및 서비스 보안관리",
        "desc": "운영체제 및 소프트웨어의 보안 패치가 적시에 식별·적용되는지 점검한다.",
        "resources": [
            "patch",
            "updatemgmt"
        ],
        "azure": {
            "cmd": "az vm assess-patches -g RESOURCE_GROUP -n VM_NAME\naz automation software-update-configuration list --automation-account-name AUTOMATION_ACCOUNT -g RESOURCE_GROUP",
            "criteria": "Automatic VM Guest Patching이 미설정, Update Management(Azure Automation)에 등록되지 않은 VM이 존재, 평가 결과 Critical·Security 패치가 다수 미적용",
            "fix": "Automatic Guest Patching 활성화 또는 Azure Update Manager로 일원화, Maintenance Configuration으로 정기 패치 일정 수립, 패치 준수율 대시보드로 상시 추적"
        },
        "aws": {
            "cmd": "aws ssm describe-instance-information --query \"InstanceInformationList[*].[InstanceId,PingStatus]\"\naws ssm list-compliance-items --resource-id INSTANCE_ID\naws ssm describe-patch-group-state --patch-group PATCH_GROUP",
            "criteria": "Systems Manager 관리 대상에 등록되지 않은 인스턴스가 존재(패치 관리 사각지대), Patch Compliance 상태가 NON_COMPLIANT인 인스턴스가 다수",
            "fix": "전 EC2에 SSM Agent 설치 및 Patch Manager 베이스라인·일정 적용, Maintenance Window로 정기 패치 자동화, Compliance 대시보드로 미준수 인스턴스 상시 추적"
        }
    },
    {
        "code": "2.11.2",
        "domain": "사고 예방 및 대응",
        "desc": "정기적인 취약점 점검을 수행하고 발견된 취약점이 기준에 따라 조치되는지 점검한다.",
        "resources": [
            "defender",
            "assessment"
        ],
        "azure": {
            "cmd": "az security assessment list --query \"[?status.code=='Unhealthy']\"\naz security sub-assessment list",
            "criteria": "Defender for Cloud 취약점 평가가 일부 리소스에 구성되지 않음, Unhealthy 평가 항목이 장기간 조치되지 않고 누적됨",
            "fix": "Defender for Servers·Containers 등 플랜을 활성화해 취약점 스캔을 자동화, Unhealthy 항목을 SLA로 관리하고 Secure Score에 반영, 월 1회 이상 취약점 리포트 검토"
        },
        "aws": {
            "cmd": "aws inspector2 batch-get-account-status\naws inspector2 list-findings --filter-criteria '{\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"CRITICAL\"}]}'",
            "criteria": "Inspector2가 일부 계정·리전에서 비활성화되어 있음, CRITICAL·HIGH 등급 취약점이 장기간 조치되지 않은 채 방치됨",
            "fix": "전 계정·리전에 Inspector2 활성화(EC2·ECR·Lambda 스캔), 취약점 등급별 조치 SLA(예: Critical 7일 이내)를 수립하고 티켓 시스템과 연동, 정기 리포트로 경영진 보고"
        }
    },
    {
        "code": "2.11.3",
        "domain": "사고 예방 및 대응",
        "desc": "침해사고 징후를 탐지하기 위한 이상행위 분석·모니터링 체계가 구축·운영되는지 점검한다.",
        "resources": [
            "defender",
            "alert"
        ],
        "azure": {
            "cmd": "az security alert list --query \"[?status=='Active']\"\naz security auto-provisioning-setting list",
            "criteria": "Defender for Cloud Active Alert이 다수 미해결 상태로 누적됨, 자동 프로비저닝(모니터링 에이전트 배포)이 비활성화되어 일부 리소스가 모니터링 사각지대에 있음",
            "fix": "Defender for Cloud 전체 플랜과 Auto-provisioning 활성화, Microsoft Sentinel 연동으로 상관분석·자동대응(Playbook) 구성, Active Alert 대응 SLA 수립"
        },
        "aws": {
            "cmd": "aws guardduty list-detectors\naws guardduty get-detector --detector-id DETECTOR_ID\naws guardduty list-findings --detector-id DETECTOR_ID",
            "criteria": "GuardDuty가 비활성화되어 있음, 활성화된 경우에도 High·Critical Finding이 장기간 확인·대응되지 않고 누적됨",
            "fix": "전 계정·리전에 GuardDuty 활성화(Organizations 위임 관리자로 중앙화), Finding을 EventBridge+SNS 또는 SOAR로 자동 알림·대응 연계, 위협 인텔리전스 룰셋 정기 갱신"
        }
    },
    {
        "code": "2.12.1",
        "domain": "재해복구",
        "desc": "재해·재난 발생에 대비한 백업 및 이중화 조치가 마련되어 있는지 점검한다.",
        "resources": [
            "backup"
        ],
        "azure": {
            "cmd": "az backup policy list -g RESOURCE_GROUP --vault-name VAULT_NAME\naz backup item list -g RESOURCE_GROUP --vault-name VAULT_NAME --query \"[?properties.lastBackupStatus=='Failed']\"\naz backup vault list --query \"[].properties.storageType\"",
            "criteria": "Recovery Services Vault에 정책이 연결되지 않은 자원이 존재, lastBackupStatus가 Failed인 항목이 다수, StorageType이 LocallyRedundant(LRS)로 지역 재해 시 손실 위험",
            "fix": "Recovery Services Vault를 GRS(Geo-Redundant)로 구성, 백업 실패 알림(Azure Monitor Alert) 설정, 연 1회 이상 DR 복구 모의훈련을 수행하고 결과 문서화"
        },
        "aws": {
            "cmd": "aws backup list-backup-plans\naws backup list-backup-jobs --by-state FAILED\naws dlm get-lifecycle-policies",
            "criteria": "중요 자원(RDS·EBS·EFS)에 백업 계획(Backup Plan)이 연결되어 있지 않음, 최근 백업 Job이 FAILED 상태로 다수 존재, 백업 보관 리전이 운영 리전과 동일해 재해 시 동반 손실 위험",
            "fix": "AWS Backup으로 전사 백업 정책을 RPO·RTO 기준에 맞게 표준화, Cross-Region Copy로 이중화, 정기 복구 테스트(Restore Test)를 수행하고 결과를 기록·보고"
        }
    }
]


_BY_CODE = {c["code"]: c for c in CONTROLS}


def all_controls() -> list[dict]:
    return list(CONTROLS)


def control(code: str) -> dict | None:
    """통제항목 원본(플랫폼별 데이터 포함)."""
    return _BY_CODE.get(code)


def control_for(code: str, platform: str = "azure") -> dict:
    """특정 플랫폼(azure/aws) 관점의 통제항목 정보를 평탄화해 반환.

    반환: {code, domain, desc, resources, platform, cmd, criteria, fix}
    알 수 없는 code면 빈 기본값.
    """
    c = _BY_CODE.get(code)
    if not c:
        return {"code": code, "domain": "", "desc": "", "resources": [],
                "platform": platform, "cmd": "", "criteria": "", "fix": ""}
    plat = c.get(platform) or c.get("azure") or {}
    return {
        "code": c["code"],
        "domain": c.get("domain", ""),
        "desc": c.get("desc", ""),
        "resources": c.get("resources", []),
        "platform": platform,
        "cmd": plat.get("cmd", ""),
        "criteria": plat.get("criteria", ""),
        "fix": plat.get("fix", ""),
        "bad_example": plat.get("bad_example", ""),
        "good_example": plat.get("good_example", ""),
    }


def controls_for_resource(resource_tag: str) -> list[dict]:
    """리소스 태그(nsg/rbac/storage 등)에 관련된 통제항목 목록."""
    return [c for c in CONTROLS if resource_tag in c.get("resources", [])]



# 리소스 태그 → 장비/서비스 그룹명(수집 스크립트 섹션 구분용)
_SERVICE_MAP_AZURE = {
    "nsg": "네트워크(NSG/방화벽)", "firewall": "네트워크(NSG/방화벽)",
    "bastion": "네트워크(NSG/방화벽)", "publicip": "네트워크(NSG/방화벽)",
    "rbac": "IAM/Entra ID", "entra": "IAM/Entra ID", "mfa": "IAM/Entra ID",
    "password": "IAM/Entra ID", "serviceprincipal": "IAM/Entra ID",
    "storage": "Storage", "tls": "Storage",
    "keyvault": "Key Vault", "sql": "SQL Database",
    "diagnostic": "모니터링/로그", "activitylog": "모니터링/로그", "loganalytics": "모니터링/로그",
    "policy": "거버넌스(Policy/관리그룹)", "managementgroup": "거버넌스(Policy/관리그룹)",
    "patch": "패치/업데이트", "updatemgmt": "패치/업데이트",
    "defender": "Defender for Cloud", "assessment": "Defender for Cloud", "alert": "Defender for Cloud",
    "backup": "백업/재해복구",
}
_SERVICE_MAP_AWS = {
    "nsg": "네트워크(보안그룹)", "firewall": "네트워크(보안그룹)",
    "bastion": "네트워크(보안그룹)", "publicip": "네트워크(보안그룹)",
    "rbac": "IAM", "entra": "IAM", "mfa": "IAM",
    "password": "IAM", "serviceprincipal": "IAM",
    "storage": "S3/스토리지", "tls": "S3/스토리지",
    "keyvault": "KMS", "sql": "RDS",
    "diagnostic": "CloudTrail/로그", "activitylog": "CloudTrail/로그", "loganalytics": "CloudTrail/로그",
    "policy": "거버넌스(Organizations/Config)", "managementgroup": "거버넌스(Organizations/Config)",
    "patch": "패치(SSM)", "updatemgmt": "패치(SSM)",
    "defender": "GuardDuty/Inspector", "assessment": "GuardDuty/Inspector", "alert": "GuardDuty/Inspector",
    "backup": "백업/재해복구",
}


def _service_for(resources: list[str], platform: str) -> str:
    """리소스 태그 목록 → 대표 장비/서비스 그룹명."""
    mapping = _SERVICE_MAP_AWS if platform == "aws" else _SERVICE_MAP_AZURE
    for tag in resources or []:
        if tag in mapping:
            return mapping[tag]
    return "기타"


def collection_commands(platform: str = "azure") -> list[dict]:
    """플랫폼(azure/aws)별 '정보 수집(점검) 명령어'를 통제항목 순으로 정리.

    각 항목: {code, domain, desc, platform, cmd, cmd_lines, criteria, service, ...}
    - cmd: 원본 멀티라인 명령 문자열
    - cmd_lines: 줄 단위로 분리한 명령 목록(화면에서 명령별 복사용, 빈 줄 제외)
    - service: 장비/서비스 그룹명(수집 스크립트 섹션 구분용)
    통제항목 코드 순으로 정렬해 반환한다.
    """
    out: list[dict] = []
    for c in sorted(CONTROLS, key=lambda x: [int(p) for p in x["code"].split(".")]):
        plat = c.get(platform) or {}
        cmd = plat.get("cmd", "") or ""
        lines = [ln.strip() for ln in cmd.splitlines() if ln.strip()]
        out.append({
            "code": c["code"],
            "domain": c.get("domain", ""),
            "desc": c.get("desc", ""),
            "platform": platform,
            "cmd": cmd,
            "cmd_lines": lines,
            "criteria": plat.get("criteria", ""),
            "bad_example": plat.get("bad_example", ""),
            "good_example": plat.get("good_example", ""),
            "service": _service_for(c.get("resources", []), platform),
        })

    # Azure는 SQL 보안 세부 8항목(TDE/CMK/Public/PrivateEndpoint/Auditing/Defender/VA/LTR)도 함께 노출
    if platform == "azure":
        from .sql_controls import sql_checks
        for s in sql_checks():
            cmd = s.get("cmd", "") or ""
            lines = [ln.strip() for ln in cmd.splitlines() if ln.strip()]
            out.append({
                "code": s.get("control_code", ""),
                "domain": "SQL 보안 세부점검",
                "desc": s.get("title", ""),
                "platform": platform,
                "cmd": cmd,
                "cmd_lines": lines,
                "criteria": s.get("criteria", ""),
                "bad_example": s.get("bad_example", ""),
                "good_example": s.get("good_example", ""),
                "service": "SQL Database",
            })
    return out
