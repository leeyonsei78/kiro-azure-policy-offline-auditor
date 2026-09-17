"""Azure SQL 보안 세부 점검 카탈로그 (ISMS-P 연계).

Azure SQL Database/Managed Instance의 8개 핵심 보안 점검 항목을 다룬다.
각 항목은 상위 ISMS-P 통제코드(control_code)에 매핑되며, 수집 CLI 명령(cmd),
문제 판단기준(criteria), 개선방안(fix), 위반 예시(bad_example),
개선 예시(good_example)를 포함한다.

엔진(engine._check_sql_obj)이 이 카탈로그의 판정 규칙을 참조해 Azure SQL 관련
JSON 입력에서 취약점을 탐지한다. 모두 인터넷/AI 없이 동작(폐쇄망 전제).
"""

from __future__ import annotations

# 8개 SQL 보안 항목. key = 엔진에서 쓰는 issue_type.
SQL_CHECKS: list[dict] = [
    {
        "key": "sql_tde_disabled",
        "control_code": "2.7.1",
        "title": "SQL TDE(투명한 데이터 암호화) 비활성화",
        "cmd": "az sql db tde show -g <RG> -s <SERVER> -n <DB> --query \"{state:state}\"",
        "criteria": "SQL Database의 TDE(Transparent Data Encryption) state가 Disabled로, 저장 데이터가 암호화되지 않음",
        "fix": "az sql db tde set --status Enabled 로 TDE를 즉시 활성화. 신규 DB는 기본 활성이나 마이그레이션·복원 DB는 반드시 확인",
        "bad_example": "{ \"name\": \"tde\", \"state\": \"Disabled\" }",
        "good_example": "{ \"name\": \"current\", \"state\": \"Enabled\" }",
        "why": "TDE는 데이터베이스 파일과 백업을 저장 단계에서 자동 암호화합니다. 꺼져 있으면 디스크·백업이 유출될 때 "
               "DB 내용이 평문으로 그대로 노출됩니다.",
        "how_to_fix": "1) az sql db tde set --status Enabled 로 TDE를 켭니다.\n"
                      "2) 신규 DB는 기본 활성이지만, 복원·마이그레이션한 DB는 반드시 상태를 확인합니다.",
    },
    {
        "key": "sql_cmk_not_used",
        "control_code": "2.7.2",
        "title": "SQL 암호화 키가 서비스 관리 키(플랫폼 키)만 사용 (CMK 미적용)",
        "cmd": "az sql server tde-key show -g <RG> -s <SERVER> --query \"{type:serverKeyType, uri:uri}\"",
        "criteria": "규제상 고객관리키(CMK, BYOK)가 요구되는 자원에 ServiceManaged(플랫폼 기본) 키만 적용됨",
        "fix": "Key Vault 키를 등록(az sql server key create) 후 az sql server tde-key set --server-key-type AzureKeyVault 로 CMK 전환. Key Vault는 Soft-delete·Purge Protection 필수",
        "bad_example": "{ \"serverKeyType\": \"ServiceManaged\" }",
        "good_example": "{ \"serverKeyType\": \"AzureKeyVault\", \"uri\": \"https://<kv>.vault.azure.net/keys/<key>/<ver>\" }",
        "why": "데이터는 암호화되지만 암호화 키를 클라우드 제공자가 관리합니다. 금융·공공 등 규제 환경에서는 조직이 키를 "
               "직접 통제(생성·회수)하도록 요구하는 경우가 많아, 이 상태는 규정 미준수가 될 수 있습니다.",
        "how_to_fix": "1) Key Vault에 키를 만들고 SQL 서버에 등록합니다(az sql server key create).\n"
                      "2) az sql server tde-key set --server-key-type AzureKeyVault 로 CMK로 전환합니다.\n"
                      "3) 해당 Key Vault는 Soft-delete·Purge Protection을 반드시 켭니다.",
        "steps": "[포털] Azure Portal → 'SQL 서버' → 해당 서버 → 보안 '투명한 데이터 암호화' → "
                 "'고객 관리형 키' 선택 → Key Vault와 키 지정 → 저장.\n"
                 "[CLI]\n"
                 "  az sql server key create -g <RG> -s <서버> -k <KeyVault키URL>\n"
                 "  az sql server tde-key set -g <RG> -s <서버> --server-key-type AzureKeyVault -k <KeyVault키URL>",
    },
    {
        "key": "sql_public_access",
        "control_code": "2.6.1",
        "title": "SQL 퍼블릭 네트워크 접근 허용",
        "cmd": "az sql server show -g <RG> -n <SERVER> --query \"{publicNetworkAccess:publicNetworkAccess}\"\naz sql server firewall-rule list -g <RG> -s <SERVER> -o table",
        "criteria": "publicNetworkAccess가 Enabled이거나, 방화벽 규칙에 0.0.0.0/0(또는 0.0.0.0~255.255.255.255) 전체 허용이 존재함",
        "fix": "az sql server update --set publicNetworkAccess=Disabled. 필요한 IP만 방화벽 규칙으로 최소 허용하고, AllowAllWindowsAzureIps(0.0.0.0) 규칙은 제거",
        "bad_example": "{ \"publicNetworkAccess\": \"Enabled\" }  또는  방화벽 규칙 { \"startIpAddress\": \"0.0.0.0\", \"endIpAddress\": \"255.255.255.255\" }",
        "good_example": "{ \"publicNetworkAccess\": \"Disabled\" }  (Private Endpoint로만 접근)",
        "why": "데이터베이스가 인터넷에서 직접 접근 가능합니다. 특히 방화벽이 0.0.0.0(전체 허용)이면 사실상 누구나 "
               "접속 시도를 할 수 있어, 무차별 대입·SQL Injection의 표적이 됩니다.",
        "how_to_fix": "1) az sql server update --set publicNetworkAccess=Disabled 로 퍼블릭 접근을 끕니다.\n"
                      "2) 0.0.0.0 전체 허용 방화벽 규칙(AllowAllAzureIps 등)을 삭제합니다.\n"
                      "3) 접근이 필요한 특정 IP만 방화벽에 최소로 등록하거나 Private Endpoint를 사용합니다.",
    },
    {
        "key": "sql_no_private_endpoint",
        "control_code": "2.6.1",
        "title": "SQL Private Endpoint 미구성",
        "cmd": "az network private-endpoint list -g <RG> --query \"[?contains(privateLinkServiceConnections[0].privateLinkServiceId,'Sql')]\" -o table\naz sql server show -g <RG> -n <SERVER> --query \"privateEndpointConnections\"",
        "criteria": "SQL 서버에 Private Endpoint 연결이 없어 퍼블릭 경로로만 접근 가능(퍼블릭 접근 허용과 결합 시 위험 가중)",
        "fix": "az network private-endpoint create 로 SQL용 Private Endpoint를 구성하고 Private DNS Zone(privatelink.database.windows.net) 연결. 이후 publicNetworkAccess=Disabled",
        "bad_example": "{ \"privateEndpointConnections\": [] }",
        "good_example": "{ \"privateEndpointConnections\": [ { \"properties\": { \"privateLinkServiceConnectionState\": { \"status\": \"Approved\" } } } ] }",
        "why": "SQL 서버가 사설 연결(Private Endpoint) 없이 퍼블릭 경로로만 접근됩니다. 퍼블릭 접근 허용과 겹치면 "
               "인터넷 노출 위험이 더 커집니다.",
        "how_to_fix": "1) az network private-endpoint create 로 SQL용 Private Endpoint를 만듭니다.\n"
                      "2) Private DNS Zone(privatelink.database.windows.net)을 연결합니다.\n"
                      "3) 이후 publicNetworkAccess=Disabled 로 퍼블릭 경로를 닫습니다.",
        "steps": "[포털] Azure Portal → 'SQL 서버' → 해당 서버 → 보안 '네트워킹' → '프라이빗 액세스' 탭 "
                 "→ '+ 프라이빗 엔드포인트 만들기' → VNet/서브넷 선택 → 프라이빗 DNS 통합 '예' → 만들기.\n"
                 "[CLI]\n"
                 "  az network private-endpoint create -g <RG> -n <PE이름> --vnet-name <VNet> --subnet <서브넷> "
                 "--private-connection-resource-id <SQL서버ID> --group-id sqlServer --connection-name sqlconn",
    },
    {
        "key": "sql_auditing_disabled",
        "control_code": "2.9.4",
        "title": "SQL 감사(Auditing) 비활성화",
        "cmd": "az sql server audit-policy show -g <RG> -n <SERVER> --query \"{state:state, retentionDays:retentionDays}\"",
        "criteria": "서버/DB 감사(Auditing) state가 Disabled이거나 로그 보존일(retentionDays)이 법정 기준 미달",
        "fix": "az sql server audit-policy update --state Enabled --bsts Enabled 등으로 Log Analytics·Storage로 감사 로그를 보내고, 보존기간을 조직 기준(예: 90일 이상)으로 설정",
        "bad_example": "{ \"state\": \"Disabled\", \"retentionDays\": 0 }",
        "good_example": "{ \"state\": \"Enabled\", \"retentionDays\": 90, \"isAzureMonitorTargetEnabled\": true }",
        "why": "데이터베이스 접근·변경 기록(감사 로그)이 남지 않습니다. 정보 유출·부정 접근이 있어도 누가 무엇을 했는지 "
               "추적할 수 없어, 사고 대응과 법적 증빙이 불가능합니다.",
        "how_to_fix": "1) az sql server audit-policy update --state Enabled 로 감사를 켭니다.\n"
                      "2) 로그를 Log Analytics 또는 Storage로 보냅니다.\n"
                      "3) 보존기간을 조직 기준(예: 90일 이상)으로 설정합니다.",
    },
    {
        "key": "sql_defender_disabled",
        "control_code": "2.11.3",
        "title": "Microsoft Defender for SQL 비활성화",
        "cmd": "az sql server advanced-threat-protection-setting show -g <RG> -n <SERVER> --query \"{state:state}\"\naz security pricing show -n SqlServers --query \"{tier:pricingTier}\"",
        "criteria": "Defender for SQL(고급 위협 방지) state가 Disabled이거나 Defender 요금제가 Free로, 이상행위·SQL Injection 탐지가 동작하지 않음",
        "fix": "az sql server advanced-threat-protection-setting update --state Enabled, 또는 az security pricing create -n SqlServers --tier Standard 로 Defender for SQL 활성화",
        "bad_example": "{ \"state\": \"Disabled\" }  /  Defender pricingTier: \"Free\"",
        "good_example": "{ \"state\": \"Enabled\" }  /  Defender pricingTier: \"Standard\"",
        "why": "SQL에 대한 지능형 위협 탐지가 꺼져 있습니다. SQL Injection·비정상 접근 같은 공격이 실시간으로 "
               "탐지·경고되지 않아, 침해가 발생해도 인지하지 못할 수 있습니다.",
        "how_to_fix": "1) az sql server advanced-threat-protection-setting update --state Enabled 로 켭니다.\n"
                      "2) 또는 az security pricing create -n SqlServers --tier Standard 로 Defender for SQL을 활성화합니다.\n"
                      "3) 경고 수신 이메일을 설정합니다.",
    },
    {
        "key": "sql_va_disabled",
        "control_code": "2.11.2",
        "title": "SQL 취약성 평가(Vulnerability Assessment) 미구성",
        "cmd": "az sql server vulnerability-assessment show -g <RG> -n <SERVER> --query \"{storageContainerPath:storageContainerPath, recurringScans:recurringScans}\"",
        "criteria": "취약성 평가(VA)가 구성되지 않았거나 정기 스캔(recurringScans.isEnabled)이 꺼져 있어 취약점이 주기적으로 점검되지 않음",
        "fix": "az sql server vulnerability-assessment update 로 저장소 연결 + 정기 스캔(recurringScans) 활성화 + 결과 이메일 수신 설정. Defender for SQL과 함께 사용",
        "bad_example": "{ \"recurringScans\": { \"isEnabled\": false } }",
        "good_example": "{ \"storageContainerPath\": \"https://<sa>.blob.core.windows.net/vulnerability-assessment\", \"recurringScans\": { \"isEnabled\": true, \"emailSubscriptionAdmins\": true } }",
        "why": "데이터베이스의 보안 취약점을 주기적으로 점검하지 않습니다. 설정 오류·권한 과다 같은 약점이 방치되어 "
               "침해 통로로 이어질 수 있습니다.",
        "how_to_fix": "1) az sql server vulnerability-assessment update 로 결과 저장소를 연결합니다.\n"
                      "2) 정기 스캔(recurringScans)을 켜고 결과 이메일 수신을 설정합니다.\n"
                      "3) Defender for SQL과 함께 사용해 탐지 범위를 넓힙니다.",
        "steps": "[포털] Azure Portal → 'SQL 서버' → 보안 'Microsoft Defender for Cloud' → "
                 "'취약성 평가 설정 구성' → 저장소 계정 지정 → '정기 반복 검사' 켜기 → 결과 수신 이메일 입력 → 저장.\n"
                 "[CLI]\n"
                 "  az sql server vulnerability-assessment update -g <RG> -n <서버> "
                 "--storage-container-path https://<저장소>.blob.core.windows.net/vulnerability-assessment "
                 "--recurring-scans Enabled --email-subscription-admins true",
    },
    {
        "key": "sql_ltr_not_configured",
        "control_code": "2.12.1",
        "title": "SQL 장기 보존 백업(LTR) 미구성",
        "cmd": "az sql db ltr-policy show -g <RG> -s <SERVER> -n <DB> --query \"{weekly:weeklyRetention, monthly:monthlyRetention, yearly:yearlyRetention}\"",
        "criteria": "장기 보존(LTR: Long-Term Retention) 정책이 없어(주/월/년 보존값 PT0S 등) 규제상 요구되는 장기 백업 보존이 되지 않음",
        "fix": "az sql db ltr-policy set --weekly-retention P4W --monthly-retention P12M --yearly-retention P7Y --week-of-year 1 등으로 조직/규제 기준에 맞춰 LTR 설정",
        "bad_example": "{ \"weeklyRetention\": \"PT0S\", \"monthlyRetention\": \"PT0S\", \"yearlyRetention\": \"PT0S\" }",
        "good_example": "{ \"weeklyRetention\": \"P4W\", \"monthlyRetention\": \"P12M\", \"yearlyRetention\": \"P7Y\" }",
        "why": "장기 보존 백업이 없어, 오래된 시점으로 복구할 수 없습니다. 규제상 수년간 백업 보존이 요구되거나, "
               "뒤늦게 발견된 데이터 훼손을 되돌려야 할 때 대응이 불가능합니다.",
        "how_to_fix": "1) az sql db ltr-policy set 로 주/월/년 보존 정책을 설정합니다.\n"
                      "2) 조직·규제 기준에 맞춰 보존기간을 정합니다(예: 주 4주·월 12개월·년 7년).\n"
                      "3) 주기적으로 복원 테스트를 수행합니다.",
        "steps": "[포털] Azure Portal → 'SQL 서버' → 데이터 관리 '백업' → '보존 정책 구성' → 대상 DB 선택 "
                 "→ 주/월/년 장기 보존(LTR) 값 설정 → 적용.\n"
                 "[CLI]\n"
                 "  az sql db ltr-policy set -g <RG> -s <서버> -n <DB> "
                 "--weekly-retention P4W --monthly-retention P12M --yearly-retention P7Y --week-of-year 1",
    },
]


def sql_checks() -> list[dict]:
    return list(SQL_CHECKS)


def sql_check(key: str) -> dict | None:
    for c in SQL_CHECKS:
        if c["key"] == key:
            return c
    return None
