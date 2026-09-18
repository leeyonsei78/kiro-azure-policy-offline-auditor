# 자동 점검 에이전트 Azure 배포 가이드 (Azure Functions)

`autoauditor`를 **Azure Functions(Timer Trigger)** 로 배포해, 주기적으로 자동 점검 →
심각/침해 시 **Slack 알림**을 받습니다. AWS(Lambda/SAM)와 대응되는 Azure 버전입니다.

> Azure Functions 런타임에는 `az` CLI가 없지만, **Azure SDK**(azure-mgmt-*)로 실제
> 구독 데이터를 수집합니다(`collector_azure_sdk`). SDK는 `requirements.txt`에 선언되어
> 배포 시 자동 설치되고, **Function App의 관리 ID(Managed Identity) + Reader 역할**로 인증합니다.

## 0. 사전 준비

- **Azure CLI** 설치 → `az login` (그리고 `az account set --subscription <구독ID>`)
- **Azure Functions Core Tools(`func`)** 설치
- **Slack Incoming Webhook URL** (기존 워크스페이스·채널 것 그대로)

## 1. 배포 (한 줄)

`deploy-azure` 폴더에서 실행합니다. Webhook URL만 본인 것으로 바꾸세요.

**Windows**
```bat
cd C:\kiro-azure-policy-offline-auditor\deploy-azure
deploy.bat "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

**Linux/mac**
```bash
cd deploy-azure
./deploy.sh "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

스크립트가 자동으로: 리소스 그룹 → 스토리지 → Function App(Python 3.11) → **관리 ID + Reader/Security Reader 역할** → 앱 설정(Slack 등) → 코드 게시 순으로 만듭니다.

- 인자(선택): `deploy.sh <웹훅> [리소스그룹] [지역] [앱이름]` (기본 지역 `koreacentral`)

## 2. 즉시 실행해 Slack 확인

- Azure Portal → 해당 Function App → **함수 → AutoAudit → 코드+테스트 → 테스트/실행**
- 또는 스케줄(기본 **매시간**)을 기다립니다. 스케줄은 `AutoAudit/function.json`의 CRON으로 조정
  - 예: `"0 0 * * * *"`(매시간), `"0 0 */6 * * *"`(6시간마다)

## 3. 옵션 (앱 설정으로 조정)

Portal → Function App → **구성(Configuration)** 또는 `az functionapp config appsettings set` 로 변경:

| 앱 설정 | 설명 | 기본 |
|---------|------|------|
| `AUTOAUDITOR_SLACK_WEBHOOK` | Slack Webhook URL | (배포 시 주입) |
| `AUTOAUDITOR_ALERT_MIN_SEVERITY` | 알림 최소 심각도 | HIGH |
| `AUTOAUDITOR_REMEDIATION` | off / suggest(반자동) / auto | suggest |
| `AUTOAUDITOR_DRY_RUN` | true면 auto라도 실제 변경 안 함 | true |
| `AUTOAUDITOR_PROTECT_TAGS` | 차단 금지(화이트리스트) 키워드 | (없음) |
| `AZURE_SUBSCRIPTION_ID` | 점검 대상 구독 | (배포 시 주입) |

## 4. 권한 (자동 부여됨)

배포 스크립트가 Function App의 **관리 ID에 구독 Reader + Security Reader** 역할을 부여합니다.
자동 차단(`auto`)을 실제로 쓰려면 대상 리소스 **기여자(수정) 권한**을 추가하고,
반드시 `DryRun=false` + 화이트리스트(`ProtectTags`)를 함께 설정하세요(안전).

## 5. 로그 확인 · 삭제

- 로그: Portal → Function App → **모니터링/로그 스트림** (또는 Application Insights)
- 삭제(원복): `az group delete -n rg-cloudsec-autoaudit --yes`

## 자주 겪는 문제

- **Slack이 안 옴**: (1) Webhook URL 정확한지, (2) 이번 주기에 HIGH↑ 이슈/침해가 있었는지, (3) 함수를 수동 실행해 로그 확인.
- **수집이 비어 있음**: 관리 ID에 Reader 역할이 부여됐는지, `AZURE_SUBSCRIPTION_ID`가 맞는지 확인(역할 전파에 몇 분 걸릴 수 있음).
- **publish 실패**: `func` Core Tools 버전(v4), Python 3.11 로컬 설치 여부 확인.
