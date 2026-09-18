# 자동 점검 에이전트 AWS 배포 가이드 (SAM)

`autoauditor`를 AWS Lambda + EventBridge로 배포해, **주기적으로 자동 점검 → Slack 알림**을 받습니다.
기존 `kiro-aws-security-agent` 배포와 동일한 SAM 흐름입니다.

> Lambda 런타임에는 `aws` CLI가 없지만 **boto3(AWS SDK)는 기본 포함**되어 있어,
> `collector_boto3`가 실제 계정 데이터를 수집합니다. 추가 패키지 설치가 필요 없습니다.

## 0. 사전 준비

- **AWS SAM CLI** 설치 ([설치 가이드](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html))
- **AWS 자격증명** 구성: `aws configure` (배포 권한: CloudFormation/Lambda/IAM/S3/Events)
- **Slack Incoming Webhook URL** (기존 워크스페이스·채널 것 그대로 사용)

## 1. 배포 (한 줄)

프로젝트를 받은 폴더에서 `deploy` 폴더로 이동 후 실행합니다.

**Windows**
```bat
cd C:\kiro-azure-policy-offline-auditor\deploy
deploy.bat "https://hooks.slack.com/services/XXX/YYY/ZZZ" "rate(1 hour)"
```

**Linux/mac**
```bash
cd deploy
./deploy.sh "https://hooks.slack.com/services/XXX/YYY/ZZZ" "rate(1 hour)"
```

- 1번째 인자: **Slack Webhook URL** (기존 것)
- 2번째 인자(선택): 실행 주기 (기본 `rate(1 hour)` = 매시간). 예: `rate(6 hours)`, `cron(0 9 * * ? *)`

## 2. 바로 한 번 실행해서 Slack 확인

스케줄을 기다리지 않고 즉시 테스트:
```bash
aws lambda invoke --function-name cloud-sec-auto-auditor out.json
cat out.json
```
→ 심각/침해가 있으면 **Slack 채널에 요약 메시지**가 도착합니다.

## 3. 옵션 조정 (재배포 없이 또는 재배포로)

배포 시 `--parameter-overrides`로 조정합니다 (deploy 스크립트를 수정하거나 직접 `sam deploy`):

| 파라미터 | 설명 | 기본 |
|----------|------|------|
| `SlackWebhook` | Slack Webhook URL | (필수) |
| `AlertMinSeverity` | 알림 최소 심각도 (CRITICAL/HIGH/MEDIUM/LOW) | HIGH |
| `Remediation` | off / suggest(반자동) / auto | suggest |
| `DryRun` | true면 auto라도 실제 변경 안 함 | true |
| `ProtectTags` | 차단 금지(화이트리스트) 키워드, 쉼표구분 | (없음) |
| `Schedule` | EventBridge 스케줄 식 | rate(1 hour) |

예) 6시간마다, 위험 이슈 차단 금지 리소스 지정:
```bash
sam deploy --parameter-overrides \
  SlackWebhook="https://hooks.slack.com/services/..." \
  Schedule="rate(6 hours)" \
  ProtectTags="prod-critical,dns"
```

## 4. IAM 권한 (자동 부여됨)

템플릿이 Lambda에 **읽기 전용 권한**(`SecurityAudit`, `ViewOnlyAccess`)을 부여합니다.
자동 차단(`Remediation=auto`)을 실제로 쓰려면 해당 리소스 **수정 권한**을 추가해야 하며,
반드시 `DryRun=false` + 화이트리스트(`ProtectTags`)를 함께 설정하세요(안전).

## 5. 로그 확인

```bash
sam logs --name cloud-sec-auto-auditor --tail
# 또는 CloudWatch Logs 콘솔에서 /aws/lambda/cloud-sec-auto-auditor
```

## 6. 삭제(원복)

```bash
sam delete --stack-name cloud-sec-auto-auditor
```

## 자주 겪는 문제

- **`sam build`가 cp949 오류**: 템플릿/설정에 한글 주석이 있으면 Windows에서 발생 → 이 저장소의 배포 파일은 영문 주석만 사용합니다.
- **`CreateChangeSet` 권한 오류**: 배포 계정에 CloudFormation 권한이 없을 때 → 배포용 정책(AdministratorAccess 또는 CloudFormation/Lambda/IAM/S3/Events FullAccess) 추가.
- **Slack이 안 옴**: (1) Webhook URL 정확한지, (2) 이번 주기에 HIGH 이상 이슈/침해가 있었는지(`AlertMinSeverity` 미만이면 전송 안 함), (3) `aws lambda invoke`로 즉시 테스트해 로그 확인.
- **수집이 비어 있음**: Lambda 역할에 읽기 권한(`SecurityAudit`)이 붙었는지 확인. 리전(`region`)이 점검 대상과 같은지 확인(samconfig.toml).
