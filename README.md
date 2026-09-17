# 클라우드 정책 오프라인 보안검토 (AWS/Azure) — azure-policy-offline-auditor

> **폐쇄망(오프라인) 전용.** AWS(`aws ...`)·Azure(`az ...`) CLI로 추출한 정책·구성 텍스트를 업로드하면,
> 인터넷·AI·클라우드 연결 없이 **ISMS-P 클라우드 인프라 통제항목** 기준으로 보안 이슈를 찾고
> 개선 방안을 제안합니다. **AWS/Azure는 자동으로 구별**되어 표시됩니다.

## 특징

- 🔒 **완전 오프라인**: Python 표준 라이브러리만 사용. 외부 패키지·인터넷·AI API·CDN이 전혀 필요 없습니다.
- ☁️ **AWS + Azure 지원**: 입력을 자동 감지해 플랫폼별(AWS/Azure) 판단기준·개선안·재점검 CLI를 적용하고, 결과에 플랫폼 뱃지·필터를 제공합니다.
- 📋 **ISMS-P 기준**: 클라우드 인프라 직결 7개 영역·**17개 통제항목**의 판단기준/개선방안을 플랫폼별로 내장.
- 🗄️ **Azure SQL 심층 점검(8항목)**: TDE·CMK·Public Access·Private Endpoint·Auditing·Defender for SQL·취약성 평가(VA)·장기보존(LTR)을 명령어와 함께 점검.
- 🐞 **CVE 탐지**: 입력 텍스트의 `CVE-YYYY-NNNN` 식별자를 자동 인식해 취약점(2.11.2)으로 보고(건수에 따라 심각도 상향).
- 🔴🟢 **위반 예시 / 개선 예시**: 각 이슈에 "이렇게 되면 위반 / 이렇게 고치면 정상" 설정 예시를 함께 제시.
- 🧩 **관대한 입력**: `aws ... `/`az ... ` 의 `-o json` 출력이 가장 정확하지만, 여러 명령 출력을 한 파일에 이어붙이거나 표/텍스트가 섞여도 최대한 분석합니다.
- 🖥️ **웹 UI + CLI**: 브라우저에서 붙여넣기/업로드하거나, 명령줄에서 파일/파이프로 검토.
- 🔎 **결과**: 점수·등급, 플랫폼(AWS/Azure)·이슈별 심각도, 매핑된 ISMS-P 통제항목, **구체적 개선 제안**, 재점검용 CLI.
- 🎯 **위험 기반 우선순위**: 인터넷 노출·민감데이터·인증 약화 등을 가중해 **위험 점수**를 산정하고 "먼저 조치할 TOP 5"를 제시.
- 🚨 **복합 위험(공격 경로) 분석**: 개별로는 중간이어도 조합되면 침해로 이어지는 취약점(예: 관리포트 개방 + MFA 없는 계정)을 묶어 경고.
- 🔐 **개인정보·시크릿 노출 탐지**: 입력에서 주민번호·카드번호·이메일 등 개인정보와 하드코딩된 키·비밀번호·토큰을 탐지(근거는 마스킹 표시).
- 💾 **엑셀(.xlsx)/CSV/PDF 저장**: 결과를 진짜 엑셀 파일로 저장(줄바꿈·특수문자 보존, CSV 손실 없음) 또는 CSV·PDF(인쇄)로 내보내기. 모두 표준 라이브러리만 사용해 폐쇄망에서 동작.

## 왜 오프라인인가

폐쇄망에서는 클라우드/AI에 직접 연결할 수 없습니다. 그래서 이 도구는 판정 로직(정규식·구조 분석)과
ISMS-P 지식 베이스를 **코드에 내장**해, 망분리 환경의 검토 PC에서 그대로 실행되도록 만들었습니다.
입력 텍스트는 **메모리에서만 처리**되고 어디에도 저장/전송하지 않습니다.

## 요구사항

- Python 3.8 이상 (표준 라이브러리만 사용 — pip install 불필요)
- **Python이 없는 폐쇄망 PC**라면 아래 "설치 — Python이 없는 폐쇄망" 절차로 Python 없이도 실행할 수 있습니다.

## 설치 — Python이 없는 폐쇄망 (설치 불필요 방식, 권장)

폐쇄망 PC에 Python을 설치할 수 없을 때 사용합니다. **인터넷 되는 PC에서 준비 → 폴더째 복사**만 하면 됩니다.

1. **인터넷 되는 Windows PC**에서 이 폴더의 **`setup-python.bat` 을 더블클릭**
   - Windows용 임베디드 Python(설치 불필요 버전, 약 10MB)을 자동으로 내려받아 `python\` 폴더에 넣습니다.
   - (사내 프록시로 다운로드가 막히면, 스크립트가 안내하는 URL을 브라우저로 받아 폴더에 두고 다시 실행)
2. **이 폴더 전체**(이제 `python\` 포함)를 USB 등으로 **폐쇄망 PC에 복사**
3. 폐쇄망 PC에서 **`run.bat` 더블클릭** → 끝 (동봉된 Python을 자동으로 사용)

> `run.bat` 은 ① 폴더 안 `python\python.exe` → ② 시스템 `py`/`python` 순으로 자동 탐지합니다.
> 그래서 임베디드 Python을 넣어두면 폐쇄망 PC에 아무 설치 없이 바로 실행됩니다.

## 설치 — Python이 이미 있는 경우

1. 이 폴더를 검토 PC로 복사 (USB·내부망 파일서버 등)
2. Python 3.8+ 확인: `python --version`
3. `run.bat`(Windows) 더블클릭 또는 `./run.sh`(mac/Linux). 끝. (pip install 불필요)

## 사용법 1 — 웹 UI (권장)

### Windows: `run.bat` 더블클릭 (가장 쉬움)

1. 이 폴더를 예: `C:\kiro-azure-policy-offline-auditor` 에 둡니다.
2. **`run.bat` 을 더블클릭**합니다.
3. 검은 콘솔 창이 뜨고, 3초 뒤 기본 브라우저가 자동으로 `http://127.0.0.1:8080` 을 엽니다.
4. Azure 정책 텍스트를 **붙여넣기**하거나 **파일 불러오기** → **보안검토 실행**.
5. 종료: 콘솔 창에서 `Ctrl+C` 를 누르거나 창을 닫습니다.

> Python이 없다면 https://www.python.org/downloads/ 에서 3.8 이상을 설치하세요.
> 설치 시 **"Add Python to PATH"** 를 반드시 체크해야 `run.bat` 이 Python을 찾습니다.

### macOS / Linux: `run.sh`

```bash
./run.sh
```

### 직접 명령으로 실행 (run.bat 이 안 될 때)

`run.bat` 이 안 되거나 창이 바로 닫히면, 명령 프롬프트(cmd)에서 아래로 직접 실행하세요.
자세한 단계·문제해결은 **[수동실행_명령어.md](수동실행_명령어.md)** 참고.

```bash
python\python.exe -m auditor --web          # 동봉 Python 사용 (Windows 폐쇄망)
# 또는 Python이 설치된 경우:
python -m auditor --web                      # http://127.0.0.1:8080
```

브라우저에서 `http://127.0.0.1:8080` 접속 → Azure 정책 텍스트를 **붙여넣기**하거나 **파일 불러오기** → **보안검토 실행**.
결과에 점수·등급, 통제항목별 이슈, 개선 제안이 표시됩니다.

검토 결과 아래의 버튼으로 리포트를 저장할 수 있습니다:
- **⬇️ 엑셀(.xlsx) 저장 (권장)** — 진짜 엑셀 파일로 내려받아 Excel에서 바로 열기. 줄바꿈·쉼표·따옴표가 든 명령어·예시 값도 **셀 분리 없이 그대로 보존**됩니다(CSV의 데이터 손실 문제 없음). 요약/상세 2개 시트.
- **CSV 저장** — 가벼운 텍스트 형식(호환용). 셀 안에 특수문자가 많으면 엑셀에서 열 분리가 어긋날 수 있어, 정확한 표는 **엑셀(.xlsx) 저장**을 권장합니다.
- **🖨️ PDF로 저장 (인쇄)** — 새 창에 리포트가 열리며, 인쇄 대화상자에서 "대상 → PDF로 저장"을 선택하면 PDF가 됩니다(별도 프로그램 불필요)

> 엑셀 저장은 외부 라이브러리 없이 Python 표준 라이브러리만으로 `.xlsx`를 생성하므로 폐쇄망에서도 그대로 동작합니다.

> 8080 포트가 이미 사용 중이면 `--port 8090` 처럼 다른 포트를 지정하세요.
> PDF 저장 시 팝업 차단이 뜨면 허용해 주세요.

### 📋 수집 명령어 가이드 탭

상단 **"📋 수집 명령어 가이드"** 탭에서는 각 클라우드에서 **보안 취약 여부를 확인할 정보를 뽑는 CLI 명령**을 통제항목별로 정리해 보여줍니다.

- **플랫폼 토글**(AWS / Azure)로 전환
- 통제항목별 카드에 점검 목적 + **재점검 CLI 명령**(명령마다 **복사 버튼**) + ⚠️ 확인 포인트(문제 판단 기준)
- **검색창**으로 코드·영역·명령어(예: `2.6.1`, `보안그룹`, `s3`, `nsg`)로 필터

관리망에서 이 명령들로 정책·구성을 내보내(`-o json`) txt로 저장한 뒤, '보안검토' 탭에 업로드하는 흐름입니다.

### 📥 일괄 수집 스크립트 (장비/서비스별 자동 수집)

명령을 하나씩 실행하기 번거로우면, **모든 점검 명령을 한 번에 실행하는 스크립트**를 내려받을 수 있습니다.

- 수집 명령어 가이드 탭의 **"Bash(.sh) / PowerShell(.ps1) 다운로드"** 버튼, 또는 CLI `--script`
- 스크립트는 **장비/서비스별 섹션**(네트워크, IAM, Storage, Key Vault, SQL Database, Defender, 백업 등)으로 구분되어 있고, 각 섹션 상단에 장비 설명이 들어 있습니다.
- 각 명령의 결과가 `out/` 폴더에 **서비스별 JSON**으로 저장됩니다.

**사용 절차 (스크립트 맨 위 주석에도 동일하게 안내됨):**

1. **관리망 PC**에서 클라우드 CLI 로그인
   - Azure: `az login`  /  AWS: `aws configure` (또는 `aws sso login`) — **읽기 권한** 계정 권장
2. 스크립트의 자리표시자(`<RG>`, `<SERVER>`, `<DB>`, `<NSG>`, `<BUCKET>` 등)를 **실제 값으로 치환**
3. 실행
   - Bash: `chmod +x collect-azure.sh && ./collect-azure.sh`
   - PowerShell: `Set-ExecutionPolicy -Scope Process Bypass -Force; .\collect-azure.ps1`
4. 결과 `out/` 폴더를 압축
   - Bash: `zip -r out.zip out`  /  PowerShell: `Compress-Archive -Path .\out\* -DestinationPath out.zip -Force`
5. `out/` 폴더의 **JSON 내용을 '보안검토' 탭에 업로드**(여러 파일을 이어붙여 붙여넣거나 파일 불러오기)

> 자리표시자를 못 채운 명령은 스크립트가 자동으로 건너뛰고(`.err` 파일로 기록) 나머지는 계속 수집합니다.

## 사용법 2 — 명령줄(CLI)

```bash
# 파일 검토 → 텍스트 리포트
python -m auditor policy.txt

# JSON 리포트(자동화 연동용)
python -m auditor policy.txt --json

# 엑셀(.xlsx)로 저장 (권장 — 데이터 손실 없음)
python -m auditor policy.txt --xlsx --out report.xlsx

# CSV로 저장(호환용)
python -m auditor policy.txt --csv --out result.csv

# HTML로 저장(브라우저로 열어 인쇄 → PDF로 저장)
python -m auditor policy.txt --html --out report.html

# 파이프 입력
az network nsg rule list --nsg-name NSG -g RG -o json | python -m auditor

# ISMS-P 통제항목 목록만 보기
python -m auditor --controls

# 정보 수집 CLI 명령어 가이드 (기본 AWS+Azure 모두)
python -m auditor --commands

# 특정 플랫폼만
python -m auditor --commands --platform aws
python -m auditor --commands --platform azure

# 일괄 수집 스크립트 생성(장비/서비스별)
python -m auditor --script --platform azure --out collect-azure.sh
python -m auditor --script --platform azure --shell ps1 --out collect-azure.ps1
python -m auditor --script --platform aws --out collect-aws.sh
```

> `--out`(또는 `-o`) 없이 `--csv`/`--html` 만 쓰면 화면에 출력됩니다.
> `--csv` 결과는 UTF-8 BOM이 포함되어 Excel에서 한글이 깨지지 않습니다.

종료 코드: `0`=이슈 없음, `1`=이슈 발견(파이프라인 게이트로 활용), `2`=실행 오류

## 입력 준비 (Azure 쪽에서 먼저 추출)

인터넷망 또는 관리망에서 `aws`/`az` CLI로 정책을 뽑아 **txt로 저장**한 뒤, 폐쇄망 검토 PC로 옮깁니다.
아래는 대표 예시입니다 (`-o json`/`--output json` 권장). 플랫폼은 입력 내용으로 자동 감지됩니다.

**Azure:**
```bash
az network nsg rule list --nsg-name <NSG> -g <RG> -o json           > azure.txt
az storage account list -o json                                      >> azure.txt
az keyvault list -o json                                             >> azure.txt
az role assignment list --all -o json                                >> azure.txt
az sql db list -g <RG> -s <SERVER> -o json                           >> azure.txt
```

**AWS:**
```bash
aws ec2 describe-security-groups --output json                       > aws.txt
aws s3api get-public-access-block --bucket <BUCKET> --output json     >> aws.txt
aws iam list-policies --scope Local --output json                     >> aws.txt
aws iam get-account-authorization-details --output json              >> aws.txt
aws cloudtrail describe-trails --output json                          >> aws.txt
```

여러 명령 출력을 한 파일에 이어붙여도 되고, AWS/Azure를 섞어 넣어도 각각 구별해 분석합니다.
`samples/` 폴더의 예시 파일(Azure: `nsg-rules.json`, `azure-sql.json` 등, AWS: `aws-security-groups.json`, `aws-s3-iam.json`)을 참고하세요.

## 점검하는 ISMS-P 통제항목 (17개)

| 영역 | 항목 | 점검 내용(요약) |
|------|------|------------------|
| 인증·권한관리 | 2.5.1 / 2.5.3 / 2.5.4 / 2.5.5 / 2.5.6 | 휴면계정, MFA·Conditional Access, 비밀번호 정책, 과다권한(Owner/전역관리자), 자격증명 검토 |
| 접근통제 | 2.6.1 / 2.6.6 / 2.6.7 | NSG 인바운드 전체공개·민감포트, 원격접속 통제, 아웃바운드 통제 |
| 암호화 | 2.7.1 / 2.7.2 | 저장·전송 암호화(HTTPS·TLS·TDE), Key Vault 키 관리(Soft-delete·Purge Protection) |
| 운영관리 | 2.9.4 / 2.9.5 | 진단·활동 로그 수집·보존, 로그 위변조 방지 |
| 보안관리 | 2.10.2 / 2.10.8 | 관리그룹·Azure Policy·Secure Score, 패치 관리 |
| 사고대응 | 2.11.2 / 2.11.3 | 취약점 평가(Unhealthy), Defender 경고·이상탐지 |
| 재해복구 | 2.12.1 | 백업 상태(Failed)·이중화(GRS/LRS) |

## Azure SQL 심층 점검 (8항목)

수집 명령어 가이드 탭(Azure) 및 검토 결과에서 함께 다루며, 각 항목에 **점검 명령 + 위반 예시 + 개선 예시**를 제공합니다.

| 항목 | ISMS-P | 점검 내용 |
|------|:------:|-----------|
| TDE(투명한 데이터 암호화) | 2.7.1 | `state`가 Disabled면 저장 데이터 미암호화 |
| CMK(고객관리키) | 2.7.2 | `serverKeyType`이 ServiceManaged면 플랫폼 기본 키만 사용 |
| Public Access | 2.6.1 | `publicNetworkAccess=Enabled` 또는 방화벽 0.0.0.0 전체 허용 |
| Private Endpoint | 2.6.1 | Private Endpoint 연결 없음(퍼블릭 경로만) |
| Auditing(감사) | 2.9.4 | 감사 `state`가 Disabled·보존일 미달 |
| Defender for SQL | 2.11.3 | 고급 위협 방지 Disabled(이상행위·SQLi 미탐지) |
| 취약성 평가(VA) | 2.11.2 | `recurringScans.isEnabled=false`(정기 스캔 미구성) |
| 장기보존(LTR) | 2.12.1 | 주/월/년 보존값이 모두 PT0S(장기 백업 미보존) |

자동 검출은 입력에 포함된 리소스에 한합니다. 텍스트만 있는 항목(진단·백업·패치 등)은 키워드로 보완 탐지합니다.

## CIS Benchmark 기반 위반·취약점 점검 (확장)

실무에서 가장 자주 지적되는 위반을 잡아내도록 CIS AWS/Azure Foundations Benchmark를 참고해
수집 명령어와 자동 탐지 로직을 보강했습니다.

**AWS**

| 점검 대상 | ISMS-P | 탐지 내용 |
|------|:------:|-----------|
| 보안그룹 SSH/RDP 개방 | 2.6.1 | 0.0.0.0/0에서 22·3389 포트 인바운드 허용 |
| RDS 퍼블릭 접근 | 2.6.1 | `PubliclyAccessible=true`(DB 인터넷 노출) |
| S3 퍼블릭 노출 | 2.7.1 | Block Public Access 미설정·ACL(AllUsers)·퍼블릭 정책 |
| EBS 스냅샷 공개 | 2.7.1 | 볼륨 생성 권한이 `all`(전체 공개) |
| CloudTrail 로그 암호화·VPC Flow Logs·Config | 2.9.4/2.10.2 | KMS 미암호화 추적, Flow Logs 미구성, Config 레코더 비활성 |
| root 액세스키·시크릿 로테이션 | 2.5.6 | root 액세스키 존재, Secrets Manager 로테이션 미설정 |

**Azure**

| 점검 대상 | ISMS-P | 탐지 내용 |
|------|:------:|-----------|
| NSG SSH/RDP 개방 | 2.6.1 | 인터넷에서 22·3389 포트 인바운드 허용 |
| Storage 퍼블릭 Blob·HTTPS·TLS | 2.7.1 | `allowBlobPublicAccess=true`, HTTP 허용, TLS 1.2 미만 |
| App Service HTTPS 전용 미설정 | 2.7.1 | `httpsOnly=false`(평문 접근 허용) |
| 디스크 CMK 미적용 | 2.7.1 | 플랫폼 관리 키만 사용(규제 시 CMK 필요) |
| Defender for Cloud 플랜 | 2.11.2 | 리소스 유형별 Defender 요금제 활성화 상태 |
| 관리 ID·특권 계정 | 2.5.5 | VM 관리 ID 미사용, Owner 광범위 부여 |

> AWS·Azure 리소스가 한 입력에 섞여 있어도 각 위반을 개별적으로 탐지합니다.
>
> **모든 신규 항목에 위반 예시(✗)·개선 예시(✓)가 포함**되어, 화면·리포트에서 조치 방향을 구체적으로 확인할 수 있습니다.

### 초보 담당자를 위한 상세 설명

각 이슈 카드는 배경지식이 없어도 이해할 수 있도록 아래를 함께 제공합니다.

- **❓ 왜 문제인가요?** — 해당 설정이 왜 위험한지(공격 시나리오·피해)를 쉬운 말로 설명합니다.
- **🛠️ 해결 방법(단계별)** — 1) 2) 3) … 순서로 무엇을 해야 하는지 방향을 안내합니다.
- **📖 따라하기 (포털 클릭 순서 + 실행 명령어)** — 클라우드를 처음 다루는 담당자도 그대로 따라할 수 있도록, **어느 메뉴를 순서대로 클릭하는지([포털])** 와 **복사해서 실행할 실제 명령어([CLI])** 를 함께 제공합니다. 명령어의 `<RG>`·`<서버>` 같은 부분만 본인 환경 값으로 바꿔 넣으면 됩니다.
- **✗ 위반 예시 / ✓ 개선 예시** — "이렇게 되면 위반 / 이렇게 고치면 정상" 설정을 나란히 보여줍니다.
- **🔎 판단 근거(입력에서 감지된 내용)** — **입력에서 실제로 매칭된 텍스트 조각**을 그대로 보여줍니다. 즉 "어떤 텍스트를 근거로 이 문제를 판단했는지"가 표시되어 오탐 여부를 즉시 확인할 수 있습니다.

이 설명들은 화면뿐 아니라 **텍스트·CSV·엑셀·PDF(HTML) 리포트**에도 모두 포함됩니다.

## 프로젝트 구조

```
azure-policy-offline-auditor/
  auditor/
    __init__.py
    __main__.py          # python -m auditor 진입점
    knowledge_base.py    # ISMS-P 17개 통제항목(AWS/Azure 판단기준·개선방안) 내장
    sql_controls.py      # Azure SQL 심층 점검 8항목(명령어·위반/개선 예시)
    collector_script.py  # 장비/서비스별 일괄 수집 스크립트 생성(.sh/.ps1)
    models.py            # Finding / AuditReport / Severity
    parser.py            # 입력 txt 파싱(JSON 블록 추출 + 텍스트 폴백)
    engine.py            # 오프라인 판정 엔진(정규식·구조 분석)
    report.py            # 텍스트 리포트 포매터
    webui.py             # 로컬 웹 UI(http.server, 단일 HTML)
    cli.py               # 명령줄 인터페이스
  samples/               # 예시 입력 파일
  tests/                 # 단위 테스트 (python -m unittest)
  README.md
```

## 테스트

```bash
python -m unittest discover -s tests -v
```

## 문제 해결 — 파일 불러오기 시 글자가 깨질 때

폐쇄망에서는 파일이 여러 인코딩으로 저장됩니다. 특히 **Windows PowerShell에서 `명령 > 파일.txt`**
로 저장하면 **BOM 없는 UTF-16LE**가 되는데, 예전 버전은 브라우저에서 이를 감지하지 못해
**한글·영어가 모두 `���`로 깨져** 보였습니다.

이제 인코딩 판별을 **서버(파이썬)**가 처리합니다. 파일을 불러오면 다음을 자동 감지·복원합니다.

- UTF-8 (BOM 있음/없음)
- UTF-16 LE / BE (**BOM 없어도 감지**)
- cp949(euc-kr) — 한글 Windows 레거시

불러온 뒤 입력창 위 안내에 `인코딩: utf-16-le` 처럼 **감지된 인코딩**이 표시됩니다.
그래도 깨진다면, 원본 파일을 메모장에서 열어 **다른 이름으로 저장 → 인코딩 `UTF-8`** 로 다시 저장한 뒤
불러오세요.

> 참고: 콘솔에 보이던 `favicon.ico 404`는 검토 결과와 무관한 브라우저 자동 요청이었고, 이제 조용히 처리됩니다.

## 참고 / 출처

- 통제항목의 판단기준·개선방안은 사내 참고자료 **isms-cloud-audit-matrix**(ISMS-P 인증기준 재구성)를 기반으로 합니다.
- 판정 엔진 설계는 **ai-security-suite**의 오프라인 감사 엔진 패턴을 참고해 이 프로젝트에 맞게 새로 구현했습니다.

## 면책

본 도구는 **오프라인 규칙 기반 자동 검토** 결과를 제공하며 **참고용**입니다. 오탐/미탐이 있을 수 있고,
실제 조치 전 대상 환경과 업무 요건을 확인해야 합니다. **KISA의 공식 ISMS-P 심사 자료를 대체하지 않습니다.**
