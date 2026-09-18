# 클라우드 정책 오프라인 보안검토 (AWS/Azure) — azure-policy-offline-auditor

> **폐쇄망(오프라인) 전용.** AWS(`aws ...`)·Azure(`az ...`) CLI로 추출한 정책·구성 텍스트를 업로드하면,
> 인터넷·AI·클라우드 연결 없이 **ISMS-P 클라우드 인프라 통제항목** 기준으로 보안 이슈를 찾고
> 개선 방안을 제안합니다. **AWS/Azure는 자동으로 구별**되어 표시됩니다.

## 특징

- 🔒 **완전 오프라인**: Python 표준 라이브러리만 사용. 외부 패키지·인터넷·AI API·CDN이 전혀 필요 없습니다.
- 🤖 **수동 + 자동 2-track**: 사람이 보며 점검하는 웹 UI/CLI(수동)와, 클라우드에서 주기 실행되는 자동 점검 에이전트(`autoauditor`)를 함께 제공합니다.
- 🚨 **침해 탐지·대응**: GuardDuty/Defender 경고·로그 상관분석으로 무차별 대입·루트 사용·악성 IP를 탐지하고, **Slack 알림 + 차단/대응 명령(반자동, 안전장치 포함)**을 제공합니다.
- ☁️ **AWS + Azure 지원**: 입력을 자동 감지해 플랫폼별(AWS/Azure) 판단기준·개선안·재점검 CLI를 적용하고, 결과에 플랫폼 뱃지·필터를 제공합니다.
- 📋 **ISMS-P 기준**: 클라우드 인프라 직결 7개 영역·**17개 통제항목**의 판단기준/개선방안을 플랫폼별로 내장.
- 🗄️ **Azure SQL 심층 점검(8항목)**: TDE·CMK·Public Access·Private Endpoint·Auditing·Defender for SQL·취약성 평가(VA)·장기보존(LTR)을 명령어와 함께 점검.
- 🐞 **CVE 탐지**: 입력 텍스트의 `CVE-YYYY-NNNN` 식별자를 자동 인식해 취약점(2.11.2)으로 보고(건수에 따라 심각도 상향).
- 🔴🟢 **위반 예시 / 개선 예시**: 각 이슈에 "이렇게 되면 위반 / 이렇게 고치면 정상" 설정 예시를 함께 제시.
- 🧩 **관대한 입력**: `aws ... `/`az ... ` 의 `-o json` 출력이 가장 정확하지만, 여러 명령 출력을 한 파일에 이어붙이거나 표/텍스트가 섞여도 최대한 분석합니다.
- 🖥️ **웹 UI + CLI**: 브라우저에서 붙여넣기/업로드하거나, 명령줄에서 파일/파이프로 검토.
- 🔎 **결과**: 점수·등급, 플랫폼(AWS/Azure)·이슈별 심각도, 매핑된 ISMS-P 통제항목, **구체적 개선 제안**, 재점검용 CLI.
- 📍 **위치 표시**: 각 이슈에 **어디를 고쳐야 하는지**(Azure: 구독·리소스그룹·리전 / AWS: 계정·리전·VPC·SG)를 함께 표시해 조치 대상을 바로 특정.
- 🔀 **보기 전환**: 결과를 **통제항목별 / 위치별(리소스그룹·VPC 단위로 묶어보기) / 위험점수순** 으로 전환해 볼 수 있어, "어느 위치부터 손볼지" 계획이 쉬워집니다. 텍스트 리포트에도 '위치별 이슈 요약'이 포함됩니다.
- 📊 **발표용 통계 그래프**: 심각도 분포·플랫폼별(도넛)과 ISMS-P 영역별·위치별·MITRE 기법별(가로막대)을 **화면과 PDF 리포트**에 표시합니다. 외부 라이브러리 없이 **순수 SVG**로 그려 폐쇄망·오프라인에서 그대로 동작하고, PDF로 저장하면 발표 자료로 바로 활용할 수 있습니다.
- 🎯 **점수 게이지**: 보안 점수(0~100)를 반원형 게이지로 시각화(등급별 색상). 화면·PDF 리포트에 표시됩니다.
- 📈 **엑셀 네이티브 차트**: `.xlsx` 저장 시 '통계(차트)' 시트에 **엑셀 진짜 막대 차트**(심각도별·영역별)가 삽입되어, 엑셀에서 열면 편집 가능한 차트로 보입니다. 표준 라이브러리(zipfile)만으로 생성해 폐쇄망에서 동작합니다.
- 🎯 **위험 기반 우선순위**: 인터넷 노출·민감데이터·인증 약화 등을 가중해 **위험 점수**를 산정하고 "먼저 조치할 TOP 5"를 제시.
- 🚨 **복합 위험(공격 경로) 분석**: 개별로는 중간이어도 조합되면 침해로 이어지는 취약점(예: 관리포트 개방 + MFA 없는 계정)을 묶어 경고.
- 🔐 **개인정보·시크릿 노출 탐지**: 입력에서 주민번호·카드번호·이메일 등 개인정보와 하드코딩된 키·비밀번호·토큰을 탐지(근거는 마스킹 표시).
- 📦 **컨테이너·API·WAF 점검**: EKS/AKS API 서버 퍼블릭 노출·RBAC, API Gateway 인증 누락, WAF 미구성까지 점검.
- 🗺️ **MITRE ATT&CK 매핑**: 각 이슈를 공격 기법(예: T1190 Exploit Public-Facing Application)에 연결해 위협 관점으로 이해.
- 📈 **추세 비교**: 이전 점검 대비 **신규 발생·해결·유지** 이슈와 점수 변화를 자동 비교(브라우저에 기준 보관, 폐쇄망 동작).
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

각 명령 카드에는 **🖥️ 실행 위치 · 점검 대상 · 필요 권한**이 함께 표시됩니다.

### 🖥️ 어느 장비에서 실행하나요? (중요)

이 프로그램의 점검 명령은 모두 **클라우드 CLI(`az`/`aws`) = API 호출**입니다. 온프레미스 장비(방화벽/서버/DB)처럼 "이 명령은 방화벽에서, 저 명령은 서버에서" 나눠 실행하는 방식이 **아닙니다.**

- **관리자 PC(점검용 단말) 한 대**에서 CLI로 로그인하면, **모든 서비스(네트워크·IAM·스토리지·DB·컨테이너 등)의 구성을 원격으로 한 번에 수집**합니다.
- 방화벽·서버·DB에 **개별 접속(SSH/RDP)할 필요가 없습니다.**
- 필요한 것은 적절한 **읽기 전용 권한(Reader/ReadOnly 등)** 계정입니다. 서비스별 권장 권한은 각 명령 카드와 스크립트 섹션에 표시됩니다.
- 여러 구독/계정을 점검하려면 대상을 전환(`az account set` / `AWS_PROFILE`) 후 다시 실행하면 됩니다.

### 📥 일괄 수집 스크립트 (서비스별 자동 수집)

명령을 하나씩 실행하기 번거로우면, **모든 점검 명령을 한 번에 실행하는 스크립트**를 내려받을 수 있습니다.

- 수집 명령어 가이드 탭의 **"Bash(.sh) / PowerShell(.ps1) 다운로드"** 버튼, 또는 CLI `--script`
- **스크립트 하나로 모든 서비스 그룹**(네트워크, IAM, Storage, Key Vault, SQL Database, 컨테이너, Defender, 백업 등)을 자동 수집합니다. 관리자 PC 한 대에서 실행하면 됩니다.
- 각 섹션 상단에 **실행 위치 · 점검 대상 · 필요 권한**이 주석으로 표시됩니다.
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

## 🤖 자동 점검 에이전트 (autoauditor)

수동 도구(웹 UI/CLI)와 별개로, **클라우드에서 주기적으로 자동 점검**하는 에이전트를 함께 제공합니다.
수동 도구의 분석 엔진을 그대로 재사용하며, 한 번 실행하면 다음을 자동 수행합니다:

1. **수집** — `aws`/`az` CLI로 리소스 구성을 자동 수집(자리표시자가 필요한 명령은 건너뜀)
2. **분석** — 취약 구성·위험 점수·복합 위험(공격 경로) 판정
3. **침해 탐지** — GuardDuty/Defender 경고, 로그인 실패 급증(무차별 대입), 루트 사용, 악성 지표 상관분석
4. **대응 계획** — 취약 구성·악성 IP에 대한 차단/조치 명령 생성(기본 반자동)
5. **알림** — 심각/복합위험/침해 시 **Slack**으로 요약 전송
6. **리포트 저장** — 텍스트·HTML·엑셀·JSON을 타임스탬프로 자동 보관

### 실행

```bash
# 1회 실행(환경변수 설정 사용). 데모는 --mock
python -m autoauditor --platform aws
python -m autoauditor --platform azure --mock

# 이미 수집한 구성/로그 파일로 분석만
python -m autoauditor --config-file config.json --threat-file logs.txt
```

주요 환경변수(비밀값은 코드에 넣지 말고 여기서 주입):

| 환경변수 | 설명 | 기본 |
|----------|------|------|
| `AUTOAUDITOR_PLATFORM` | aws \| azure | aws |
| `AUTOAUDITOR_SLACK_WEBHOOK` | Slack Incoming Webhook URL(없으면 알림 생략) | (없음) |
| `AUTOAUDITOR_ALERT_MIN_SEVERITY` | 알림 최소 심각도 | HIGH |
| `AUTOAUDITOR_OUTPUT_DIR` | 리포트 저장 폴더 | ./autoaudit_out |
| `AUTOAUDITOR_REMEDIATION` | off \| suggest(반자동) \| auto | suggest |
| `AUTOAUDITOR_DRY_RUN` | true면 실제 변경 안 함 | true |
| `AUTOAUDITOR_PROTECT_TAGS` | 차단 금지(화이트리스트) 키워드, 쉼표구분 | (없음) |

### 스케줄 등록

```bash
# Linux/mac - cron 매시간 예시
0 * * * * cd /opt/kiro-azure-policy-offline-auditor && \
  AUTOAUDITOR_PLATFORM=aws AUTOAUDITOR_SLACK_WEBHOOK="..." \
  ./autoauditor/run_scheduled.sh >> /var/log/autoaudit/cron.log 2>&1
```

- **Windows**: `autoauditor\run_scheduled.bat` 을 작업 스케줄러(schtasks)에 등록

### ☁️ AWS Lambda 자동 배포 (SAM, 권장)

**한 줄 배포**로 Lambda + EventBridge(스케줄)를 만들고, 심각/침해 시 **Slack 알림**을 받습니다.
Lambda 런타임에 기본 포함된 **boto3**로 실제 계정 데이터를 수집하므로 `aws` CLI가 필요 없습니다.

```bash
cd deploy
# Windows:  deploy.bat "https://hooks.slack.com/services/XXX/YYY/ZZZ" "rate(1 hour)"
./deploy.sh "https://hooks.slack.com/services/XXX/YYY/ZZZ" "rate(1 hour)"

# 즉시 한 번 실행해 Slack 확인
aws lambda invoke --function-name cloud-sec-auto-auditor out.json
```

- 사전 준비: **AWS SAM CLI** 설치 + `aws configure`(배포 권한)
- 스케줄·심각도·차단 모드 등은 `--parameter-overrides`로 조정 (상세: **`deploy/README.md`**)
- **화면(웹 UI)의 "🤖 자동화 배포 가이드" 탭**에 동일 절차가 복사 버튼과 함께 단계별로 안내됩니다.
- 삭제: `sam delete --stack-name cloud-sec-auto-auditor`

### ☁️ Azure Functions 자동 배포 (Timer)

**한 줄 배포**로 Azure Functions(Timer) + 리소스 그룹·스토리지·관리 ID·역할·앱 설정을 자동 구성합니다.
Functions 런타임에는 `az` CLI가 없지만 **Azure SDK**로 실제 구독 데이터를 수집합니다(관리 ID 인증).

```bash
cd deploy-azure
# Windows:  deploy.bat "https://hooks.slack.com/services/XXX/YYY/ZZZ"
./deploy.sh "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

- 사전 준비: **Azure CLI**(`az login`) + **Azure Functions Core Tools(`func`)**
- 스케줄은 `deploy-azure/AutoAudit/function.json`의 CRON, 옵션은 Function App 앱 설정으로 조정 (상세: **`deploy-azure/README.md`**)
- 화면 "🤖 자동화 배포 가이드" 탭에서 **🟦 Azure**를 선택하면 동일 절차가 단계별로 안내됩니다.
- 삭제: `az group delete -n rg-cloudsec-autoaudit --yes`

### 🧰 배포 도구 로컬 설치 (처음 한 번)

**AWS로 배포하려면**
1. **AWS CLI** 설치 — AWS 공식 "Install AWS CLI"(Windows MSI). 확인: `aws --version`
2. **AWS SAM CLI** 설치 — AWS 공식 "Install SAM CLI"(Windows MSI). 확인: `sam --version`
3. **자격증명 등록**: 명령프롬프트에서 `aws configure`
   ```
   AWS Access Key ID:      (IAM 사용자 액세스 키)
   AWS Secret Access Key:  (비밀 키)
   Default region name:    ap-northeast-2      # 서울
   Default output format:  json
   ```
   > 액세스 키는 AWS 콘솔 → IAM → 사용자 → 보안 자격 증명 → 액세스 키에서 발급. **배포 권한**(CloudFormation/Lambda/IAM/S3/Events)이 있는 계정이어야 합니다.

**Azure로 배포하려면**
1. **Azure CLI** 설치 — Microsoft "Install Azure CLI". 확인: `az version`
2. **로그인**: `az login` → 브라우저 인증. 여러 구독이면 `az account set --subscription <구독ID>`
3. **Azure Functions Core Tools(func)** 설치 — Microsoft "Run functions locally". 확인: `func --version`

> 참고: 위 CLI는 **배포할 때만** 필요합니다. 배포된 Lambda/Functions는 이후 스스로 스케줄대로 실행됩니다.

### 🛡️ 자동 차단의 안전장치 (중요)

자동 차단은 잘못되면 정상 서비스를 막을 수 있어, 기본을 **반자동**으로 두고 여러 안전장치를 둡니다:

- **suggest(기본)**: 차단/조치 명령을 **생성만** 하고 실행하지 않음 → 사람이 검토 후 실행
- **dry_run(기본 true)**: `auto` 모드라도 dry_run이면 **실제 변경 없이** "실행했을 명령"만 기록
- **화이트리스트(`PROTECT_TAGS`)**: 보호 키워드가 포함된 대상은 **절대 건드리지 않음**(skipped_protected)
- **롤백 명령 동봉**: 각 조치에 되돌리기 명령을 함께 생성
- **파괴적 작업 금지**: 삭제·종료 계열은 자동 실행하지 않고 '제한/비활성/차단'만 수행

> 완전 자동 차단(`auto` + `--no-dry-run`)은 화이트리스트·롤백을 반드시 갖춘 뒤, 소규모부터 신중히 적용하세요.

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
  autoauditor/           # 🤖 자동 점검 에이전트(스케줄 실행)
    __init__.py
    __main__.py          # python -m autoauditor 진입점(1회 실행)
    config.py            # 설정(환경변수, 안전장치 옵션)
    collector.py         # aws/az CLI 자동 수집(+목업 폴백)
    collector_boto3.py   # boto3(AWS SDK) 수집 — Lambda 등 CLI 없는 환경용
    collector_azure_sdk.py # Azure SDK 수집 — Functions 등 CLI 없는 환경용
    threat.py            # 침해 탐지·상관분석(GuardDuty/Defender/로그)
    notifier.py          # Slack 알림(표준 라이브러리 urllib)
    remediation.py       # 차단/대응 명령 생성(반자동+안전장치)
    orchestrator.py      # run_once: 수집→분석→침해→알림→리포트→대응
    lambda_function.py   # AWS Lambda 핸들러(EventBridge 스케줄)
    azure_function.py    # Azure Functions 핸들러(Timer 트리거)
    run_scheduled.sh     # Linux/mac cron 실행 스크립트
    run_scheduled.bat    # Windows 작업 스케줄러 실행 스크립트
  deploy/                # AWS Lambda 배포(SAM)
    template.yaml        # SAM 템플릿(Lambda + EventBridge 스케줄 + 읽기 IAM)
    samconfig.toml       # 배포 기본값
    deploy.sh / deploy.bat  # 한 줄 배포 스크립트
    README.md            # 배포 가이드(단계별)
  deploy-azure/          # Azure Functions 배포
    host.json / requirements.txt
    AutoAudit/function.json   # Timer 트리거(스케줄)
    AutoAudit/__init__.py     # Functions 진입점
    deploy.sh / deploy.bat    # 한 줄 배포 스크립트
    README.md            # 배포 가이드(단계별)
  samples/               # 예시 입력 파일
  tests/                 # 단위 테스트 (python -m unittest)
  README.md
```

## 테스트

```bash
python -m unittest discover -s tests -v
```

## 🔐 보안 (금융권/내부망 반입)

금융회사 내부망 등 통제된 환경에 반입할 때 검토할 보안 설계·안전장치는 **[`SECURITY.md`](SECURITY.md)** 에 정리되어 있습니다. 요점:

- **외부 통신**: 수동 도구는 전혀 없음(완전 오프라인). 자동 도구는 **Slack Webhook 전송만**(선택).
- **명령 실행**: `shell=True` 미사용 — 모든 외부 명령은 셸을 거치지 않고 직접 실행(인젝션 방지). `eval/exec/os.system/pickle` 미사용.
- **웹 UI**: 기본 `127.0.0.1`(로컬 전용), 외부 바인딩 시 경고. 인증이 없으므로 신뢰된 환경에서만 사용.
- **비밀정보**: Webhook·계정 ID 등은 환경변수/배포 파라미터로만 주입(하드코딩 없음).
- **권한**: 점검·수집은 읽기 전용으로 충분. 자동 차단은 기본 반자동(suggest)+dry-run.

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
