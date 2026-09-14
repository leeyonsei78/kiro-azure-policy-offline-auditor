# Azure 정책 오프라인 보안검토 (azure-policy-offline-auditor)

> **폐쇄망(오프라인) 전용.** Azure CLI(`az ...`)로 추출한 정책·구성 텍스트를 업로드하면,
> 인터넷·AI·클라우드 연결 없이 **ISMS-P 클라우드 인프라 통제항목** 기준으로 보안 이슈를 찾고
> 개선 방안을 제안합니다.

## 특징

- 🔒 **완전 오프라인**: Python 표준 라이브러리만 사용. 외부 패키지·인터넷·AI API·CDN이 전혀 필요 없습니다.
- 📋 **ISMS-P 기준**: 클라우드 인프라 직결 7개 영역·**17개 통제항목**의 판단기준/개선방안을 내장.
- 🧩 **관대한 입력**: `az ... -o json` 출력이 가장 정확하지만, 여러 명령 출력을 한 파일에 이어붙이거나 표/텍스트가 섞여도 최대한 분석합니다.
- 🖥️ **웹 UI + CLI**: 브라우저에서 붙여넣기/업로드하거나, 명령줄에서 파일/파이프로 검토.
- 🔎 **결과**: 점수·등급, 이슈별 심각도, 매핑된 ISMS-P 통제항목, **구체적 개선 제안**, 재점검용 CLI.

## 왜 오프라인인가

폐쇄망에서는 클라우드/AI에 직접 연결할 수 없습니다. 그래서 이 도구는 판정 로직(정규식·구조 분석)과
ISMS-P 지식 베이스를 **코드에 내장**해, 망분리 환경의 검토 PC에서 그대로 실행되도록 만들었습니다.
입력 텍스트는 **메모리에서만 처리**되고 어디에도 저장/전송하지 않습니다.

## 요구사항

- Python 3.8 이상 (표준 라이브러리만 사용 — 추가 설치 불필요)

## 설치 (폐쇄망)

인터넷이 없으므로 파일만 복사하면 됩니다.

1. 이 폴더(`azure-policy-offline-auditor/`)를 검토 PC로 복사 (USB·내부망 파일서버 등)
2. Python 3.8+ 설치되어 있는지 확인: `python --version`
3. 끝. (pip install 불필요)

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

### 직접 명령으로 실행

```bash
python -m auditor --web            # http://127.0.0.1:8080
# 또는
python -m auditor.webui --port 8080
```

브라우저에서 접속 → Azure 정책 텍스트를 **붙여넣기**하거나 **파일 불러오기** → **보안검토 실행**.
결과에 점수·등급, 통제항목별 이슈, 개선 제안이 표시됩니다.

## 사용법 2 — 명령줄(CLI)

```bash
# 파일 검토 → 텍스트 리포트
python -m auditor policy.txt

# JSON 리포트(자동화 연동용)
python -m auditor policy.txt --json

# 파이프 입력
az network nsg rule list --nsg-name NSG -g RG -o json | python -m auditor

# ISMS-P 통제항목 목록만 보기
python -m auditor --controls
```

종료 코드: `0`=이슈 없음, `1`=이슈 발견(파이프라인 게이트로 활용), `2`=실행 오류

## 입력 준비 (Azure 쪽에서 먼저 추출)

인터넷망 또는 관리망에서 `az` CLI로 정책을 뽑아 **txt로 저장**한 뒤, 폐쇄망 검토 PC로 옮깁니다.
아래는 대표 예시입니다 (`-o json` 권장):

```bash
az network nsg rule list --nsg-name <NSG> -g <RG> -o json           > nsg.txt
az storage account list -o json                                      >> nsg.txt
az keyvault list -o json                                             >> nsg.txt
az role assignment list --all -o json                                >> nsg.txt
az sql db list -g <RG> -s <SERVER> -o json                           >> nsg.txt
```

여러 명령 출력을 한 파일에 이어붙여도 됩니다. `samples/` 폴더의 예시 파일을 참고하세요.

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

자동 검출은 입력에 포함된 리소스에 한합니다. 텍스트만 있는 항목(진단·백업·패치 등)은 키워드로 보완 탐지합니다.

## 프로젝트 구조

```
azure-policy-offline-auditor/
  auditor/
    __init__.py
    __main__.py          # python -m auditor 진입점
    knowledge_base.py    # ISMS-P Azure 17개 통제항목(판단기준·개선방안) 내장
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

## 참고 / 출처

- 통제항목의 판단기준·개선방안은 사내 참고자료 **isms-cloud-audit-matrix**(ISMS-P 인증기준 재구성)를 기반으로 합니다.
- 판정 엔진 설계는 **ai-security-suite**의 오프라인 감사 엔진 패턴을 참고해 이 프로젝트에 맞게 새로 구현했습니다.

## 면책

본 도구는 **오프라인 규칙 기반 자동 검토** 결과를 제공하며 **참고용**입니다. 오탐/미탐이 있을 수 있고,
실제 조치 전 대상 환경과 업무 요건을 확인해야 합니다. **KISA의 공식 ISMS-P 심사 자료를 대체하지 않습니다.**
