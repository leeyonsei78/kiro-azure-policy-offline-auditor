"""애플리케이션 보안 점검(간이 SAST) + WAF 설정 점검.

폐쇄망 전용 · 파이썬 표준 라이브러리(re)만 사용.

중요(범위·한계):
    - 이 스캐너는 정규식 기반 '간이(lightweight) SAST'로, 상용 정적분석 엔진을
      대체하지 않는다. 데이터 흐름(taint) 분석을 하지 않으므로 오탐/미탐이 있을 수
      있으며 결과는 '참고용'이다. 실제 위험 여부는 담당자가 코드 맥락으로 확인해야 한다.
    - DAST(실제 공격 수행)는 폐쇄망·안전상 수행하지 않는다. 대신 WAF 설정이
      켜져 있는지 '구성 점검'만 제공한다.

기능:
    - scan_source(text, filename="", lang="auto"): 소스코드 텍스트에서 위험 패턴 탐지 -> Finding 리스트.
    - check_waf(text, platform): WAF 구성 JSON을 받아 활성/룰셋 여부 점검 -> Finding 리스트.
    - run(text, filename, platform): 위 둘을 합쳐 결과 dict 반환(웹 UI/CLI 공용).
    - detect_language(filename, text): 파일 확장자·내용으로 언어(python/js/html/sql) 추정.

언어 태그(rule["lang"]):
    python / js / html / sql / common(모든 언어에 적용). 스캔 시 감지된 언어 + common 규칙만
    적용해 다른 언어에서의 오탐을 줄인다. lang="auto"면 자동 감지, "all"이면 전체 적용.
"""

from __future__ import annotations

import re
from typing import Any

from .models import Finding, Severity

# ---------------------------------------------------------------------------
# KISA 소프트웨어 개발보안 가이드(시큐어코딩) 7대 보안약점 유형.
# 각 SAST 규칙의 kisa 필드에 (유형코드, 약점명)을 매핑해 "KISA 어느 항목인지"를 표시한다.
#   K1 입력데이터 검증 및 표현 / K2 보안 기능 / K3 시간 및 상태 /
#   K4 에러 처리 / K5 코드 오류 / K6 캡슐화 / K7 API 오용
# ---------------------------------------------------------------------------
_KISA_TYPES: dict[str, str] = {
    "K1": "입력데이터 검증 및 표현",
    "K2": "보안 기능",
    "K3": "시간 및 상태",
    "K4": "에러 처리",
    "K5": "코드 오류",
    "K6": "캡슐화",
    "K7": "API 오용",
}


def kisa_type_name(code: str) -> str:
    """KISA 유형 코드(K1~K7) -> 유형명. 알 수 없으면 빈 문자열."""
    return _KISA_TYPES.get((code or "").upper(), "")


# ---------------------------------------------------------------------------
# 간이 SAST 규칙 스키마:
#   id, label, re(정규식), sev, why(설명), fix(개선), bad(취약예), good(개선예), lang,
#   kisa=(유형코드, 약점명)  -- KISA 시큐어코딩 매핑
# 각 규칙은 '줄 단위'로 매칭한다. 오탐을 줄이기 위해 형태가 비교적 뚜렷한 것만 포함한다.
# ---------------------------------------------------------------------------
_SAST_RULES: list[dict[str, Any]] = [
    # ===================== 공통(common) =====================
    {
        "id": "hardcoded_secret",
        "label": "하드코딩된 비밀번호/키",
        "re": re.compile(r"""(?ix)(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*['"][^'"]{4,}['"]"""),
        "sev": "HIGH", "lang": "common", "kisa": ("K2", "하드코딩된 중요정보(비밀번호/키)"),
        "why": "소스코드에 비밀번호·API 키를 직접 적으면, 코드가 유출될 때 자격증명도 함께 노출됩니다.",
        "fix": "비밀값은 환경변수·비밀 관리 서비스(AWS Secrets Manager, Azure Key Vault)로 옮기고 코드에서 제거하세요.",
        "bad": 'password = "P@ssw0rd123"',
        "good": 'password = os.environ["DB_PASSWORD"]',
    },
    {
        "id": "private_ip_hardcoded",
        "label": "하드코딩된 IP 주소",
        "re": re.compile(r"""(?x)['"]?\b(?:\d{1,3}\.){3}\d{1,3}\b['"]?"""),
        "sev": "LOW", "lang": "common", "kisa": ("K6", "중요정보 평문 저장/노출(하드코딩 IP)"),
        "why": "소스에 IP를 직접 박으면 환경 이전·주소 변경 시 오류가 나고, 내부망 구조가 코드에 노출됩니다.",
        "fix": "IP·엔드포인트는 환경변수·설정 파일·서비스 디스커버리로 분리하세요.",
        "bad": 'DB_HOST = "192.168.10.25"',
        "good": 'DB_HOST = os.environ["DB_HOST"]',
        # 버전문자열(1.2.3.4 형태의 흔한 오탐) 완화: 4옥텟 모두 0~255여야 IP로 간주
        "validate": "ipv4",
    },
    {
        "id": "weak_crypto",
        "label": "취약한 해시/암호 알고리즘",
        "re": re.compile(r"""(?ix)(hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*['"](MD5|SHA-1)['"]|createHash\s*\(\s*['"](md5|sha1)['"]|DES|RC4|ECB)"""),
        "sev": "MEDIUM", "lang": "common", "kisa": ("K2", "취약한 암호화 알고리즘 사용"),
        "why": "MD5·SHA-1·DES·RC4·ECB는 취약한 알고리즘으로 무결성·기밀성 보호에 부적합합니다.",
        "fix": "SHA-256 이상·AES-GCM을 쓰고, 비밀번호는 bcrypt·scrypt·argon2 전용 해시를 사용하세요.",
        "bad": "hashlib.md5(password.encode())",
        "good": "hashlib.sha256(data)  # 비밀번호는 bcrypt/argon2",
    },
    {
        "id": "insecure_random",
        "label": "예측 가능한 난수(보안용 부적합)",
        "re": re.compile(r"""(?ix)(?<![.\w])random\.(random|randint|choice|randrange)\s*\(|Math\.random\s*\("""),
        "sev": "LOW", "lang": "common", "kisa": ("K2", "예측 가능한 난수 사용"),
        "why": "일반 난수(random/Math.random)는 예측 가능해 토큰·비밀번호·세션에 쓰면 위험합니다.",
        "fix": "보안용 난수는 secrets 모듈(Python)·crypto.randomBytes(Node)를 사용하세요.",
        "bad": "token = random.randint(1000, 9999)",
        "good": "import secrets; token = secrets.token_hex(16)",
    },
    {
        "id": "tls_verify_disabled",
        "label": "TLS 인증서 검증 비활성화",
        "re": re.compile(r"""(?ix)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|InsecureSkipVerify\s*:\s*true)"""),
        "sev": "MEDIUM", "lang": "common", "kisa": ("K2", "부적절한 인증서 검증(TLS 검증 비활성화)"),
        "why": "TLS 검증을 끄면 중간자 공격(MITM)에 노출되어 통신이 가로채기·변조될 수 있습니다.",
        "fix": "인증서 검증을 활성화(verify=True)하고, 사설 CA는 신뢰 저장소에 등록하세요.",
        "bad": "requests.get(url, verify=False)",
        "good": "requests.get(url)  # 기본값 verify=True",
    },
    {
        "id": "sensitive_info_logging",
        "label": "민감정보 로그 출력(비밀번호·토큰 등)",
        "re": re.compile(r"""(?ix)(print|console\.(log|info|debug|warn|error)|logger?\.(info|debug|warning|error|log)|logging\.(info|debug|warning|error))\s*\([^)]*(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|주민|카드번호|ssn)"""),
        "sev": "MEDIUM", "lang": "common", "kisa": ("K6", "중요정보 로그 출력(민감정보 노출)"),
        "why": "비밀번호·토큰·개인정보를 로그로 남기면 로그 파일·수집 시스템을 통해 민감정보가 유출됩니다.",
        "fix": "로그에는 민감정보를 남기지 말고, 필요하면 마스킹(예: ****)하거나 식별자만 기록하세요.",
        "bad": 'logger.info("login pw=" + password)',
        "good": 'logger.info("login user=%s", user_id)  # 비밀번호는 남기지 않음',
    },

    # ===================== 파이썬(python) =====================
    {
        "id": "os_command_exec",
        "label": "OS 명령 실행(명령 인젝션 위험)",
        "re": re.compile(r"""(?ix)(os\.system|os\.popen|subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True|child_process\.(exec|execSync)\s*\()"""),
        "sev": "HIGH", "lang": "python", "kisa": ("K1", "운영체제 명령어 삽입"),
        "why": "외부 입력이 셸 명령에 들어가면 임의 명령이 실행(명령 인젝션)될 수 있습니다.",
        "fix": "shell=True를 피하고 인자를 리스트로 전달하세요. 입력은 화이트리스트로 검증하세요.",
        "bad": 'subprocess.run(f"ping {host}", shell=True)',
        "good": 'subprocess.run(["ping", host])  # 리스트 인자, shell 미사용',
    },
    {
        "id": "dangerous_eval",
        "label": "eval/exec 등 동적 코드 실행",
        "re": re.compile(r"""(?ix)(?<![.\w])(eval|exec)\s*\(|new\s+Function\s*\(|pickle\.loads\s*\(|yaml\.load\s*\((?![^)]*Loader)"""),
        "sev": "HIGH", "lang": "python", "kisa": ("K7", "위험한 함수(eval/exec)·안전하지 않은 역직렬화"),
        "why": "eval/exec나 안전하지 않은 역직렬화는 외부 입력으로 임의 코드가 실행될 수 있습니다.",
        "fix": "eval/exec 사용을 제거하고, 역직렬화는 안전한 방식(json, yaml.safe_load)을 쓰세요.",
        "bad": "result = eval(user_input)",
        "good": "import json; result = json.loads(user_input)",
    },
    {
        "id": "debug_enabled",
        "label": "디버그 모드 활성화(운영 위험)",
        "re": re.compile(r"""(?ix)(debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1)"""),
        "sev": "LOW", "lang": "python", "kisa": ("K4", "오류 상황 대응 부재(디버그 모드 노출)"),
        "why": "운영에서 디버그 모드가 켜지면 상세 오류·대화형 콘솔로 내부 정보가 노출될 수 있습니다.",
        "fix": "운영 환경에서는 디버그를 끄고(Debug=False), 오류 상세는 로그로만 남기세요.",
        "bad": "app.run(debug=True)",
        "good": "app.run(debug=False)  # 운영",
    },
    {
        "id": "insecure_file_perms",
        "label": "안전하지 않은 파일 권한(chmod 0777 등)",
        "re": re.compile(r"""(?ix)(os\.chmod\s*\([^)]*0o?7[0-7]7|os\.chmod\s*\([^)]*0o?777|chmod\s+(-R\s+)?0?777|st_mode.*0o?777)"""),
        "sev": "MEDIUM", "lang": "python", "kisa": ("K2", "부적절한 접근 권한 설정(파일 권한)"),
        "why": "0777(모두에게 읽기·쓰기·실행) 권한은 같은 시스템의 다른 사용자가 파일을 변조·실행할 수 있게 합니다.",
        "fix": "필요한 최소 권한만 부여하세요(예: 0o600 소유자만, 0o640 그룹 읽기). 비밀 파일은 0o600 권장.",
        "bad": "os.chmod(path, 0o777)",
        "good": "os.chmod(path, 0o600)  # 소유자만 읽기/쓰기",
    },
    {
        "id": "path_traversal",
        "label": "경로 조작(Path Traversal) 위험",
        "re": re.compile(r"""(?ix)(open|os\.path\.join|send_file|sendfile|os\.remove|shutil\.(copy|move|rmtree))\s*\([^)]*(request\.(args|form|values|GET|POST|params)|req\.(query|params|body)|input\(|sys\.argv)"""),
        "sev": "HIGH", "lang": "python", "kisa": ("K1", "경로 조작 및 자원 삽입"),
        "why": "사용자 입력을 파일 경로에 그대로 쓰면 '../' 등으로 의도치 않은 파일에 접근·삭제할 수 있습니다.",
        "fix": "허용 디렉터리를 정하고 os.path.realpath로 정규화 후 해당 경로 하위인지 검증하세요. 파일명은 화이트리스트로 제한.",
        "bad": 'open(os.path.join(base, request.args["name"]))',
        "good": 'p=os.path.realpath(os.path.join(base, name)); assert p.startswith(base_real)',
    },
    {
        "id": "xxe_risk",
        "label": "XXE 위험(안전하지 않은 XML 파서)",
        "re": re.compile(r"""(?ix)(xml\.etree|xml\.dom\.minidom|xml\.sax|lxml\.etree|etree\.parse|parseString|minidom\.parse|resolve_entities\s*=\s*True|no_network\s*=\s*False)"""),
        "sev": "MEDIUM", "lang": "python", "kisa": ("K1", "XML 외부 개체(XXE)"),
        "why": "표준 XML 파서는 외부 엔터티(XXE)를 처리해 파일 유출·SSRF·DoS로 이어질 수 있습니다.",
        "fix": "defusedxml 사용 또는 외부 엔터티/DTD 처리를 비활성화하세요(resolve_entities=False, no_network=True).",
        "bad": "import xml.etree.ElementTree as ET; ET.parse(user_file)",
        "good": "from defusedxml.ElementTree import parse; parse(user_file)",
    },
    {
        "id": "assert_for_security",
        "label": "보안 검사에 assert 사용",
        "re": re.compile(r"""(?ix)^\s*assert\s+.*(auth|admin|permission|role|token|password|is_valid|verify)"""),
        "sev": "LOW", "lang": "python", "kisa": ("K2", "부적절한 인가(보안 검사 assert)"),
        "why": "assert는 최적화 실행(python -O)에서 통째로 제거됩니다. 인증·권한 검사를 assert로 하면 운영에서 무력화될 수 있습니다.",
        "fix": "보안 검사는 if 문 + 예외 발생으로 구현하세요. assert는 개발용 불변식 확인에만 쓰세요.",
        "bad": "assert user.is_admin, 'forbidden'",
        "good": "if not user.is_admin: raise PermissionError('forbidden')",
    },
    {
        "id": "insecure_tempfile",
        "label": "안전하지 않은 임시파일 생성",
        "re": re.compile(r"""(?ix)(tempfile\.mktemp\s*\(|/tmp/[A-Za-z0-9_.-]+\s*['"]?\s*[,)]|open\s*\(\s*['"]/tmp/)"""),
        "sev": "LOW", "lang": "python", "kisa": ("K3", "경쟁 조건(TOCTOU)·안전하지 않은 임시파일"),
        "why": "예측 가능한 임시파일 경로나 mktemp는 경쟁 조건(TOCTOU)·심볼릭 링크 공격에 취약합니다.",
        "fix": "tempfile.NamedTemporaryFile / mkstemp 로 안전하게 생성하세요.",
        "bad": 'path = tempfile.mktemp()',
        "good": "fd, path = tempfile.mkstemp()",
    },
    {
        "id": "flask_ssl_none",
        "label": "요청 검증 없는 서버 바인딩(0.0.0.0)",
        "re": re.compile(r"""(?ix)(host\s*=\s*['"]0\.0\.0\.0['"]|app\.run\([^)]*['"]0\.0\.0\.0['"])"""),
        "sev": "LOW", "lang": "python", "kisa": ("K2", "부적절한 접근 통제(전체 인터페이스 바인딩)"),
        "why": "0.0.0.0 바인딩은 모든 인터페이스에 노출됩니다. 인증이 없으면 외부에서 접근될 수 있습니다.",
        "fix": "로컬만 필요하면 127.0.0.1로 바인딩하고, 외부 노출은 인증·방화벽·리버스 프록시로 보호하세요.",
        "bad": 'app.run(host="0.0.0.0")',
        "good": 'app.run(host="127.0.0.1")  # 필요한 경우에만 외부 노출',
    },
    {
        "id": "broad_except_pass",
        "label": "광범위한 예외 무시(except: pass)",
        "re": re.compile(r"""(?ix)except\s*(\w+\s*)?:\s*pass\s*$|except\s*:\s*$|catch\s*\([^)]*\)\s*\{\s*\}"""),
        "sev": "LOW", "lang": "python", "kisa": ("K4", "부적절한 예외 처리(오류 무시)"),
        "why": "예외를 모두 삼키면(except: pass) 보안 오류·공격 시도가 은폐되고 문제 원인 추적이 어려워집니다.",
        "fix": "구체적 예외만 잡고, 최소한 로그를 남기세요. 보안 관련 오류는 안전하게 실패(fail-safe)하도록 하세요.",
        "bad": "try:\n    verify(token)\nexcept:\n    pass",
        "good": "except InvalidToken as e:\n    logger.warning('token invalid: %s', e); raise",
    },
    {
        "id": "ssrf_risk",
        "label": "서버측 요청 위조(SSRF) 위험",
        "re": re.compile(r"""(?ix)(requests\.(get|post|put|delete|head)|urllib\.request\.urlopen|urlopen|httpx\.(get|post)|fetch)\s*\([^)]*(request\.(args|form|values|GET|POST|params)|req\.(query|params|body)|input\(|params\[)"""),
        "sev": "HIGH", "lang": "python", "kisa": ("K1", "서버측 요청 위조(SSRF)"),
        "why": "사용자 입력 URL로 서버가 요청을 보내면, 내부망·클라우드 메타데이터(169.254.169.254) 등에 접근될 수 있습니다(SSRF).",
        "fix": "요청 대상 URL을 허용 목록(도메인/IP)으로 제한하고, 내부·사설 IP·메타데이터 주소를 차단하세요.",
        "bad": 'requests.get(request.args["url"])',
        "good": 'if urlparse(url).hostname in ALLOWED: requests.get(url)',
    },
    {
        "id": "open_redirect",
        "label": "검증 없는 리다이렉트(Open Redirect)",
        "re": re.compile(r"""(?ix)(redirect|Location\s*header|res\.redirect|HttpResponseRedirect)\s*\([^)]*(request\.(args|form|values|GET|POST|params)|req\.(query|params)|params\[|next\b)"""),
        "sev": "MEDIUM", "lang": "python", "kisa": ("K1", "신뢰할 수 없는 사이트로의 리다이렉트"),
        "why": "사용자 입력을 그대로 리다이렉트 대상으로 쓰면 피싱 사이트로 유도(Open Redirect)될 수 있습니다.",
        "fix": "리다이렉트 대상은 내부 경로 또는 허용된 도메인 목록으로만 제한하세요.",
        "bad": 'return redirect(request.args["next"])',
        "good": 'return redirect(url_for("home")) if not is_safe(next) else redirect(next)',
    },

    # ===================== SQL(sql) =====================
    {
        "id": "sql_injection",
        "label": "SQL 인젝션 위험(문자열 결합 쿼리)",
        "re": re.compile(r"""(?ix)(select|insert|update|delete)\s+.*(\+\s*\w+|%\s*\(|%s\s*%|\.format\(|f['"])"""),
        "sev": "HIGH", "lang": "common", "kisa": ("K1", "SQL 삽입"),
        "why": "쿼리에 외부 입력을 문자열로 이어 붙이면 공격자가 쿼리를 조작(SQL 인젝션)할 수 있습니다.",
        "fix": "파라미터 바인딩(플레이스홀더)이나 ORM을 사용하세요. 입력을 쿼리 문자열에 직접 넣지 마세요.",
        "bad": 'cursor.execute("SELECT * FROM users WHERE id=" + uid)',
        "good": 'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))',
    },
    {
        "id": "sql_grant_all",
        "label": "과도한 권한 부여(GRANT ALL)",
        "re": re.compile(r"""(?ix)grant\s+all(\s+privileges)?\s+on\s+.*\bto\b|with\s+grant\s+option|grant\s+all\s+to"""),
        "sev": "HIGH", "lang": "sql", "kisa": ("K2", "부적절한 인가(과도한 권한 부여)"),
        "why": "GRANT ALL은 계정에 모든 권한을 줍니다. 계정 탈취 시 피해가 전면적으로 커집니다(최소권한 위반).",
        "fix": "업무에 필요한 최소 권한(SELECT/INSERT 등)만 부여하고, 관리 권한은 분리하세요.",
        "bad": "GRANT ALL PRIVILEGES ON db.* TO 'app'@'%';",
        "good": "GRANT SELECT, INSERT ON db.orders TO 'app'@'10.0.%';",
    },
    {
        "id": "sql_public_grant",
        "label": "PUBLIC/모든 호스트에 권한 부여",
        "re": re.compile(r"""(?ix)(to\s+public\b|to\s+'[^']*'@'%'|identified\s+by\s+['"][^'"]*['"]|create\s+user\s+.*@'%')"""),
        "sev": "HIGH", "lang": "sql", "kisa": ("K2", "부적절한 인가(PUBLIC 권한 부여)"),
        "why": "PUBLIC 또는 '%'(모든 호스트) 대상 권한 부여, 평문 비밀번호 지정은 누구나·어디서나 접근을 허용할 수 있습니다.",
        "fix": "특정 사용자·특정 호스트(IP 대역)로 제한하고, 비밀번호는 스크립트에 평문으로 두지 마세요.",
        "bad": "CREATE USER 'app'@'%' IDENTIFIED BY 'plainpw';",
        "good": "CREATE USER 'app'@'10.0.0.%';  -- 호스트 제한, 비번은 별도 안전 주입",
    },
    {
        "id": "sql_xp_cmdshell",
        "label": "위험한 확장 프로시저(xp_cmdshell 등)",
        "re": re.compile(r"""(?ix)(xp_cmdshell|sp_oacreate|sp_configure\s+['"]?xp_cmdshell|OPENROWSET|load_file\s*\(|into\s+outfile|into\s+dumpfile)"""),
        "sev": "CRITICAL", "lang": "sql", "kisa": ("K7", "위험한 확장 기능(xp_cmdshell 등) 사용"),
        "why": "xp_cmdshell·load_file·INTO OUTFILE 등은 DB에서 OS 명령 실행·파일 읽기/쓰기가 가능해 서버 장악으로 이어집니다.",
        "fix": "해당 기능을 비활성화하고(sp_configure 'xp_cmdshell',0), DB 계정에 파일·명령 실행 권한을 주지 마세요.",
        "bad": "EXEC xp_cmdshell 'whoami';",
        "good": "-- xp_cmdshell 비활성화 유지; 애플리케이션에서 처리",
    },
    {
        "id": "sql_plaintext_password",
        "label": "비밀번호 평문 저장/비교",
        "re": re.compile(r"""(?ix)(password\s*(varchar|char|text)|where\s+password\s*=\s*['"]|set\s+password\s*=\s*['"][^'"]+['"])"""),
        "sev": "HIGH", "lang": "sql", "kisa": ("K2", "중요정보 평문 저장(비밀번호)"),
        "why": "비밀번호를 평문 컬럼에 저장하거나 평문으로 비교하면 DB 유출 시 즉시 계정이 탈취됩니다.",
        "fix": "비밀번호는 bcrypt/argon2 등으로 해시해 저장하고, 애플리케이션에서 해시 비교하세요.",
        "bad": "WHERE password = 'user_input'",
        "good": "-- 해시 저장 후 앱에서 검증(bcrypt.checkpw)",
    },

    # ===================== HTML / 프론트엔드(html) =====================
    {
        "id": "xss_innerhtml",
        "label": "XSS 위험(innerHTML/document.write에 동적 값)",
        "re": re.compile(r"""(?ix)(\.innerHTML\s*=|\.outerHTML\s*=|document\.write(ln)?\s*\(|insertAdjacentHTML\s*\()"""),
        "sev": "HIGH", "lang": "html", "kisa": ("K1", "크로스사이트 스크립트(XSS)"),
        "why": "사용자 입력을 innerHTML·document.write로 그대로 넣으면 스크립트가 실행(XSS)될 수 있습니다.",
        "fix": "textContent/innerText로 넣거나, 프레임워크의 자동 이스케이프를 쓰고, 필요 시 DOMPurify로 정제하세요.",
        "bad": "el.innerHTML = userInput;",
        "good": "el.textContent = userInput;  // 또는 DOMPurify.sanitize(...)",
    },
    {
        "id": "xss_jquery_html",
        "label": "XSS 위험(jQuery .html()/append에 동적 값)",
        "re": re.compile(r"""(?ix)\$\([^)]*\)\.(html|append|prepend|after|before)\s*\(\s*[^'"][^)]*(val\(|data\(|param|input|location|search)"""),
        "sev": "HIGH", "lang": "html", "kisa": ("K1", "크로스사이트 스크립트(XSS)"),
        "why": "jQuery .html()/append 등에 사용자 값을 넣으면 XSS가 발생할 수 있습니다.",
        "fix": ".text()로 넣거나 입력을 이스케이프/정제하세요.",
        "bad": "$('#out').html(location.search);",
        "good": "$('#out').text(value);",
    },
    {
        "id": "js_url_scheme",
        "label": "javascript: URL / 문자열 setTimeout",
        "re": re.compile(r"""(?ix)(href\s*=\s*['"]?\s*javascript:|location(\.href)?\s*=\s*['"]javascript:|setTimeout\s*\(\s*['"]|setInterval\s*\(\s*['"])"""),
        "sev": "MEDIUM", "lang": "html", "kisa": ("K7", "위험한 형식의 URL/함수 사용"),
        "why": "javascript: URL이나 문자열 인자 setTimeout/setInterval은 임의 스크립트 실행 통로가 됩니다.",
        "fix": "javascript: URL을 제거하고, setTimeout에는 문자열 대신 함수를 전달하세요.",
        "bad": '<a href="javascript:doIt()">',
        "good": '<a href="#" onclick="doIt(); return false;">  // 또는 addEventListener',
    },
    {
        "id": "target_blank_noopener",
        "label": "target=_blank 에 rel=noopener 누락(탭 탈취)",
        "re": re.compile(r"""(?ix)target\s*=\s*['"]_blank['"](?![^>]*rel\s*=\s*['"][^'"]*noopener)"""),
        "sev": "LOW", "lang": "html", "kisa": ("K1", "부적절한 링크 처리(탭 나빙)"),
        "why": "target=_blank 링크는 rel=noopener가 없으면 새 창이 window.opener로 원본 페이지를 조작(탭 나빙)할 수 있습니다.",
        "fix": 'target="_blank" 링크에는 rel="noopener noreferrer"를 추가하세요.',
        "bad": '<a href="https://x.com" target="_blank">',
        "good": '<a href="https://x.com" target="_blank" rel="noopener noreferrer">',
    },
    {
        "id": "inline_event_handler",
        "label": "인라인 이벤트 핸들러(onerror/onload 등)",
        "re": re.compile(r"""(?ix)<[^>]+\son(error|load|click|mouseover|focus)\s*=\s*['"][^'"]*(document\.|window\.|eval|alert|fetch)"""),
        "sev": "LOW", "lang": "html", "kisa": ("K1", "크로스사이트 스크립트(인라인 핸들러)"),
        "why": "인라인 이벤트 핸들러는 XSS 표면을 넓히고 CSP 적용을 어렵게 합니다.",
        "fix": "이벤트는 addEventListener로 분리하고, 콘텐츠 보안 정책(CSP)을 적용하세요.",
        "bad": "<img src=x onerror=\"fetch('/steal')\">",
        "good": "el.addEventListener('click', handler);  // + CSP",
    },
    {
        "id": "debug_code_leftover",
        "label": "디버그 코드 잔존(console.log/debugger)",
        "re": re.compile(r"""(?ix)(?<![.\w])console\.(log|debug|info)\s*\(|(?<![.\w])debugger\s*;?|alert\s*\("""),
        "sev": "LOW", "lang": "html", "kisa": ("K6", "제거되지 않은 디버그 코드"),
        "why": "운영 코드에 남은 console.log·debugger·alert는 내부 정보 노출·동작 방해가 될 수 있습니다.",
        "fix": "배포 전에 디버그 코드를 제거하고, 빌드 단계에서 자동 제거(예: 린터·번들러 설정)하세요.",
        "bad": "console.log('token=', token);",
        "good": "// 디버그 로그 제거 (또는 개발 환경에서만 조건부 출력)",
    },
]

# WAF 구성 점검용 키워드(입력 JSON/텍스트에서 활성 흔적을 찾는다).
_WAF_ACTIVE_HINTS = re.compile(
    r"(?i)(webacl|web_acl|wafv2|aws_wafv2|frontdoor.*waf|application\s*gateway.*waf|"
    r"\"?firewallpolicy\"?|managedrulegroup|owasp|managed_rule_set|policySettings)"
)
# '차단(blocking)'으로 동작하는 상태만 활성으로 본다. Detection(탐지만)은 차단하지 않으므로 제외.
_WAF_ENABLED = re.compile(r"(?i)\"?(enabledstate|state|mode)\"?\s*[:=]\s*\"?(enabled|prevention|on)\b")
_WAF_MANAGED_RULES = re.compile(r"(?i)(managedrulegroup|managedrulesets?|owasp|coreruleset|crs|managed_rule_set)")


# 언어별 라벨(리포트 표기용)
_LANG_LABEL = {"python": "Python", "js": "JavaScript", "html": "HTML", "sql": "SQL",
               "common": "공통", "unknown": "일반"}

# 파일 확장자 -> 언어
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js",
    ".html": "html", ".htm": "html", ".vue": "html", ".svelte": "html",
    ".sql": "sql", ".ddl": "sql",
}

_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")


def detect_language(filename: str = "", text: str = "") -> str:
    """파일 확장자·내용으로 언어를 추정한다. 실패 시 'unknown'.

    'unknown'이면 스캔 시 모든 규칙을 적용(가장 넓게 점검)한다.
    """
    import os
    ext = os.path.splitext(filename or "")[1].lower()
    if ext in _EXT_LANG:
        return _EXT_LANG[ext]
    low = (text or "")[:4000].lower()
    # 내용 기반 휴리스틱(뚜렷한 신호 위주)
    if re.search(r"<\s*(html|!doctype|div|script|body|a\s|img\s)", low):
        return "html"
    if re.search(r"\b(select|insert|update|delete|create\s+table|grant|create\s+user)\b.*\b(from|into|table|to)\b", low):
        return "sql"
    if re.search(r"\b(def |import |from \w+ import|print\(|self\.)", low):
        return "python"
    if re.search(r"\b(function |const |let |var |=>|require\(|console\.log)", low):
        return "js"
    return "unknown"


def _rule_applies(rule: dict, lang: str) -> bool:
    """규칙이 현재 언어에 적용되는지. common은 항상, unknown/all이면 전체 적용."""
    if lang in ("unknown", "all"):
        return True
    rlang = rule.get("lang", "common")
    return rlang == "common" or rlang == lang


def _false_positive(rule: dict, line: str, match: "re.Match") -> bool:
    """규칙별 추가 검증으로 명백한 오탐을 걸러낸다."""
    if rule.get("validate") == "ipv4":
        # 매치 라인에서 IPv4를 찾아 4옥텟이 모두 0~255인지 확인(버전문자열 등 완화)
        found = _IPV4_RE.search(line)
        if not found:
            return True
        octets = found.group(1).split(".")
        if any(not (o.isdigit() and 0 <= int(o) <= 255) for o in octets):
            return True
        # 0.0.0.0 / 127.0.0.1 / 255.255.255.255 같은 자리표시자·루프백은 IP 노출로 보지 않음
        if found.group(1) in ("0.0.0.0", "127.0.0.1", "255.255.255.255", "1.2.3.4"):
            return True
    return False


def _mk_finding(rule: dict, filename: str, lineno: int, line: str, lang: str = "") -> Finding:
    snippet = line.strip()
    if len(snippet) > 160:
        snippet = snippet[:160] + "…"
    loc = f"{filename}:{lineno}" if filename else f"line {lineno}"
    lang_tag = _LANG_LABEL.get(rule.get("lang", "common"), "")
    # KISA 시큐어코딩 매핑: (유형코드, 약점명)
    kisa = rule.get("kisa")
    if kisa:
        kcode, kname = kisa
        ktype = kisa_type_name(kcode)
        # control_code 에 KISA 유형코드를 함께 표기(예: "APP·K1")
        control_code = f"APP·{kcode}"
        # 설명 앞에 KISA 항목을 명시해 리포트·화면 어디서나 보이게 한다.
        kisa_line = f"[KISA {kcode} {ktype}] {kname}"
        description = f"{kisa_line}\n{rule['why']}"
    else:
        control_code = "APP"
        description = rule["why"]
    return Finding(
        control_code=control_code,
        control_domain=f"애플리케이션 보안(간이 SAST · {lang_tag})",
        issue_type=f"sast_{rule['id']}",
        severity=Severity.from_name(rule["sev"]),
        title=f"{rule['label']} ({loc})",
        description=description,
        recommendation=rule["fix"],
        evidence=f"{loc}  {snippet}",
        resource=filename or "(소스코드)",
        location=loc,
        platform="appsec",
        bad_example=rule["bad"],
        good_example=rule["good"],
        why=description,
        how_to_fix=rule["fix"],
    )


def scan_source(text: str, filename: str = "", lang: str = "auto") -> list[Finding]:
    """소스코드 텍스트를 줄 단위로 스캔해 위험 패턴 Finding 목록을 반환.

    Args:
        text: 소스코드 텍스트.
        filename: 파일명(언어 자동감지·위치표기에 사용).
        lang: "auto"(자동감지) | "python" | "js" | "html" | "sql" | "all".

    주석 줄(#, //, --, *, <!--)로 시작하는 라인은 오탐을 줄이기 위해 건너뛴다(단순 휴리스틱).
    """
    findings: list[Finding] = []
    if not text:
        return findings
    lang = (lang or "auto").lower()
    if lang == "auto":
        lang = detect_language(filename, text)
    applicable = [r for r in _SAST_RULES if _rule_applies(r, lang)]
    for i, raw in enumerate((text or "").splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        # 순수 주석 줄은 스킵(오탐 감소). 코드 뒤 인라인 주석은 스캔 유지.
        # 파이썬 #, C/JS //, SQL --, HTML <!--, 블록주석 *
        if (stripped.startswith("#") or stripped.startswith("//") or
                stripped.startswith("*") or stripped.startswith("--") or
                stripped.startswith("<!--")):
            continue
        for rule in applicable:
            m = rule["re"].search(raw)
            if m and not _false_positive(rule, raw, m):
                findings.append(_mk_finding(rule, filename, i, raw, lang))
    return findings


def check_waf(text: str, platform: str = "aws") -> list[Finding]:
    """WAF 구성(JSON/텍스트)을 받아 활성화·관리형 룰셋 적용 여부를 점검.

    입력에 WAF 관련 흔적이 전혀 없으면 '설정 확인 필요' 안내 Finding 1건을 준다.
    """
    platform = (platform or "aws").lower()
    findings: list[Finding] = []
    if not text or not text.strip():
        return findings
    has_hint = bool(_WAF_ACTIVE_HINTS.search(text))
    enabled = bool(_WAF_ENABLED.search(text))
    managed = bool(_WAF_MANAGED_RULES.search(text))

    if not has_hint:
        findings.append(Finding(
            control_code="2.6.7",
            control_domain="접근통제(경계 보안)",
            issue_type="waf_not_found",
            severity=Severity.MEDIUM,
            title="WAF 구성 흔적이 확인되지 않음 — 웹 방화벽 적용 여부 확인 필요",
            description=("입력한 구성에서 WAF(AWS WAFv2 / Azure Front Door·Application Gateway WAF) "
                         "설정을 찾지 못했습니다. 인터넷에 노출된 웹 서비스라면 WAF 미적용일 수 있습니다."),
            recommendation=("웹 애플리케이션 앞단에 WAF를 배치하고 관리형 룰셋(OWASP/Core Rule Set)을 "
                            "적용하세요. 이미 적용했다면 WAF 구성 출력을 포함해 다시 점검하세요."),
            evidence="(입력에서 WAF 관련 키워드 미검출)",
            resource="(웹 경계)",
            platform=platform,
            why="WAF가 없으면 SQL 인젝션·XSS 등 웹 공격을 애플리케이션이 그대로 받습니다.",
            how_to_fix=("AWS: WAFv2 WebACL 생성 후 ALB/CloudFront/API GW에 연결, AWSManagedRules 적용. "
                        "Azure: Front Door 또는 Application Gateway에 WAF 정책(Prevention 모드) 연결."),
        ))
        return findings

    if not enabled:
        findings.append(Finding(
            control_code="2.6.7",
            control_domain="접근통제(경계 보안)",
            issue_type="waf_not_enabled",
            severity=Severity.HIGH,
            title="WAF가 활성(Prevention/Enabled) 상태가 아님",
            description="WAF 구성은 있으나 활성화(Enabled)·차단(Prevention) 모드로 보이지 않습니다.",
            recommendation="WAF 정책을 Enabled/Prevention 모드로 전환해 실제 차단이 되도록 하세요(탐지만 하는 Detection 모드는 차단하지 않음).",
            evidence="(WAF 구성 존재하나 enabled/prevention 미확인)",
            resource="(WAF 정책)",
            platform=platform,
            why="탐지(Detection) 모드나 비활성 상태는 로그만 남기고 공격을 차단하지 않습니다.",
            how_to_fix="Azure: WAF Policy를 Prevention 모드로. AWS: WebACL 기본 동작·룰 액션을 Block으로 설정.",
        ))

    if not managed:
        findings.append(Finding(
            control_code="2.6.7",
            control_domain="접근통제(경계 보안)",
            issue_type="waf_no_managed_rules",
            severity=Severity.MEDIUM,
            title="WAF에 관리형 룰셋(OWASP/Core Rule Set)이 적용되지 않음",
            description="WAF는 있으나 관리형 룰셋(OWASP CRS·AWS Managed Rules 등) 적용 흔적이 없습니다.",
            recommendation="OWASP Top10을 커버하는 관리형 룰그룹을 적용하고, 오탐은 예외 규칙으로 조정하세요.",
            evidence="(managed rule set/OWASP 미확인)",
            resource="(WAF 정책)",
            platform=platform,
            why="관리형 룰셋 없이 커스텀 룰만으로는 알려진 웹 공격을 폭넓게 막기 어렵습니다.",
            how_to_fix="AWS: AWSManagedRulesCommonRuleSet 등 추가. Azure: Managed Rule Set(OWASP 3.2 등) 지정.",
        ))

    if enabled and managed and not findings:
        findings.append(Finding(
            control_code="2.6.7",
            control_domain="접근통제(경계 보안)",
            issue_type="waf_ok",
            severity=Severity.INFO,
            title="WAF 활성 + 관리형 룰셋 적용 확인(양호)",
            description="WAF가 활성 상태이고 관리형 룰셋이 적용된 것으로 보입니다.",
            recommendation="정기적으로 룰셋 버전 갱신·오탐 튜닝·로그 모니터링을 유지하세요.",
            evidence="(enabled + managed rule set 확인)",
            resource="(WAF 정책)",
            platform=platform,
            why="",
            how_to_fix="",
        ))
    return findings


def run(text: str, filename: str = "", platform: str = "aws", mode: str = "sast",
        lang: str = "auto") -> dict[str, Any]:
    """웹 UI/CLI 공용 진입점.

    Args:
        text: 소스코드(SAST) 또는 WAF 구성(waf) 텍스트.
        filename: 소스 파일명(있으면 언어 자동감지·위치 표기에 사용).
        platform: "aws" | "azure" (WAF 점검용).
        mode: "sast" | "waf" | "both".
        lang: "auto"(자동감지) | "python" | "js" | "html" | "sql" | "all".

    Returns:
        {ok, mode, platform, lang, total, severity_counts, findings:[to_dict...], notes:[...]}
    """
    mode = (mode or "sast").lower()
    lang = (lang or "auto").lower()
    findings: list[Finding] = []
    notes: list[str] = []
    detected = None
    if mode in ("sast", "both"):
        detected = detect_language(filename, text) if lang == "auto" else lang
        findings += scan_source(text, filename, lang=lang)
    if mode in ("waf", "both"):
        findings += check_waf(text, platform)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1

    if mode in ("sast", "both"):
        lang_note = _LANG_LABEL.get(detected or "unknown", "일반")
        if detected in (None, "unknown", "all"):
            notes.append("언어를 특정하지 못해 모든 규칙(Python/JS/HTML/SQL/공통)을 적용했습니다.")
        else:
            notes.append(f"감지된 언어: {lang_note} — 해당 언어 + 공통 규칙을 적용했습니다.")
        notes.append("간이 SAST는 정규식 기반 참고용 점검입니다(오탐/미탐 가능). 상용 정적분석을 대체하지 않습니다.")
    if mode in ("waf", "both"):
        notes.append("WAF 점검은 구성(설정) 확인이며, 실제 공격 시험(DAST)은 수행하지 않습니다.")

    # KISA 시큐어코딩 7대 유형별 집계(SAST 항목의 control_code "APP·K1"에서 유형코드 추출)
    kisa_counts: dict[str, int] = {}
    for f in findings:
        cc = f.control_code or ""
        if "·K" in cc:
            kcode = cc.split("·", 1)[1]
            kisa_counts[kcode] = kisa_counts.get(kcode, 0) + 1
    kisa_summary = [
        {"code": k, "type": kisa_type_name(k), "count": kisa_counts[k]}
        for k in sorted(kisa_counts)
    ]

    # 심각도 높은 순 정렬
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ordered = sorted(findings, key=lambda x: order.get(x.severity.name, 9))
    return {
        "ok": True,
        "mode": mode,
        "platform": platform,
        "lang": detected or lang,
        "total": len(findings),
        "severity_counts": counts,
        "kisa_summary": kisa_summary,
        "findings": [f.to_dict() for f in ordered],
        "notes": notes,
    }
