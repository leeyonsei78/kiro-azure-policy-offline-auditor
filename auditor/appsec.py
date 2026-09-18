"""애플리케이션 보안 점검(간이 SAST) + WAF 설정 점검.

폐쇄망 전용 · 파이썬 표준 라이브러리(re)만 사용.

중요(범위·한계):
    - 이 스캐너는 정규식 기반 '간이(lightweight) SAST'로, 상용 정적분석 엔진을
      대체하지 않는다. 데이터 흐름(taint) 분석을 하지 않으므로 오탐/미탐이 있을 수
      있으며 결과는 '참고용'이다. 실제 위험 여부는 담당자가 코드 맥락으로 확인해야 한다.
    - DAST(실제 공격 수행)는 폐쇄망·안전상 수행하지 않는다. 대신 WAF 설정이
      켜져 있는지 '구성 점검'만 제공한다.

기능:
    - scan_source(text, filename=""): 소스코드 텍스트에서 위험 패턴 탐지 -> Finding 리스트.
    - check_waf(text, platform): WAF 구성 JSON을 받아 활성/룰셋 여부 점검 -> Finding 리스트.
    - run(text, filename, platform): 위 둘을 합쳐 결과 dict 반환(웹 UI/CLI 공용).
"""

from __future__ import annotations

import re
from typing import Any

from .models import Finding, Severity

# ---------------------------------------------------------------------------
# 간이 SAST 규칙: (issue_type, 라벨, 정규식, 심각도, 설명, 개선방안, 취약예, 개선예)
# 언어 우선순위: Python / JavaScript(Node) / 공통 설정. 오탐을 줄이기 위해 형태가
# 비교적 뚜렷한 것만 포함한다. 각 규칙은 '줄 단위'로 매칭한다.
# ---------------------------------------------------------------------------
_SAST_RULES: list[dict[str, Any]] = [
    {
        "id": "hardcoded_secret",
        "label": "하드코딩된 비밀번호/키",
        "re": re.compile(r"""(?ix)(password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*['"][^'"]{4,}['"]"""),
        "sev": "HIGH",
        "why": "소스코드에 비밀번호·API 키를 직접 적으면, 코드가 유출될 때 자격증명도 함께 노출됩니다.",
        "fix": "비밀값은 환경변수·비밀 관리 서비스(AWS Secrets Manager, Azure Key Vault)로 옮기고 코드에서 제거하세요.",
        "bad": 'password = "P@ssw0rd123"',
        "good": 'password = os.environ["DB_PASSWORD"]',
    },
    {
        "id": "sql_injection",
        "label": "SQL 인젝션 위험(문자열 결합 쿼리)",
        "re": re.compile(r"""(?ix)(select|insert|update|delete)\s+.*(\+\s*\w+|%\s*\(|%s\s*%|\.format\(|f['"])"""),
        "sev": "HIGH",
        "why": "쿼리에 외부 입력을 문자열로 이어 붙이면 공격자가 쿼리를 조작(SQL 인젝션)할 수 있습니다.",
        "fix": "파라미터 바인딩(플레이스홀더)이나 ORM을 사용하세요. 입력을 쿼리 문자열에 직접 넣지 마세요.",
        "bad": 'cursor.execute("SELECT * FROM users WHERE id=" + uid)',
        "good": 'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))',
    },
    {
        "id": "os_command_exec",
        "label": "OS 명령 실행(명령 인젝션 위험)",
        "re": re.compile(r"""(?ix)(os\.system|os\.popen|subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True|child_process\.(exec|execSync)\s*\()"""),
        "sev": "HIGH",
        "why": "외부 입력이 셸 명령에 들어가면 임의 명령이 실행(명령 인젝션)될 수 있습니다.",
        "fix": "shell=True를 피하고 인자를 리스트로 전달하세요. 입력은 화이트리스트로 검증하세요.",
        "bad": 'subprocess.run(f"ping {host}", shell=True)',
        "good": 'subprocess.run(["ping", host])  # 리스트 인자, shell 미사용',
    },
    {
        "id": "dangerous_eval",
        "label": "eval/exec 등 동적 코드 실행",
        "re": re.compile(r"""(?ix)(?<![.\w])(eval|exec)\s*\(|new\s+Function\s*\(|pickle\.loads\s*\(|yaml\.load\s*\((?![^)]*Loader)"""),
        "sev": "HIGH",
        "why": "eval/exec나 안전하지 않은 역직렬화는 외부 입력으로 임의 코드가 실행될 수 있습니다.",
        "fix": "eval/exec 사용을 제거하고, 역직렬화는 안전한 방식(json, yaml.safe_load)을 쓰세요.",
        "bad": "result = eval(user_input)",
        "good": "import json; result = json.loads(user_input)",
    },
    {
        "id": "weak_crypto",
        "label": "취약한 해시/암호 알고리즘",
        "re": re.compile(r"""(?ix)(hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*['"](MD5|SHA-1)['"]|createHash\s*\(\s*['"](md5|sha1)['"])"""),
        "sev": "MEDIUM",
        "why": "MD5·SHA-1은 충돌이 발견된 약한 알고리즘으로 무결성·비밀번호 보호에 부적합합니다.",
        "fix": "SHA-256 이상을 쓰고, 비밀번호는 bcrypt·scrypt·argon2 같은 전용 해시를 사용하세요.",
        "bad": "hashlib.md5(password.encode())",
        "good": "hashlib.sha256(data)  # 비밀번호는 bcrypt/argon2",
    },
    {
        "id": "insecure_random",
        "label": "예측 가능한 난수(보안용 부적합)",
        "re": re.compile(r"""(?ix)(?<![.\w])random\.(random|randint|choice|randrange)\s*\(|Math\.random\s*\("""),
        "sev": "LOW",
        "why": "일반 난수(random/Math.random)는 예측 가능해 토큰·비밀번호·세션에 쓰면 위험합니다.",
        "fix": "보안용 난수는 secrets 모듈(Python)·crypto.randomBytes(Node)를 사용하세요.",
        "bad": "token = random.randint(1000, 9999)",
        "good": "import secrets; token = secrets.token_hex(16)",
    },
    {
        "id": "tls_verify_disabled",
        "label": "TLS 인증서 검증 비활성화",
        "re": re.compile(r"""(?ix)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|InsecureSkipVerify\s*:\s*true)"""),
        "sev": "MEDIUM",
        "why": "TLS 검증을 끄면 중간자 공격(MITM)에 노출되어 통신이 가로채기·변조될 수 있습니다.",
        "fix": "인증서 검증을 활성화(verify=True)하고, 사설 CA는 신뢰 저장소에 등록하세요.",
        "bad": "requests.get(url, verify=False)",
        "good": "requests.get(url)  # 기본값 verify=True",
    },
    {
        "id": "debug_enabled",
        "label": "디버그 모드 활성화(운영 위험)",
        "re": re.compile(r"""(?ix)(debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1)"""),
        "sev": "LOW",
        "why": "운영에서 디버그 모드가 켜지면 상세 오류·대화형 콘솔로 내부 정보가 노출될 수 있습니다.",
        "fix": "운영 환경에서는 디버그를 끄고(Debug=False), 오류 상세는 로그로만 남기세요.",
        "bad": "app.run(debug=True)",
        "good": "app.run(debug=False)  # 운영",
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


def _mk_finding(rule: dict, filename: str, lineno: int, line: str) -> Finding:
    snippet = line.strip()
    if len(snippet) > 160:
        snippet = snippet[:160] + "…"
    loc = f"{filename}:{lineno}" if filename else f"line {lineno}"
    return Finding(
        control_code="APP",
        control_domain="애플리케이션 보안(간이 SAST)",
        issue_type=f"sast_{rule['id']}",
        severity=Severity.from_name(rule["sev"]),
        title=f"{rule['label']} ({loc})",
        description=rule["why"],
        recommendation=rule["fix"],
        evidence=f"{loc}  {snippet}",
        resource=filename or "(소스코드)",
        location=loc,
        platform="appsec",
        bad_example=rule["bad"],
        good_example=rule["good"],
        why=rule["why"],
        how_to_fix=rule["fix"],
    )


def scan_source(text: str, filename: str = "") -> list[Finding]:
    """소스코드 텍스트를 줄 단위로 스캔해 위험 패턴 Finding 목록을 반환.

    주석 줄(#, //)로 시작하는 라인은 오탐을 줄이기 위해 건너뛴다(단순 휴리스틱).
    """
    findings: list[Finding] = []
    if not text:
        return findings
    for i, raw in enumerate((text or "").splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        # 순수 주석 줄은 스킵(오탐 감소). 코드 뒤 인라인 주석은 스캔 유지.
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue
        for rule in _SAST_RULES:
            if rule["re"].search(raw):
                findings.append(_mk_finding(rule, filename, i, raw))
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


def run(text: str, filename: str = "", platform: str = "aws", mode: str = "sast") -> dict[str, Any]:
    """웹 UI/CLI 공용 진입점.

    Args:
        text: 소스코드(SAST) 또는 WAF 구성(waf) 텍스트.
        filename: 소스 파일명(있으면 위치 표기에 사용).
        platform: "aws" | "azure" (WAF 점검용).
        mode: "sast" | "waf" | "both".

    Returns:
        {ok, mode, total, severity_counts, findings:[to_dict...], notes:[...]}
    """
    mode = (mode or "sast").lower()
    findings: list[Finding] = []
    notes: list[str] = []
    if mode in ("sast", "both"):
        findings += scan_source(text, filename)
    if mode in ("waf", "both"):
        findings += check_waf(text, platform)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1

    if mode in ("sast", "both"):
        notes.append("간이 SAST는 정규식 기반 참고용 점검입니다(오탐/미탐 가능). 상용 정적분석을 대체하지 않습니다.")
    if mode in ("waf", "both"):
        notes.append("WAF 점검은 구성(설정) 확인이며, 실제 공격 시험(DAST)은 수행하지 않습니다.")

    # 심각도 높은 순 정렬
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ordered = sorted(findings, key=lambda x: order.get(x.severity.name, 9))
    return {
        "ok": True,
        "mode": mode,
        "platform": platform,
        "total": len(findings),
        "severity_counts": counts,
        "findings": [f.to_dict() for f in ordered],
        "notes": notes,
    }
