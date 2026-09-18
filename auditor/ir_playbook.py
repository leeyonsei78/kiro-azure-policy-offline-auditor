"""사고 대응(IR, Incident Response) 플레이북 생성기.

폐쇄망 전용 · 파이썬 표준 라이브러리만 사용.

이 모듈은 침해사고 유형을 고르면(또는 침해탐지 결과를 받으면)
ISMS-P '2.11 사고 예방 및 대응' 절차에 맞춘 단계별 대응 플레이북을 생성한다.

중요(범위 안내):
    이 도구는 대응 '절차·체크리스트·증거수집 명령어·보고서 양식'을 안내할 뿐,
    실제 격리·복구·법적 신고를 대신 수행하지 않는다. 실제 조치는 담당자가
    승인 절차에 따라 직접 수행해야 하며, 명령은 대상 환경에 맞게 조정이 필요하다.

설계:
    - PLAYBOOKS: 침해 유형별 시나리오 정의(리스트[dict]).
    - build_playbook(incident_type, platform): 단일 플레이북 dict 생성.
    - list_incident_types(): UI 선택용 유형 목록.
    - playbook_from_threats(events, platform): 침해탐지 이벤트 -> 관련 플레이북 묶음.
    - render_text(playbook): 사람이 읽기 좋은 텍스트(리포트/복사용).
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# 공통 6단계 골격 (ISMS-P 2.11 / NIST SP 800-61 대응 수명주기와 정렬)
#   1 준비/식별 → 2 분류·심각도 → 3 격리(확산 차단) → 4 증거 보전 →
#   5 근절·복구 → 6 사후(보고·재발방지)
# 각 플레이북은 이 골격 위에 유형별 상세 행동을 채운다.
# ---------------------------------------------------------------------------

# 플랫폼별 "증거 수집" 명령어(읽기 전용 위주). 실행은 담당자가 수행.
_EVIDENCE_CMDS: dict[str, dict[str, list[str]]] = {
    "account_compromise": {
        "aws": [
            "aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<USER> --max-results 50",
            "aws iam list-access-keys --user-name <USER>",
            "aws iam get-account-authorization-details > iam-snapshot.json",
        ],
        "azure": [
            "az monitor activity-log list --caller <UPN> --start-time <ISO8601> -o json > activity.json",
            "az ad user get-member-groups --id <UPN> -o json",
            "az role assignment list --assignee <UPN> --all -o json > role-assignments.json",
        ],
    },
    "data_exposure": {
        "aws": [
            "aws s3api get-bucket-acl --bucket <BUCKET>",
            "aws s3api get-bucket-policy --bucket <BUCKET>",
            "aws s3api get-public-access-block --bucket <BUCKET>",
            "aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=<BUCKET> --max-results 50",
        ],
        "azure": [
            "az storage account show -n <ACCOUNT> --query 'allowBlobPublicAccess'",
            "az storage container list --account-name <ACCOUNT> --query \"[?properties.publicAccess!=null]\" -o json",
            "az monitor activity-log list --resource-id <RESOURCE_ID> --start-time <ISO8601> -o json > activity.json",
        ],
    },
    "privilege_abuse": {
        "aws": [
            "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy --max-results 50",
            "aws iam get-account-authorization-details > iam-snapshot.json",
            "aws organizations list-accounts",
        ],
        "azure": [
            "az role assignment list --all --include-inherited -o json > role-assignments.json",
            "az monitor activity-log list --offset 24h --query \"[?contains(operationName.value,'roleAssignments')]\" -o json",
        ],
    },
    "malware_host": {
        "aws": [
            "aws ec2 describe-instances --instance-ids <INSTANCE_ID> -o json > instance.json",
            "aws ec2 create-snapshot --volume-id <VOLUME_ID> --description 'IR-forensic-<INCIDENT_ID>'",
            "aws ec2 describe-flow-logs --filter Name=resource-id,Values=<VPC_ID>",
        ],
        "azure": [
            "az vm show -g <RG> -n <VM> -d -o json > vm.json",
            "az snapshot create -g <RG> -n ir-<INCIDENT_ID> --source <OS_DISK_ID>",
            "az network watcher flow-log show --location <REGION> -o json",
        ],
    },
    "ransomware": {
        "aws": [
            "aws backup list-recovery-points-by-backup-vault --backup-vault-name <VAULT>",
            "aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[].[SnapshotId,StartTime]'",
            "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteObject --max-results 50",
        ],
        "azure": [
            "az backup recoverypoint list -g <RG> -v <VAULT> -c <CONTAINER> -i <ITEM> -o json",
            "az snapshot list -g <RG> -o table",
            "az monitor activity-log list --offset 24h --query \"[?contains(operationName.value,'delete')]\" -o json",
        ],
    },
    "ddos": {
        "aws": [
            "aws cloudwatch get-metric-statistics --namespace AWS/ApplicationELB --metric-name RequestCount --start-time <ISO8601> --end-time <ISO8601> --period 60 --statistics Sum",
            "aws shield describe-protection --resource-arn <ARN>",
        ],
        "azure": [
            "az network ddos-protection show -g <RG> -n <PLAN> -o json",
            "az monitor metrics list --resource <RESOURCE_ID> --metric 'IfUnderDDoSAttack' -o json",
        ],
    },
}

# 침해 유형별 시나리오 정의.
PLAYBOOKS: list[dict[str, Any]] = [
    {
        "type": "account_compromise",
        "name": "계정 탈취 / 자격증명 유출",
        "severity": "CRITICAL",
        "isms_p": "2.11.2 취약점 점검 · 2.11.3 이상행위 분석 · 2.5.6 접근권한 검토",
        "mitre": "T1078 유효 계정(Valid Accounts)",
        "summary": "IAM 사용자·역할·서비스주체의 자격증명이 탈취되어 무단 접근·조작이 의심되는 상황.",
        "detect_signals": [
            "평소와 다른 국가/IP에서의 로그인",
            "짧은 시간 다수 로그인 실패 후 성공(무차별 대입 성공)",
            "MFA 없이 콘솔/CLI 접근, 액세스 키 신규 발급",
        ],
        "contain": [
            "의심 사용자의 콘솔 로그인·액세스 키를 즉시 비활성화(삭제가 아닌 '비활성화'로 증거 보전).",
            "탈취 의심 세션 무효화(임시 자격증명/토큰 취소).",
            "해당 계정에 부여된 과도 권한 임시 회수(최소권한 원칙).",
        ],
        "eradicate": [
            "모든 관련 자격증명(액세스 키·비밀번호·서비스주체 시크릿) 회전(재발급).",
            "MFA 강제 적용, 비정상 생성된 키/정책/역할 제거.",
            "침해 경로(피싱·유출된 코드·로그) 원인 제거.",
        ],
        "recover": [
            "정상 사용자에게 신규 자격증명 안전 채널로 재발급.",
            "권한을 사고 이전의 승인된 상태로 복원.",
            "모니터링 강화(비정상 로그인 알림) 후 정상 운영 재개.",
        ],
    },
    {
        "type": "data_exposure",
        "name": "스토리지/데이터 공개 노출",
        "severity": "CRITICAL",
        "isms_p": "2.6.1 접근통제 · 2.7.1 암호화 · 3.x 개인정보 보호",
        "mitre": "T1530 클라우드 스토리지 객체 접근",
        "summary": "S3 버킷·Blob 컨테이너 등이 인터넷에 공개되어 민감정보 유출이 의심되는 상황.",
        "detect_signals": [
            "public-read/공개 액세스 허용된 버킷·컨테이너",
            "외부에서의 대량 다운로드(GetObject) 급증",
            "개인정보·시크릿이 포함된 객체 노출",
        ],
        "contain": [
            "공개 액세스 즉시 차단(Public Access Block/allowBlobPublicAccess=false).",
            "노출 버킷/컨테이너 정책을 비공개로 전환, 필요 시 임시 접근 중단.",
            "노출된 객체 목록·접근 로그 확보(삭제 전 스냅샷).",
        ],
        "eradicate": [
            "유출된 데이터 범위 산정(무엇이·언제·누구에게).",
            "노출 원인(잘못된 정책/ACL) 교정, 조직 차원 공개 차단 정책 적용.",
            "노출 객체 내 시크릿이 있으면 해당 자격증명 회전.",
        ],
        "recover": [
            "데이터 분류·암호화 재적용, 접근권한 최소화 재구성.",
            "개인정보 유출이면 관련 법령상 통지·신고 절차 착수(법무/CISO 협의).",
            "버킷/컨테이너 상시 공개여부 점검 자동화.",
        ],
    },
    {
        "type": "privilege_abuse",
        "name": "권한 오남용 / 권한 상승",
        "severity": "HIGH",
        "isms_p": "2.5.6 접근권한 검토 · 2.6.2 정보시스템 접근",
        "mitre": "T1098 계정 조작 · T1548 권한 상승",
        "summary": "정상 계정이 과도 권한을 획득·사용하거나, 권한을 무단 부여·변경한 정황.",
        "detect_signals": [
            "AttachUserPolicy/roleAssignments 등 권한 변경 이벤트",
            "관리자(Administrator/Owner) 권한 신규 부여",
            "업무 범위를 벗어난 리소스 접근",
        ],
        "contain": [
            "무단 부여된 권한/정책 회수, 비정상 역할 할당 제거.",
            "관련 계정 활동 일시 제한 및 감사 강화.",
        ],
        "eradicate": [
            "권한 부여 경로(누가·어떻게) 추적, 취약한 위임/신뢰관계 제거.",
            "역할 신뢰정책·권한 경계(Permission Boundary) 재설계.",
        ],
        "recover": [
            "승인된 최소권한 상태로 복원, 권한 검토 주기 단축.",
            "권한 변경에 대한 승인·알림 통제 도입.",
        ],
    },
    {
        "type": "malware_host",
        "name": "악성코드 감염 인스턴스",
        "severity": "HIGH",
        "isms_p": "2.10.x 악성코드 통제 · 2.11.3 이상행위 분석",
        "mitre": "T1204 사용자 실행 · T1046 네트워크 스캐닝",
        "summary": "EC2/VM에서 악성 프로세스·비정상 아웃바운드(C2·코인채굴·포트스캔)가 관측된 상황.",
        "detect_signals": [
            "비정상 외부 통신(C2/채굴풀/스캔)",
            "GuardDuty/Defender 악성 탐지",
            "CPU 급증·미확인 프로세스",
        ],
        "contain": [
            "감염 인스턴스를 격리 보안그룹/NSG(모든 통신 차단)로 이동 — 종료 전 격리.",
            "종료·삭제 전에 디스크 스냅샷 생성(포렌식 증거 보전).",
            "동일 이미지/오토스케일링 그룹 확산 여부 확인.",
        ],
        "eradicate": [
            "감염 원인(취약 서비스·자격증명·이미지) 제거.",
            "감염 인스턴스는 재사용 금지 — 깨끗한 골든 이미지로 재프로비저닝.",
        ],
        "recover": [
            "정상 이미지·패치 적용본으로 재배포, 통신 제한 재검토.",
            "EDR/모니터링 강화 후 서비스 복귀.",
        ],
    },
    {
        "type": "ransomware",
        "name": "랜섬웨어 / 데이터 파괴",
        "severity": "CRITICAL",
        "isms_p": "2.9.x 백업 · 2.11.x 사고대응 · 2.12.x 재해복구",
        "mitre": "T1486 데이터 암호화(파괴) · T1490 복구 방해",
        "summary": "데이터가 대량 암호화·삭제되거나 백업/스냅샷 삭제 시도가 관측된 상황.",
        "detect_signals": [
            "대량 DeleteObject/삭제 이벤트",
            "백업 볼트·스냅샷 삭제 시도",
            "협박 메시지·확장자 변경",
        ],
        "contain": [
            "영향 리소스·계정 즉시 격리, 백업 볼트에 삭제 방지(Vault Lock/불변) 확인.",
            "추가 삭제 방지를 위해 관련 자격증명 비활성화.",
            "삭제 이벤트 로그·남은 복구지점 목록 확보.",
        ],
        "eradicate": [
            "침입 경로·악성 스크립트 제거, 침해 자격증명 회전.",
            "불변 백업 존재 여부 확인(없으면 복구 난이도 급증).",
        ],
        "recover": [
            "검증된 백업/스냅샷에서 단계적 복구(복구 전 무결성 검증).",
            "복구 후 재감염 방지 통제 적용, 백업 불변성·격리 강화.",
        ],
    },
    {
        "type": "ddos",
        "name": "DDoS / 서비스 거부",
        "severity": "HIGH",
        "isms_p": "2.6.7 인터넷 접속 통제 · 2.11.x 사고대응",
        "mitre": "T1498 네트워크 서비스 거부",
        "summary": "대량 트래픽으로 서비스 가용성이 저하되거나 중단된 상황.",
        "detect_signals": [
            "요청 수·대역폭 급증",
            "특정 소스/지역 집중 트래픽",
            "가용성 지표(5xx·지연) 악화",
        ],
        "contain": [
            "DDoS 보호(Shield/Front Door WAF·DDoS Protection) 활성 확인·강화.",
            "WAF 속도 제한(Rate limit)·지역/IP 차단 규칙 적용.",
            "오토스케일/캐시로 완충, 불필요 엔드포인트 노출 축소.",
        ],
        "eradicate": [
            "공격 패턴 분석(시그니처·소스), 차단 규칙 정교화.",
            "원본(Origin) 직접 노출 제거(엣지/프록시 뒤로).",
        ],
        "recover": [
            "정상 트래픽 확인 후 임시 차단 규칙 완화.",
            "용량·보호 수준 재평가 및 상시 방어 구성.",
        ],
    },
]

_BY_TYPE = {p["type"]: p for p in PLAYBOOKS}

# 위협탐지(threat.py) threat_type -> 플레이북 type 매핑.
_THREAT_TO_PLAYBOOK = {
    "guardduty_finding": "malware_host",
    "defender_alert": "malware_host",
    "root_activity": "privilege_abuse",
    "admin_activity": "privilege_abuse",
    "brute_force": "account_compromise",
    "malicious_indicator": "malware_host",
}


def list_incident_types() -> list[dict[str, str]]:
    """UI 선택용 침해 유형 목록."""
    return [
        {"type": p["type"], "name": p["name"], "severity": p["severity"]}
        for p in PLAYBOOKS
    ]


def _report_template(pb: dict, platform: str) -> list[str]:
    """사고 보고서(타임라인) 양식."""
    return [
        "■ 사고 개요: (발생 일시 / 인지 경로 / 영향 범위)",
        f"■ 사고 유형: {pb['name']} ({pb['severity']})",
        f"■ 대상 플랫폼: {platform.upper()}",
        "■ 타임라인:",
        "   - 최초 발생(추정): ____",
        "   - 탐지/인지: ____",
        "   - 격리 조치: ____",
        "   - 근절/복구: ____",
        "   - 종결/보고: ____",
        "■ 조치 내역: (수행자 / 승인자 / 조치 내용)",
        "■ 영향 평가: (데이터·서비스·개인정보 영향)",
        f"■ ISMS-P 관련 항목: {pb['isms_p']}",
        "■ 재발 방지 대책: (원인 / 개선 / 이행 기한)",
        "■ 대외 신고 여부: (개인정보 유출 시 관련 법령상 통지·신고 검토)",
    ]


def build_playbook(incident_type: str, platform: str = "aws") -> dict[str, Any]:
    """단일 침해 유형에 대한 6단계 대응 플레이북 생성.

    Args:
        incident_type: PLAYBOOKS의 type 값.
        platform: "aws" | "azure" (증거수집 명령어 선택).

    Returns:
        UI/리포트에서 소비하는 dict.

    Raises:
        KeyError: 알 수 없는 incident_type.
    """
    platform = (platform or "aws").lower()
    if platform not in ("aws", "azure"):
        platform = "aws"
    pb = _BY_TYPE[incident_type]
    evidence = _EVIDENCE_CMDS.get(incident_type, {}).get(platform, [])
    steps = [
        {"phase": "1. 준비·식별", "actions": [
            "사고대응 담당자·연락체계(CISO/보안팀) 가동, 사고 ID 부여.",
            "무엇을 근거로 사고로 판단했는지 탐지 신호 기록.",
        ] + [f"탐지 신호: {s}" for s in pb["detect_signals"]]},
        {"phase": "2. 분류·심각도", "actions": [
            f"사고 유형 확정: {pb['name']}",
            f"심각도 판정: {pb['severity']} (영향 범위·데이터 민감도 고려)",
            f"관련 MITRE ATT&CK: {pb['mitre']}",
        ]},
        {"phase": "3. 격리(확산 차단)", "actions": list(pb["contain"])},
        {"phase": "4. 증거 보전", "actions": [
            "조치 전 현재 상태를 스냅샷·로그로 보전(삭제보다 비활성화 우선).",
            "아래 증거수집 명령을 담당자가 검토 후 실행(값은 실제로 치환).",
        ]},
        {"phase": "5. 근절·복구", "actions": list(pb["eradicate"]) + ["— 복구 —"] + list(pb["recover"])},
        {"phase": "6. 사후(보고·재발방지)", "actions": [
            "사고 보고서 작성(아래 양식) 및 경영진·관계기관 보고 검토.",
            "원인 분석 기반 재발방지 대책 수립·이행 점검.",
            f"ISMS-P {pb['isms_p']} 항목에 근거해 통제 보완.",
        ]},
    ]
    return {
        "type": pb["type"],
        "name": pb["name"],
        "severity": pb["severity"],
        "platform": platform,
        "summary": pb["summary"],
        "isms_p": pb["isms_p"],
        "mitre": pb["mitre"],
        "steps": steps,
        "evidence_commands": evidence,
        "report_template": _report_template(pb, platform),
        "disclaimer": ("이 플레이북은 대응 절차 안내용입니다. 실제 격리·복구·신고는 "
                       "담당자가 승인 절차에 따라 직접 수행해야 하며, 명령은 대상 환경에 "
                       "맞게 조정하세요."),
    }


def playbook_from_threats(events: list, platform: str = "aws") -> dict[str, Any]:
    """침해탐지 이벤트(threat.ThreatEvent 또는 dict) 목록에서 관련 플레이북 묶음 생성.

    같은 유형은 중복 제거하고, 심각도 높은 순으로 정렬한다.
    """
    types: list[str] = []
    for ev in events or []:
        ttype = getattr(ev, "threat_type", None)
        if ttype is None and isinstance(ev, dict):
            ttype = ev.get("threat_type")
        mapped = _THREAT_TO_PLAYBOOK.get(ttype or "")
        if mapped and mapped not in types:
            types.append(mapped)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    playbooks = [build_playbook(t, platform) for t in types]
    playbooks.sort(key=lambda p: order.get(p["severity"], 9))
    return {"count": len(playbooks), "platform": platform, "playbooks": playbooks}


def render_text(pb: dict[str, Any]) -> str:
    """플레이북을 사람이 읽기 좋은 텍스트로(복사·리포트용)."""
    lines: list[str] = []
    lines.append(f"[사고 대응 플레이북] {pb['name']} ({pb['severity']}) — {pb['platform'].upper()}")
    lines.append(f"개요: {pb['summary']}")
    lines.append(f"ISMS-P: {pb['isms_p']}")
    lines.append(f"MITRE ATT&CK: {pb['mitre']}")
    lines.append("")
    for step in pb["steps"]:
        lines.append(f"[{step['phase']}]")
        for a in step["actions"]:
            lines.append(f"  - {a}")
        lines.append("")
    if pb["evidence_commands"]:
        lines.append("[증거 수집 명령어] (담당자 검토 후 실행, 값은 실제로 치환)")
        for c in pb["evidence_commands"]:
            lines.append(f"  $ {c}")
        lines.append("")
    lines.append("[사고 보고서 양식]")
    for r in pb["report_template"]:
        lines.append(f"  {r}")
    lines.append("")
    lines.append(f"※ {pb['disclaimer']}")
    return "\n".join(lines)
