"""boto3 기반 AWS 수집기 (Lambda/서버리스용).

AWS CLI가 없는 환경(Lambda 기본 런타임 등)에서도 boto3(AWS SDK, Lambda에 기본 포함)로
실제 계정의 리소스 구성과 침해 신호를 수집한다. 결과는 기존 auditor.engine이 분석할 수
있는 JSON 텍스트로 반환한다.

- 각 수집은 독립적으로 try/except — 권한 부족·API 오류가 나도 나머지는 계속 진행.
- boto3가 없으면(로컬 등) 사용 불가 → available()가 False.
표준 라이브러리 + boto3만 사용(추가 패키징 불필요).

필요한 최소 읽기 권한(IAM): ec2:Describe*, rds:Describe*, s3:List*/GetBucket*,
iam:Get*/List*/GenerateCredentialReport, guardduty:List*/Get*.
"""

from __future__ import annotations

import json


def available() -> bool:
    try:
        import boto3  # noqa: F401
        return True
    except ImportError:
        return False


def _safe(fn, default=None):
    """AWS 호출 래퍼: 예외 시 default 반환(권한 부족 등에도 파이프라인 유지)."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - 어떤 API 오류든 건너뜀
        return default


def collect_config(region: str | None = None) -> list[dict]:
    """엔진이 탐지하는 리소스 구성을 boto3로 수집해 dict 목록으로 반환."""
    import boto3

    objs: list[dict] = []
    sess = boto3.session.Session(region_name=region) if region else boto3.session.Session()

    # ── EC2 보안그룹 (2.6.1) ──
    def _sg():
        ec2 = sess.client("ec2")
        out = []
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            out.append({
                "GroupId": sg.get("GroupId"),
                "GroupName": sg.get("GroupName"),
                "VpcId": sg.get("VpcId"),
                "OwnerId": sg.get("OwnerId"),
                "IpPermissions": sg.get("IpPermissions", []),
            })
        return out
    objs += _safe(_sg, []) or []

    # ── RDS 인스턴스 (2.6.1/2.7.1) ──
    def _rds():
        rds = sess.client("rds")
        out = []
        for db in rds.describe_db_instances().get("DBInstances", []):
            out.append({
                "DBInstanceIdentifier": db.get("DBInstanceIdentifier"),
                "Engine": db.get("Engine"),
                "PubliclyAccessible": db.get("PubliclyAccessible"),
                "StorageEncrypted": db.get("StorageEncrypted"),
                "Endpoint": db.get("Endpoint"),
            })
        return out
    objs += _safe(_rds, []) or []

    # ── S3 버킷 퍼블릭 차단 상태 (2.7.1) ──
    def _s3():
        s3 = sess.client("s3")
        out = []
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets[:50]:  # 과도한 호출 방지(상위 50개)
            name = b.get("Name")
            pab = _safe(lambda: s3.get_public_access_block(Bucket=name)
                        .get("PublicAccessBlockConfiguration", {}), {})
            enc = _safe(lambda: s3.get_bucket_encryption(Bucket=name), None)
            out.append({
                "Name": name,
                "PublicAccessBlockConfiguration": pab or {
                    "BlockPublicAcls": False, "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
                "ServerSideEncryptionConfiguration": (None if enc is None else "configured"),
                "Encryption": (None if enc is None else "configured"),
            })
        return out
    objs += _safe(_s3, []) or []

    # ── IAM 계정 요약(루트 액세스키/MFA) (2.5.x) ──
    def _iam():
        iam = sess.client("iam")
        out = []
        summ = _safe(lambda: iam.get_account_summary().get("SummaryMap", {}), {}) or {}
        out.append({
            "AccountSummary": summ,
            "RootAccessKeysPresent": summ.get("AccountAccessKeysPresent"),
            "AccountMFAEnabled": summ.get("AccountMFAEnabled"),
        })
        return out
    objs += _safe(_iam, []) or []

    return objs


def collect_threats(region: str | None = None) -> list[dict]:
    """GuardDuty 등 침해 신호를 boto3로 수집(dict 목록)."""
    import boto3

    sess = boto3.session.Session(region_name=region) if region else boto3.session.Session()
    events: list[dict] = []

    def _guardduty():
        gd = sess.client("guardduty")
        out = []
        det_ids = gd.list_detectors().get("DetectorIds", [])
        for did in det_ids:
            fids = _safe(lambda: gd.list_findings(
                DetectorId=did,
                FindingCriteria={"Criterion": {"severity": {"GreaterThanOrEqual": 4}}}
            ).get("FindingIds", []), []) or []
            if not fids:
                continue
            details = _safe(lambda: gd.get_findings(DetectorId=did, FindingIds=fids[:20])
                            .get("Findings", []), []) or []
            for f in details:
                svc = f.get("Service", {})
                remote = (svc.get("Action", {}) or {}).get("networkConnectionAction", {}) \
                    .get("remoteIpDetails", {})
                out.append({
                    "Type": f.get("Type"),
                    "Severity": f.get("Severity"),
                    "Title": f.get("Title"),
                    "AccountId": f.get("AccountId"),
                    "Region": f.get("Region"),
                    "RemoteIp": remote.get("IpAddressV4", ""),
                    "service": "guardduty",
                })
        return out
    events += _safe(_guardduty, []) or []

    return events


def collect(region: str | None = None) -> dict:
    """boto3로 구성+침해 신호를 함께 수집.

    반환: {"text": 구성 JSON 텍스트, "threat_text": 침해 JSON 텍스트,
           "ran": 수집 항목 수, "source": "boto3"}
    """
    if not available():
        return {"text": "", "threat_text": "", "ran": 0, "source": "unavailable"}
    cfg_objs = collect_config(region)
    threat_objs = collect_threats(region)
    return {
        "text": json.dumps(cfg_objs, ensure_ascii=False, indent=2) if cfg_objs else "",
        "threat_text": json.dumps(threat_objs, ensure_ascii=False, indent=2) if threat_objs else "",
        "ran": len(cfg_objs) + len(threat_objs),
        "source": "boto3",
    }
