"""Azure SDK 기반 수집기 (Azure Functions/서버리스용).

az CLI가 없는 환경(Azure Functions 등)에서도 Azure SDK로 실제 구독의 리소스 구성과
침해 신호를 수집한다. 결과는 기존 auditor.engine이 분석할 수 있는 JSON 텍스트로 반환한다.

- SDK 패키지가 없으면(available()=False) 상위(collector)가 CLI/목업으로 폴백한다.
- 각 수집은 try/except — 권한 부족·API 오류가 나도 나머지는 계속 진행.
- 인증: DefaultAzureCredential (Function App의 Managed Identity 자동 사용).
- 구독 ID는 AZURE_SUBSCRIPTION_ID 환경변수로 지정.

필요 최소 역할: 구독 Reader (+ 침해 경고 조회 시 Security Reader).
requirements.txt 에 azure-identity, azure-mgmt-network, azure-mgmt-storage,
azure-mgmt-sql, azure-mgmt-security 를 선언하면 배포 시 자동 설치됨.
"""

from __future__ import annotations

import json
import os


def available() -> bool:
    try:
        import azure.identity  # noqa: F401
        import azure.mgmt.network  # noqa: F401
        return True
    except ImportError:
        return False


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return default


def _credential():
    from azure.identity import DefaultAzureCredential
    return DefaultAzureCredential()


def collect_config(subscription_id: str | None = None) -> list[dict]:
    """구독의 NSG·Storage·SQL 구성을 SDK로 수집."""
    sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not sub:
        return []
    cred = _credential()
    objs: list[dict] = []

    # ── NSG 규칙 (2.6.1) ──
    def _nsg():
        from azure.mgmt.network import NetworkManagementClient
        net = NetworkManagementClient(cred, sub)
        out = []
        for nsg in net.network_security_groups.list_all():
            rg = ""
            if getattr(nsg, "id", None):
                parts = nsg.id.split("/")
                if "resourceGroups" in parts:
                    rg = parts[parts.index("resourceGroups") + 1]
            for rule in (nsg.security_rules or []):
                out.append({
                    "name": rule.name,
                    "resourceGroup": rg,
                    "id": rule.id,
                    "sourceAddressPrefix": rule.source_address_prefix,
                    "destinationPortRange": rule.destination_port_range,
                    "access": rule.access,
                    "direction": rule.direction,
                })
        return out
    objs += _safe(_nsg, []) or []

    # ── Storage 계정 (2.7.1) ──
    def _storage():
        from azure.mgmt.storage import StorageManagementClient
        st = StorageManagementClient(cred, sub)
        out = []
        for acct in st.storage_accounts.list():
            out.append({
                "name": acct.name,
                "id": acct.id,
                "allowBlobPublicAccess": getattr(acct, "allow_blob_public_access", None),
                "supportsHttpsTrafficOnly": getattr(acct, "enable_https_traffic_only", None),
                "minimumTlsVersion": getattr(acct, "minimum_tls_version", None),
            })
        return out
    objs += _safe(_storage, []) or []

    # ── SQL 서버 (2.6.1) ──
    def _sql():
        from azure.mgmt.sql import SqlManagementClient
        sql = SqlManagementClient(cred, sub)
        out = []
        for srv in sql.servers.list():
            out.append({
                "name": srv.name,
                "id": srv.id,
                "publicNetworkAccess": getattr(srv, "public_network_access", None),
            })
        return out
    objs += _safe(_sql, []) or []

    return objs


def collect_threats(subscription_id: str | None = None) -> list[dict]:
    """Defender for Cloud 보안 경고를 SDK로 수집."""
    sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not sub:
        return []
    cred = _credential()
    events: list[dict] = []

    def _alerts():
        from azure.mgmt.security import SecurityCenter
        sc = SecurityCenter(cred, sub)
        out = []
        for a in sc.alerts.list():
            out.append({
                "alertDisplayName": getattr(a, "alert_display_name", None) or getattr(a, "name", None),
                "severity": getattr(a, "severity", "Medium"),
                "status": getattr(a, "status", None),
                "alertType": getattr(a, "alert_type", None),
            })
        return out
    events += _safe(_alerts, []) or []

    return events


def collect(subscription_id: str | None = None) -> dict:
    """SDK로 구성+침해 신호를 함께 수집.

    반환: {"text", "threat_text", "ran", "source": "azure_sdk"|"unavailable"}
    """
    if not available():
        return {"text": "", "threat_text": "", "ran": 0, "source": "unavailable"}
    cfg_objs = collect_config(subscription_id)
    threat_objs = collect_threats(subscription_id)
    return {
        "text": json.dumps(cfg_objs, ensure_ascii=False, indent=2) if cfg_objs else "",
        "threat_text": json.dumps(threat_objs, ensure_ascii=False, indent=2) if threat_objs else "",
        "ran": len(cfg_objs) + len(threat_objs),
        "source": "azure_sdk",
    }
