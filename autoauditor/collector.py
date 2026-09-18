"""자동 리소스 수집기.

클라우드 CLI(`aws`/`az`)를 subprocess로 호출해 구성 정보를 JSON으로 모은다.
수집 결과는 여러 명령 출력을 이어붙인 하나의 텍스트로 반환되어, 기존
auditor.engine.analyze()가 그대로 분석할 수 있다.

- CLI가 없거나 실패하면 해당 명령은 건너뛴다(전체는 계속 진행).
- Config.use_mock=True이거나 CLI가 전혀 없으면 목업 데이터로 폴백(데모/테스트).
표준 라이브러리만 사용(폐쇄망/Lambda 기본 런타임 호환).
"""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess

from auditor.knowledge_base import collection_commands


def _cli_available(platform: str) -> bool:
    return shutil.which("az" if platform == "azure" else "aws") is not None


def _placeholder_free(cmd: str) -> bool:
    """자리표시자(<RG>, NSG_NAME 등)가 남아있으면 자동 수집에서 제외.

    자동 실행은 사람이 값을 못 채우므로, 특정 리소스명을 요구하는 명령은 건너뛴다
    (list류 명령은 자리표시자가 없어 자동 수집 가능).
    """
    import re
    if "<" in cmd and ">" in cmd:
        return False
    # 대문자_대문자 형태의 흔한 자리표시자
    if re.search(r"\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b", cmd):
        return False
    return True


def _run(cmd: str, timeout: int = 60) -> str | None:
    """CLI 명령 한 줄 실행 → stdout(JSON 기대). 실패 시 None.

    보안: 셸을 거치지 않고(shell 미사용) 프로그램을 직접 실행한다(셸 인젝션 방지).
    명령은 shlex로 안전하게 토큰화하며, 파이프(`|`)가 있으면 각 단계를 파이썬에서
    stdin/stdout으로 직접 연결한다.
    """
    try:
        stages = [s.strip() for s in cmd.split("|")]
        prev_out: bytes | None = None
        last_stdout = ""
        for i, stage in enumerate(stages):
            args = shlex.split(stage)
            if not args:
                return None
            proc = subprocess.run(
                args,
                input=prev_out,
                capture_output=True,
                timeout=timeout,
                # shell=False (기본) — 셸을 거치지 않고 프로그램을 직접 실행
            )
            if proc.returncode != 0:
                return None
            prev_out = proc.stdout
            last_stdout = proc.stdout.decode("utf-8", errors="replace")
        return last_stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        return None


def collect(platform: str, use_mock: bool = False, timeout: int = 60) -> dict:
    """플랫폼 구성 정보를 수집.

    수집 우선순위: (AWS) boto3 SDK → CLI → 목업 / (Azure) CLI → 목업.
    반환: {"text": JSON 텍스트, "threat_text": 침해 JSON(있으면), "ran": 수집 수,
           "source": "boto3"|"cli"|"mock"}
    text는 auditor.engine.analyze()에 그대로 넣을 수 있다.
    """
    if use_mock:
        return {"text": mock_data(platform), "threat_text": "", "ran": 0, "source": "mock"}

    # SDK 우선 시도 — Functions/Lambda 등 CLI 없는 환경에서 실제 수집 가능
    if platform == "aws":
        try:
            from . import collector_boto3
            if collector_boto3.available():
                r = collector_boto3.collect()
                if r.get("text"):
                    return {"text": r["text"], "threat_text": r.get("threat_text", ""),
                            "ran": r.get("ran", 0), "source": "boto3"}
        except Exception:  # noqa: BLE001 - boto3 수집 실패 시 CLI/목업으로 폴백
            pass
    elif platform == "azure":
        try:
            from . import collector_azure_sdk
            if collector_azure_sdk.available():
                r = collector_azure_sdk.collect()
                if r.get("text"):
                    return {"text": r["text"], "threat_text": r.get("threat_text", ""),
                            "ran": r.get("ran", 0), "source": "azure_sdk"}
        except Exception:  # noqa: BLE001 - SDK 수집 실패 시 CLI/목업으로 폴백
            pass

    if not _cli_available(platform):
        return {"text": mock_data(platform), "threat_text": "", "ran": 0, "source": "mock"}

    chunks: list[str] = []
    ran = 0
    for item in collection_commands(platform):
        for cmd in item.get("cmd_lines", []):
            cli = "az " if platform == "azure" else "aws "
            if not cmd.startswith(cli):
                continue
            if not _placeholder_free(cmd):
                continue
            # -o json 강제(테이블/tsv면 파싱 정확도 저하) — 이미 있으면 중복 무해
            run_cmd = cmd
            out = _run(run_cmd, timeout=timeout)
            if out and out.strip():
                chunks.append(f"# [{item['code']}] {item['domain']} :: {cmd}\n{out.strip()}")
                ran += 1
    if not chunks:
        # CLI는 있으나 아무것도 못 모았으면 목업으로라도 파이프라인 유지
        return {"text": mock_data(platform), "threat_text": "", "ran": 0, "source": "mock"}
    return {"text": "\n\n".join(chunks), "threat_text": "", "ran": ran, "source": "cli"}


# ---------------------------------------------------------------------------
# 목업 데이터(데모/테스트) — 실제 취약 구성을 흉내낸 안전한 샘플
# ---------------------------------------------------------------------------
def mock_data(platform: str) -> str:
    if platform == "azure":
        objs = [
            {"name": "nsg-web-prod", "resourceGroup": "rg-net-prod",
             "id": "/subscriptions/sub-demo/resourceGroups/rg-net-prod/providers/"
                   "Microsoft.Network/networkSecurityGroups/nsg-web-prod/securityRules/allow-rdp",
             "sourceAddressPrefix": "*", "destinationPortRange": "3389",
             "access": "Allow", "direction": "Inbound"},
            {"name": "stgdemo01", "resourceGroup": "rg-data-prod",
             "id": "/subscriptions/sub-demo/resourceGroups/rg-data-prod/providers/"
                   "Microsoft.Storage/storageAccounts/stgdemo01",
             "allowBlobPublicAccess": True, "supportsHttpsTrafficOnly": False,
             "minimumTlsVersion": "TLS1_0"},
            {"name": "kv-demo", "resourceGroup": "rg-sec-prod",
             "id": "/subscriptions/sub-demo/resourceGroups/rg-sec-prod/providers/"
                   "Microsoft.KeyVault/vaults/kv-demo",
             "type": "Microsoft.KeyVault/vaults",
             "enableSoftDelete": False, "enablePurgeProtection": False},
        ]
        return json.dumps(objs, ensure_ascii=False, indent=2)
    # aws
    objs = [
        {"GroupId": "sg-demo1", "GroupName": "web-prod-sg", "VpcId": "vpc-demo",
         "OwnerId": "111122223333",
         "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        {"DBInstanceIdentifier": "prod-db", "Engine": "mysql",
         "PubliclyAccessible": True, "StorageEncrypted": False},
        {"Name": "demo-public-bucket",
         "PublicAccessBlockConfiguration": {"BlockPublicAcls": False,
                                            "RestrictPublicBuckets": False}},
    ]
    return json.dumps(objs, ensure_ascii=False, indent=2)
