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
    """CLI 명령 한 줄 실행 → stdout(JSON 기대). 실패 시 None."""
    try:
        # 파이프(| base64 등)가 있으면 shell 필요
        use_shell = "|" in cmd
        proc = subprocess.run(
            cmd if use_shell else cmd.split(),
            shell=use_shell,
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def collect(platform: str, use_mock: bool = False, timeout: int = 60) -> dict:
    """플랫폼 구성 정보를 수집.

    반환: {"text": 이어붙인 JSON 텍스트, "ran": 실행된 명령 수, "source": "cli"|"mock"}
    text는 auditor.engine.analyze()에 그대로 넣을 수 있다.
    """
    if use_mock or not _cli_available(platform):
        return {"text": mock_data(platform), "ran": 0, "source": "mock"}

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
        return {"text": mock_data(platform), "ran": 0, "source": "mock"}
    return {"text": "\n\n".join(chunks), "ran": ran, "source": "cli"}


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
