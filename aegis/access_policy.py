"""
Host-side Access Policy (allowlist) for the Aegis-Zero dashboard.

Only the HOST (the Mac running Aegis-Zero) can change this policy, by editing a local file:
    ~/.config/aegis-zero/access.json   (override with env AEGIS_ACCESS_CONFIG)
The dashboard and remote devices can never modify it.

Fields:
  bind_address        : IP to listen on. Default 127.0.0.1. Use a Tailscale IP (100.x.y.z) for remote devices.
                        0.0.0.0 / :: are refused (would expose the dashboard to every network).
  port                : default 8765
  allowed_hosts       : Host-header names accepted (DNS-rebinding defense), e.g. "my-mac.tailnet.ts.net"
  allowed_client_ips  : client IPs / CIDR ranges allowed to use the dashboard, e.g. "100.101.102.103", "100.64.0.0/10"
  trusted_devices     : [{"name": "iPhone", "ip": "100.101.102.103"}]  (also added to allowed_client_ips)
  allowed_scan_paths  : folders the plaintext-secret scan may read, e.g. "~/", "/Volumes/Work"

CLI:
  python3 -m aegis.access_policy init        # create template (mode 600)
  python3 -m aegis.access_policy show        # print effective policy
  python3 -m aegis.access_policy check-path /some/folder
"""
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "aegis-zero" / "access.json"

_DEFAULT_SCAN_PATHS = list(
    dict.fromkeys(["~/", "/tmp/aegis-honey-trap", str(Path(tempfile.gettempdir()) / "aegis-honey-trap")])
)

TEMPLATE: Dict[str, Any] = {
    "bind_address": "127.0.0.1",
    "port": 8765,
    "allowed_hosts": ["127.0.0.1", "localhost"],
    "allowed_client_ips": ["127.0.0.1", "::1"],
    "trusted_devices": [],
    "allowed_scan_paths": _DEFAULT_SCAN_PATHS,
}


class AccessPolicyError(ValueError):
    pass


@dataclass
class AccessPolicy:
    bind_address: str = "127.0.0.1"
    port: int = 8765
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_networks: List[Any] = field(default_factory=list)
    trusted_devices: List[Dict[str, str]] = field(default_factory=list)
    allowed_scan_paths: List[Path] = field(default_factory=list)
    source: str = "defaults"
    warnings: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source: str = "dict") -> "AccessPolicy":
        merged = {**TEMPLATE, **(data or {})}
        warnings: List[str] = []

        try:
            bind = ipaddress.ip_address(str(merged["bind_address"]))
        except ValueError as exc:
            raise AccessPolicyError(f"bind_address が不正です: {merged['bind_address']}") from exc
        if bind.is_unspecified:
            raise AccessPolicyError("bind_address に 0.0.0.0 / :: は指定できません（全ネットワークへ公開されるため）")

        port = int(merged["port"])
        if not (1 <= port <= 65535):
            raise AccessPolicyError(f"port が不正です: {port}")

        networks = []
        devices: List[Dict[str, str]] = []
        for dev in merged.get("trusted_devices") or []:
            name, ip = str(dev.get("name", "device")), str(dev.get("ip", ""))
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise AccessPolicyError(f"trusted_devices の IP が不正です: {name}={ip}") from exc
            devices.append({"name": name, "ip": ip})
        for entry in list(merged.get("allowed_client_ips") or []) + [d["ip"] for d in devices]:
            try:
                networks.append(ipaddress.ip_network(str(entry), strict=False))
            except ValueError as exc:
                raise AccessPolicyError(f"allowed_client_ips の値が不正です: {entry}") from exc
        for net in networks:
            if net.prefixlen == 0:
                raise AccessPolicyError(f"全アドレスを許可する範囲は指定できません: {net}")

        if not bind.is_loopback:
            if not any(not n.network_address.is_loopback for n in networks):
                raise AccessPolicyError("ループバック以外で待ち受ける場合は、allowed_client_ips か trusted_devices に許可デバイスを登録してください")
            if not bind in ipaddress.ip_network("100.64.0.0/10"):
                warnings.append("Tailscale 以外のアドレスで待ち受けています。HTTPは暗号化されないため、同じネットワーク上で合言葉（トークン）を盗聴される恐れがあります。")

        hosts = {str(h).lower() for h in merged.get("allowed_hosts") or []}
        hosts.add(str(bind))
        if bind.is_loopback:
            hosts.update({"127.0.0.1", "localhost"})

        scan_paths = []
        for p in merged.get("allowed_scan_paths") or []:
            rp = Path(str(p)).expanduser().resolve()
            if rp == Path(rp.anchor):
                raise AccessPolicyError("allowed_scan_paths に / （ディスク全体）は指定できません")
            scan_paths.append(rp)

        return cls(
            bind_address=str(bind),
            port=port,
            allowed_hosts=sorted(hosts),
            allowed_networks=networks,
            trusted_devices=devices,
            allowed_scan_paths=scan_paths,
            source=source,
            warnings=warnings,
        )

    @classmethod
    def load(cls, path: Optional[str] = None) -> "AccessPolicy":
        cfg = Path(path or os.environ.get("AEGIS_ACCESS_CONFIG") or DEFAULT_CONFIG_PATH).expanduser()
        if not cfg.exists():
            return cls.from_dict({}, source="defaults (設定ファイルなし)")
        mode = cfg.stat().st_mode & 0o777
        policy = cls.from_dict(json.loads(cfg.read_text(encoding="utf-8")), source=str(cfg))
        if sys.platform != "win32" and (mode & 0o022):
            policy.warnings.append(f"{cfg} が他ユーザーから書き込み可能です（chmod 600 を推奨）")
        return policy

    # ---------- checks ----------
    def client_status(self, ip: str) -> Tuple[bool, Optional[str]]:
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False, None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        device = next((d["name"] for d in self.trusted_devices if ipaddress.ip_address(d["ip"]) == addr), None)
        allowed = any(addr.version == n.version and addr in n for n in self.allowed_networks)
        return allowed, device

    def host_allowed(self, host_header: str) -> bool:
        host = (host_header or "").strip().lower()
        return any(host == f"{'[' + name + ']' if ':' in name else name}:{self.port}"
                   for name in self.allowed_hosts)

    def allowed_origins(self) -> List[str]:
        return [f"http://{'[' + h + ']' if ':' in h else h}:{self.port}" for h in self.allowed_hosts]

    def path_allowed(self, path: str) -> Tuple[bool, Path]:
        try:
            if "\x00" in path:
                return False, Path(".")
            rp = Path(path).expanduser().resolve()
        except (OSError, ValueError, RuntimeError):
            return False, Path(".")
        return any(rp == r or r in rp.parents for r in self.allowed_scan_paths), rp

    def summary(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "bind_address": self.bind_address,
            "port": self.port,
            "allowed_hosts": self.allowed_hosts,
            "allowed_client_ips": [str(n) for n in self.allowed_networks],
            "trusted_devices": self.trusted_devices,
            "allowed_scan_paths": [str(p) for p in self.allowed_scan_paths],
            "warnings": self.warnings,
        }


def _main(argv: List[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "show"
    cfg = Path(os.environ.get("AEGIS_ACCESS_CONFIG") or DEFAULT_CONFIG_PATH).expanduser()
    if cmd == "init":
        if cfg.exists():
            print(f"既に存在します: {cfg}")
            return 1
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps(TEMPLATE, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(cfg, 0o600)
        print(f"作成しました: {cfg}（編集後、Aegis-Zero を再起動すると反映されます）")
        return 0
    try:
        policy = AccessPolicy.load()
    except AccessPolicyError as exc:
        print(f"設定エラー: {exc}")
        return 2
    if cmd == "check-path" and len(argv) > 2:
        ok, rp = policy.path_allowed(argv[2])
        print(f"{'許可' if ok else '拒否'}: {rp}")
        return 0 if ok else 1
    print(json.dumps(policy.summary(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
