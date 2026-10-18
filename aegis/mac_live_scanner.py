"""
Real-World Practical macOS & Windows Host Security Scanner + Live File Tripwire
Performs actual, non-destructive diagnostics on the host machine (macOS & Windows cross-platform):
- macOS: FileVault, Application Firewall, Gatekeeper, ~/.ssh Enclave audit, lsof listening ports
- Windows: BitLocker, Windows Defender Firewall, Microsoft Defender Realtime/Tamper protection,
           Explorer HideFileExt (PPAP double-extension defense), ~/.ssh audit, netstat listening ports
- Deploys real honey-token bait files on disk and triggers native Desktop Notifications (macOS osascript / Windows PowerShell)
"""
import base64
import hashlib
import ipaddress
import json
import locale
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


def default_trap_dir() -> str:
    if sys.platform == "win32":
        return str(Path(tempfile.gettempdir()) / "aegis-honey-trap")
    return "/tmp/aegis-honey-trap"


class RealMacSecurityScanner:
    """Executes real, safe, read-only OS & SSH security checks on both macOS and Windows."""

    def __init__(self, cmd_runner: Optional[Callable[[List[str]], str]] = None):
        self._cmd_runner = cmd_runner

    def _run_cmd(self, cmd: List[str], timeout: float = 2.5) -> str:
        if self._cmd_runner is not None:
            return self._cmd_runner(cmd)
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
            if res.returncode != 0:
                return ""
            def decode_output(data: bytes) -> str:
                if not data:
                    return ""
                if data.startswith((b"\xff\xfe", b"\xfe\xff")):
                    return data.decode("utf-16", errors="replace")
                encodings = ["utf-8-sig", locale.getpreferredencoding(False)]
                if sys.platform == "win32":
                    encodings.append("cp932")
                for encoding in encodings:
                    try:
                        return data.decode(encoding)
                    except UnicodeDecodeError:
                        continue
                return data.decode("utf-8", errors="replace")
            return decode_output(res.stdout) + decode_output(res.stderr)
        except Exception:
            return ""

    def _audit_ssh_directory(self, check_id: str = "MAC-SSH-04", is_windows: bool = False) -> Dict[str, Any]:
        ssh_dir = Path.home() / ".ssh"
        plaintext_keys: List[str] = []
        sock = os.environ.get("SSH_AUTH_SOCK", "").lower()
        enclave_agent_active = "secretive" in sock or "bitwarden" in sock or "1password" in sock

        if ssh_dir.exists() and ssh_dir.is_dir():
            for p in ssh_dir.iterdir():
                if p.is_file() and not p.name.endswith(".pub") and p.name not in (
                    "known_hosts",
                    "known_hosts.old",
                    "config",
                    "authorized_keys",
                ):
                    try:
                        head = p.read_text(encoding="utf-8", errors="ignore")[:512]
                        if "PRIVATE KEY-----" in head and "ENCRYPTED" not in head:
                            plaintext_keys.append(p.name)
                    except Exception:
                        pass

        remedy = (
            "Windows Hello 連携 (1Password SSH Agent / Bitwarden SSH Agent) またはパスフレーズ保護付き鍵へ移行し、平文秘密鍵を排除してください。"
            if is_windows
            else "Secretive (macOS Secure Enclave) または Bitwarden SSH Agent へ移行し、ディスク上の秘密鍵ファイルをゼロにしてください。"
        )
        if plaintext_keys:
            return {
                "id": check_id,
                "name": "SSH秘密鍵のハードウェア保護監査 (~/.ssh)",
                "status": "WARN",
                "severity": "HIGH",
                "detail": f"パスフレーズなし、または平文ファイル形式のSSH秘密鍵が {len(plaintext_keys)} 個見つかりました ({', '.join(plaintext_keys[:3])})",
                "action": remedy,
            }
        return {
            "id": check_id,
            "name": "SSH秘密鍵のハードウェア保護監査 (~/.ssh)",
            "status": "PASS",
            "severity": "LOW",
            "detail": "平文露出のSSH秘密鍵は検出されませんでした。" + (" (Hardware Agent稼働中)" if enclave_agent_active else ""),
            "action": "安全に管理されています。",
        }

    def scan_macos_posture(self) -> Dict[str, Any]:
        checks: List[Dict[str, Any]] = []

        # 1. FileVault (Disk Encryption)
        fdesetup_out = self._run_cmd(["/usr/bin/fdesetup", "status"])
        fv_on = "FileVault is On" in fdesetup_out
        checks.append(
            {
                "id": "MAC-FV-01",
                "name": "macOS FileVault (フルディスク暗号化)",
                "status": "PASS" if fv_on else "WARN",
                "severity": "LOW" if fv_on else "CRITICAL",
                "detail": fdesetup_out.strip() or "ステータス取得不可",
                "action": "システム設定 > プライバシーとセキュリティ > FileVault をオンにしてください" if not fv_on else "保護済み（PC盗難時もデータ抽出不可）",
            }
        )

        # 2. macOS Application Firewall
        fw_out = self._run_cmd(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        fw_on = "enabled" in fw_out.lower()
        checks.append(
            {
                "id": "MAC-FW-02",
                "name": "macOS アプリケーションファイアウォール",
                "status": "PASS" if fw_on else "WARN",
                "severity": "LOW" if fw_on else "HIGH",
                "detail": fw_out.strip() or "Disabled",
                "action": "システム設定 > ネットワーク > ファイアウォール をオンにしてください" if not fw_on else "有効（外部からの不正ポート接続を遮断中）",
            }
        )

        # 3. Gatekeeper
        gk_out = self._run_cmd(["/usr/sbin/spctl", "--status"])
        gk_on = "assessments enabled" in gk_out.lower()
        checks.append(
            {
                "id": "MAC-GK-03",
                "name": "Gatekeeper (未署名マルウェア実行防止)",
                "status": "PASS" if gk_on else "WARN",
                "severity": "LOW" if gk_on else "CRITICAL",
                "detail": gk_out.strip() or "Unknown",
                "action": "`sudo spctl --master-enable` で有効化してください" if not gk_on else "有効（公証のない不審アプリの起動を阻止）",
            }
        )

        # 4. SSH Key & Secure Enclave Audit (~/.ssh)
        checks.append(self._audit_ssh_directory(check_id="MAC-SSH-04", is_windows=False))

        # 5. Local Listening TCP Port Audit (Self-Inspection via lsof)
        lsof_listen = self._run_cmd(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        wildcard_ports: List[str] = []
        local_ports: List[str] = []
        for line in lsof_listen.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                proc_name, addr_port = parts[0], parts[8]
                entry = f"{proc_name}({addr_port})"
                if addr_port.startswith("*:") or addr_port.startswith("0.0.0.0:") or addr_port.startswith("[::]:"):
                    if entry not in wildcard_ports:
                        wildcard_ports.append(entry)
                else:
                    if entry not in local_ports:
                        local_ports.append(entry)

        if wildcard_ports:
            checks.append(
                {
                    "id": "MAC-PORT-05",
                    "name": "自機待受ポート監査 (lsof LISTEN検査)",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "detail": f"全インターフェース(*:)で待ち受け中のポートが {len(wildcard_ports)} 件あります: {', '.join(wildcard_ports[:4])}",
                    "action": "不要な外部公開サービスを停止するか、127.0.0.1（ループバック）またはTailscale IP限定バインドへ変更してください。",
                }
            )
        else:
            checks.append(
                {
                    "id": "MAC-PORT-05",
                    "name": "自機待受ポート監査 (lsof LISTEN検査)",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": f"外部全公開(*:)の待受ポートはありません（ローカル限定待受: {len(local_ports)} 件）",
                    "action": "最小権限のポート待受状態です。",
                }
            )

        return self._summarize_checks(checks, os_family="macos")

    def scan_windows_posture(self) -> Dict[str, Any]:
        """Executes real, read-only Windows 10/11 security posture checks."""
        checks: List[Dict[str, Any]] = []

        # 1. BitLocker Drive Encryption
        bl_out = self._run_cmd(["manage-bde", "-status", "C:"])
        bl_on = bool(re.search(r"(?im)^\s*(?:Protection Status\s*:\s*Protection On|保護(?:の)?状態\s*[:：]\s*保護はオン)\s*$", bl_out))
        checks.append(
            {
                "id": "WIN-BL-01",
                "name": "Windows BitLocker (C:ドライブ暗号化)",
                "status": "PASS" if bl_on else "WARN",
                "severity": "LOW" if bl_on else "CRITICAL",
                "detail": "BitLocker Protection On" if bl_on else (bl_out.strip()[:120] or "BitLocker 無効または未確認"),
                "action": "コントロールパネル > BitLocker ドライブ暗号化 を有効化してください" if not bl_on else "保護済み（PC盗難時もストレージ抽出不可）",
            }
        )

        # 2. Windows Defender Firewall
        fw_out = self._run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
        fw_states = re.findall(r"(?im)^\s*(?:State|状態)\s+(ON|OFF|オン|オフ)\s*$", fw_out)
        fw_on = len(fw_states) == 3 and all(state.upper() in ("ON", "オン") for state in fw_states)
        checks.append(
            {
                "id": "WIN-FW-02",
                "name": "Windows Defender ファイアウォール (全プロファイル)",
                "status": "PASS" if fw_on else "WARN",
                "severity": "LOW" if fw_on else "HIGH",
                "detail": "全プロファイル ON" if fw_on else (fw_out.strip()[:120] or "一部プロファイルがOFF"),
                "action": "`netsh advfirewall set allprofiles state on` で全プロファイルを有効化してください" if not fw_on else "有効（外部からの不正ポート接続を遮断中）",
            }
        )

        # 3. Microsoft Defender Antivirus Realtime & Tamper Protection
        def_out = self._run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,IsTamperProtected | ConvertTo-Json -Compress",
            ]
        )
        try:
            defender = json.loads(def_out)
        except (ValueError, TypeError):
            defender = {}
        rt_on = isinstance(defender, dict) and defender.get("RealTimeProtectionEnabled") is True
        tamper_on = isinstance(defender, dict) and defender.get("IsTamperProtected") is True
        def_pass = rt_on and tamper_on
        checks.append(
            {
                "id": "WIN-DEF-03",
                "name": "Microsoft Defender リアルタイム保護 ＆ 改ざん防止 (Infostealer対策)",
                "status": "PASS" if def_pass else "WARN",
                "severity": "LOW" if def_pass else ("HIGH" if rt_on else "CRITICAL"),
                "detail": def_out.strip()[:120] or "ステータス取得不可",
                "action": "Windows セキュリティ > ウイルスと脅威の防止 > リアルタイム保護と改ざん防止をオンにしてください" if not def_pass else "有効（Lumma/RedLine等の情報窃取型マルウェアを監視中）",
            }
        )

        # 4. Windows Explorer HideFileExt (PPAP / Double Extension .pdf.exe Disguise Prevention)
        reg_out = self._run_cmd(
            [
                "reg",
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                "/v",
                "HideFileExt",
            ]
        )
        ext_visible = bool(re.search(r"HideFileExt\s+REG_DWORD\s+0x0\b", reg_out, re.IGNORECASE))
        checks.append(
            {
                "id": "WIN-EXT-04",
                "name": "Windows 拡張子常時表示設定 (PPAP・二重拡張子 .pdf.exe 偽装防止)",
                "status": "PASS" if ext_visible else "WARN",
                "severity": "LOW" if ext_visible else "HIGH",
                "detail": "HideFileExt = 0x0 (拡張子を常に表示)" if ext_visible else "HideFileExt = 0x1 (既知の拡張子が非表示：.pdf.exe が .pdf に見えます)",
                "action": (
                    "安全です（二重拡張子マルウェアを視覚的に識別可能）"
                    if ext_visible
                    else "エクスプローラー > 表示 > 表示 > 「ファイル名拡張子」にチェックを入れるか、`reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v HideFileExt /t REG_DWORD /d 0 /f` を実行してください"
                ),
            }
        )

        # 5. SSH Keys (~/.ssh)
        checks.append(self._audit_ssh_directory(check_id="WIN-SSH-05", is_windows=True))

        # Do not filter TCP: Windows' TCP selector can exclude TCPv6 sockets.
        netstat_out = self._run_cmd(["netstat", "-ano"])
        wildcard_ports: List[str] = []
        local_ports: List[str] = []
        parsed_rows = 0
        malformed_listener = False
        for line in netstat_out.splitlines():
            parts = line.split()
            if parts and parts[0].upper() == "TCP" and len(parts) != 5:
                malformed_listener = True
                continue
            if len(parts) >= 5 and parts[0].upper() == "TCP":
                if parts[3].upper() not in {
                    "LISTENING", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT",
                    "SYN_RECEIVED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSING", "LAST_ACK",
                    "DELETE_TCB", "BOUND", "CLOSED",
                }:
                    malformed_listener = True
                    continue
                parsed_rows += 1
            if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[3].upper() == "LISTENING":
                local_addr, pid = parts[1], parts[4]
                entry = f"{local_addr}(PID:{pid})"
                try:
                    host, port = local_addr.rsplit(":", 1)
                    address = ipaddress.ip_address(host[1:-1] if host.startswith("[") and host.endswith("]") else host)
                    if not port.isascii() or not port.isdigit() or not 0 <= int(port) <= 65535 or not pid.isascii() or not pid.isdigit():
                        raise ValueError("Invalid netstat port or PID")
                    mapped = getattr(address, "ipv4_mapped", None)
                    is_loopback = (mapped or address).is_loopback
                except ValueError:
                    malformed_listener = True
                    continue
                if not is_loopback:
                    if entry not in wildcard_ports:
                        wildcard_ports.append(entry)
                else:
                    if entry not in local_ports:
                        local_ports.append(entry)

        if wildcard_ports:
            checks.append(
                {
                    "id": "WIN-PORT-06",
                    "name": "自機待受ポート監査 (netstat LISTENING検査)",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "detail": f"ループバック以外で待ち受け中のポートが {len(wildcard_ports)} 件あります: {', '.join(wildcard_ports[:4])}",
                    "action": "不要な外部公開サービス（SMB 445 / RDP 3389 等）を停止するか、ファイアウォールで遮断してください。",
                }
            )
        elif malformed_listener or (parsed_rows == 0 and not re.search(r"(?i)Proto\s+Local Address|プロトコル\s+ローカル", netstat_out)):
            checks.append({
                "id": "WIN-PORT-06", "name": "自機待受ポート監査 (netstat LISTENING検査)",
                "status": "WARN", "severity": "MEDIUM", "detail": "netstatの結果を確認できませんでした。",
                "action": "netstat -ano を実行し、待受状態を確認してください。",
            })
        else:
            checks.append(
                {
                    "id": "WIN-PORT-06",
                    "name": "自機待受ポート監査 (netstat LISTENING検査)",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": f"ループバック以外の待受ポートはありません（ローカル限定待受: {len(local_ports)} 件）",
                    "action": "最小権限のポート待受状態です。",
                }
            )

        return self._summarize_checks(checks, os_family="windows")

    @staticmethod
    def _summarize_checks(checks: List[Dict[str, Any]], os_family: str) -> Dict[str, Any]:
        passed = sum(1 for c in checks if c["status"] == "PASS")
        score = int((passed / len(checks)) * 100) if checks else 100
        return {
            "os_family": os_family,
            "posture_score": score,
            "total_checks": len(checks),
            "passed_checks": passed,
            "checks": checks,
        }

    def scan_host_posture(self, target_os: Optional[str] = None) -> Dict[str, Any]:
        effective_os = (target_os or sys.platform).lower()
        if effective_os.startswith("win"):
            return self.scan_windows_posture()
        return self.scan_macos_posture()


RealHostSecurityScanner = RealMacSecurityScanner


class LiveFileHoneyTrapManager:
    """
    Deploys real decoy files on disk (in a safe canary folder) and fires native
    macOS or Windows desktop notifications when a trap is touched.
    """

    def __init__(self, trap_dir: Optional[str] = None):
        self.trap_dir = Path(trap_dir or default_trap_dir())
        self.manifest_path = self.trap_dir / ".aegis_trap_manifest.json"

    def deploy_real_bait_files(self, server_port: int = 8765) -> List[Dict[str, str]]:
        if self.trap_dir.is_symlink():
            raise ValueError("Trap directory must not be a symlink")
        self.trap_dir.mkdir(parents=True, exist_ok=True)
        # Replace files atomically; never open a pre-existing symlink for writing.
        def write_bait(path: Path, content: str) -> None:
            if path.is_symlink():
                raise ValueError("Bait destination must not be a symlink")
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.trap_dir, delete=False) as handle:
                    temp_path = Path(handle.name)
                    handle.write(content)
                os.replace(temp_path, path)
            finally:
                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)
        now_ts = time.time()

        env_file = self.trap_dir / ".env.production.bait"
        aws_key = f"AKIA{secrets.token_hex(8).upper()}"
        sec_token = f"sbi_live_{secrets.token_hex(16)}"
        env_content = (
            f"# DO NOT COMMIT - PRODUCTION TREASURY CREDENTIALS\n"
            f"AWS_ACCESS_KEY_ID={aws_key}\n"
            f"AWS_SECRET_ACCESS_KEY={secrets.token_urlsafe(30)}\n"
            f"SBI_SECURITIES_API_TOKEN={sec_token}\n"
            f"INTERNAL_VAULT_VERIFY_URL=http://127.0.0.1:{server_port}/api/trap-beacon?token={sec_token}\n"
        )
        write_bait(env_file, env_content)

        wallet_file = self.trap_dir / "crypto_cold_wallet_backup.json"
        evm_priv = "0x" + secrets.token_hex(32)
        wallet_content = json.dumps(
            {
                "wallet_label": "Corporate Treasury Safe Signer #1 (50.0 ETH)",
                "network": "ethereum-mainnet",
                "private_key": evm_priv,
                "rpc_auth_endpoint": f"http://127.0.0.1:{server_port}/api/trap-beacon?token={evm_priv[:16]}",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        )
        write_bait(wallet_file, wallet_content)

        smb_file = self.trap_dir / "取引先_銀行振込口座_パスワード一覧.csv"
        smb_token = f"smb_keiri_{secrets.token_hex(12)}"
        smb_content = (
            "区分,金融機関・サービス名,ログインID,暗証番号・取引パスワード,ワンタイム認証確認URL\n"
            f"法人メイン口座,住信SBIネット銀行（法人第一営業部）,keiri-admin@example.co.jp,{secrets.token_urlsafe(16)},"
            f"http://127.0.0.1:{server_port}/api/trap-beacon?token={smb_token}\n"
            f"証券・資産運用,SBI証券（代表取締役個人・確定申告用）,owner-wealth@example.co.jp,{secrets.token_urlsafe(16)},"
            f"http://127.0.0.1:{server_port}/api/trap-beacon?token={smb_token}\n"
        )
        write_bait(smb_file, smb_content)

        baits = [
            {
                "id": "BAIT-ENV-01",
                "type": "証券・AWS本番環境変数トラップ",
                "path": str(env_file),
                "decoy_key": aws_key,
                "token": sec_token,
                "sha256": hashlib.sha256(env_content.encode("utf-8")).hexdigest(),
                "deployed_at": str(now_ts),
            },
            {
                "id": "BAIT-WALLET-02",
                "type": "仮想通貨50ETH秘密鍵バックアップトラップ",
                "path": str(wallet_file),
                "decoy_key": evm_priv[:14] + "...",
                "token": evm_priv,
                "sha256": hashlib.sha256(wallet_content.encode("utf-8")).hexdigest(),
                "deployed_at": str(now_ts),
            },
            {
                "id": "BAIT-SMB-03",
                "type": "個人・中小企業向け「取引先・銀行振込口座・確定申告パスワード」日本語おとりトラップ",
                "path": str(smb_file),
                "decoy_key": smb_token[:16] + "...",
                "token": smb_token,
                "sha256": hashlib.sha256(smb_content.encode("utf-8")).hexdigest(),
                "deployed_at": str(now_ts),
            },
        ]
        write_bait(self.manifest_path, json.dumps(baits, indent=2, ensure_ascii=False))
        return baits

    def get_deployed_baits(self) -> List[Dict[str, str]]:
        if not self.manifest_path.exists():
            return []
        try:
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    @staticmethod
    def send_macos_notification(title: str, message: str, play_sound: bool = False) -> None:
        """Sends a quiet native desktop banner on macOS (osascript) or Windows (PowerShell BalloonTip) without disruptive audio by default."""
        safe_title = re.sub(r"[\r\n\"'`]", " ", title)[:80]
        safe_msg = re.sub(r"[\r\n\"'`]", " ", message)[:200]
        if sys.platform == "win32":
            # Only base64 ASCII enters PowerShell source. Even smart quotes and
            # $() in untrusted notification text remain data after decoding.
            def ps_text(value: str) -> str:
                encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
                return f"([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')))"
            ps_script = (
                "Add-Type -AssemblyName System.Windows.Forms; "
                "Add-Type -AssemblyName System.Drawing; "
                "$n = New-Object System.Windows.Forms.NotifyIcon; "
                "$n.Icon = [System.Drawing.SystemIcons]::Warning; "
                "$n.Visible = $true; "
                f"$n.ShowBalloonTip(4000, {ps_text(title[:80])}, {ps_text(message[:200])}, [System.Windows.Forms.ToolTipIcon]::Warning);"
            )
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                    timeout=2.0,
                    check=False,
                )
            except Exception:
                pass
            return

        sound_clause = ' sound name "Sosumi"' if play_sound else ""
        script = f'display notification "{safe_msg}" with title "{safe_title}"{sound_clause}'
        try:
            subprocess.run(["/usr/bin/osascript", "-e", script], timeout=1.5, check=False)
        except Exception:
            pass
