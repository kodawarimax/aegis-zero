"""
Module 8: Attacker Intelligence, Evidence Log & Alerting (passive, legal-by-design)

Identifies the attacker ONLY from data the attacker sent to us, plus public registry lookups:
- Loopback hits (bait beacon opened on this Mac): resolves the LOCAL PROCESS that made the request
  via `lsof` on the client's source port (PID, command, executable path, parent PID, user).
  This is the realistic case: malware/infostealer on this Mac reading a bait file and calling its URL.
- Public IP hits: reverse DNS + RDAP (IP owner, network, country, abuse contact).
  Network lookups are OFF by default (set AEGIS_INTEL_NETWORK=1 to enable).
- HTTP fingerprint: hash of header order + User-Agent, plus attack-tool hints (curl, python-requests ...).

Never does: port scanning, exploitation, or any active probing of the attacker (legal risk).

Outputs:
- Tamper-evident evidence log (JSONL with SHA-256 hash chain)
- macOS notification + optional webhook (AEGIS_ALERT_WEBHOOK_URL, Slack/Discord-compatible)
- Abuse-report DRAFT (never sent automatically; human approval required)
- Optional attacker-facing legal warning banner (AEGIS_WARN_ATTACKER=1). Off by default because it
  reveals that the credential is a trap.
"""
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

TOOL_HINTS = {
    "curl": "curl（コマンドライン）",
    "wget": "wget（コマンドライン）",
    "python-requests": "Python requests（スクリプト）",
    "python-urllib": "Python urllib（スクリプト）",
    "aiohttp": "Python aiohttp（スクリプト）",
    "go-http-client": "Go製ツール",
    "powershell": "PowerShell",
    "node-fetch": "Node.js",
    "axios": "Node.js axios",
    "okhttp": "Java/Android",
    "headlesschrome": "ヘッドレスブラウザ（自動操作）",
    "sqlmap": "sqlmap（攻撃ツール）",
    "nuclei": "nuclei（スキャナ）",
    "nmap": "nmap（スキャナ）",
}

ATTACKER_WARNING_BANNER = (
    "WARNING / 警告: This access used a monitored decoy credential. Your request, IP address and "
    "client fingerprint have been recorded as evidence. Unauthorized access may violate applicable laws, "
    "including Japan's Act on the Prohibition of Unauthorized Computer Access. "
    "このアクセスは監視対象の囮認証情報を使用しており、IPアドレス・端末情報・リクエスト内容は証拠として記録されました。"
    "無権限のアクセスは不正アクセス禁止法等に抵触する可能性があります。"
)


def _run(cmd: List[str], timeout: float = 2.0) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return r.stdout or ""
    except Exception:
        return ""


def classify_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private or addr.is_link_local:
        return "private"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "reserved"
    return "public"


def parse_lsof_fields(output: str) -> List[Dict[str, str]]:
    """Parses `lsof -F pcL` output into [{pid, command, user}]."""
    procs: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in output.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            if cur:
                procs.append(cur)
            cur = {"pid": val}
        elif tag == "c":
            cur["command"] = val
        elif tag == "L":
            cur["user"] = val
    if cur:
        procs.append(cur)
    return procs


def _is_loopback_endpoint(endpoint: str, expected_port: Optional[int] = None) -> bool:
    host, sep, port_s = endpoint.rpartition(":")
    if not sep or not port_s.isdigit():
        return False
    if expected_port is not None and int(port_s) != expected_port:
        return False
    host_clean = host.strip("[]").split("%")[0]
    try:
        addr = ipaddress.ip_address(host_clean)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return addr.is_loopback
    except ValueError:
        return False


def parse_netstat_ano_port(output: str, client_port: int, server_pid: Optional[int] = None) -> Optional[str]:
    """Parses Windows `netstat -ano -p TCP` output to find the PID owning loopback:<client_port>."""
    candidates: List[str] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        local_addr, foreign_addr, state, pid = parts[1], parts[2], parts[3], parts[4]
        if state.upper() == "LISTENING" or not pid.isdigit():
            continue
        if _is_loopback_endpoint(local_addr, expected_port=client_port) and _is_loopback_endpoint(foreign_addr):
            candidates.append(pid)
    if not candidates:
        return None
    if server_pid is not None:
        non_server = [p for p in candidates if p != str(server_pid)]
        if non_server:
            return non_server[0]
    return candidates[0]


def parse_tasklist_csv(output: str) -> Optional[Dict[str, str]]:
    """Parses Windows `tasklist /FO CSV /NH` output into {command, pid}."""
    for row in csv.reader(io.StringIO(output.strip())):
        if len(row) >= 2 and row[1].strip().isdigit():
            return {"command": row[0].strip(), "pid": row[1].strip()}
    return None


def parse_rdap(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts owner/network/country/abuse e-mails from an RDAP IP response."""
    abuse: List[str] = []
    orgs: List[str] = []

    def walk(entities: Iterable[Dict[str, Any]]) -> None:
        for ent in entities or []:
            roles = ent.get("roles", []) or []
            vcard = ent.get("vcardArray", [None, []])
            props = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
            for prop in props:
                if not isinstance(prop, list) or len(prop) < 4:
                    continue
                if prop[0] == "email" and "abuse" in roles:
                    abuse.append(str(prop[3]))
                if prop[0] == "fn" and ("registrant" in roles or "administrative" in roles):
                    orgs.append(str(prop[3]))
            walk(ent.get("entities", []))

    walk(data.get("entities", []))
    return {
        "network_name": data.get("name"),
        "handle": data.get("handle"),
        "range": f"{data.get('startAddress', '?')} - {data.get('endAddress', '?')}",
        "country": data.get("country"),
        "organizations": sorted(set(orgs)),
        "abuse_emails": sorted(set(abuse)),
    }


class AttackerProfiler:
    """Passive attacker identification with per-source rate limiting and benign OS/Owner process filtering."""

    BENIGN_OWNER_AND_OS_DAEMONS = {
        "mds",
        "mdworker",
        "mdworker_shared",
        "spotlight",
        "backupd",
        "backupd-helper",
        "timemachine",
        "quicklookuiservice",
        "quicklooksatellite",
        "finder",
        "explorer.exe",
        "searchindexer.exe",
        "searchprotocolhost.exe",
    }

    def __init__(self, allow_network: Optional[bool] = None, rate_limit_seconds: float = 10.0):
        if allow_network is None:
            allow_network = os.environ.get("AEGIS_INTEL_NETWORK", "0") == "1"
        self.allow_network = allow_network
        self.rate_limit_seconds = rate_limit_seconds
        self._last_seen: Dict[str, float] = {}
        self._rdap_cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    @classmethod
    def is_benign_owner_or_os_process(cls, proc: Optional[Dict[str, Any]]) -> bool:
        """
        Returns True if the local process is a standard OS indexer/backup daemon (Spotlight, Time Machine, Windows Search)
        or the owner previewing files in Finder/Explorer/QuickLook, preventing false-positive alarms.
        """
        if not proc or not isinstance(proc, dict):
            return False
        for key in ("command", "executable", "parent_command"):
            raw = str(proc.get(key) or "").strip()
            if not raw:
                continue
            base = raw.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if base in cls.BENIGN_OWNER_AND_OS_DAEMONS:
                return True
        return False

    def should_profile(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last_seen.get(ip)
            if last is not None and now - last < self.rate_limit_seconds:
                return False
            self._last_seen[ip] = now
            return True

    @staticmethod
    def resolve_local_process(client_port: int, server_pid: Optional[int] = None) -> Optional[Dict[str, str]]:
        """Finds the local process owning the TCP source port of a loopback connection (macOS/Linux + Windows)."""
        server_pid = server_pid if server_pid is not None else os.getpid()
        if sys.platform == "win32":
            net_out = _run(["netstat", "-ano", "-p", "TCP"])
            pid = parse_netstat_ano_port(net_out, client_port, server_pid=server_pid)
            if not pid:
                return None
            tl_out = _run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
            parsed = parse_tasklist_csv(tl_out) or {"pid": pid, "command": "unknown.exe"}
            parsed["executable"] = parsed.get("command", "")
            parsed["parent_pid"] = ""
            parsed["is_same_process_as_server"] = pid == str(server_pid)
            return parsed

        out = _run(["/usr/sbin/lsof", "-nP", f"-iTCP@127.0.0.1:{client_port}", "-F", "pcL"])
        procs = parse_lsof_fields(out)
        candidates = [p for p in procs if p.get("pid") != str(server_pid)] or procs
        if not candidates:
            return None
        proc = dict(candidates[0])
        pid = proc["pid"]
        proc["executable"] = _run(["/bin/ps", "-o", "comm=", "-p", pid]).strip()
        proc["parent_pid"] = _run(["/bin/ps", "-o", "ppid=", "-p", pid]).strip()
        if proc["parent_pid"]:
            proc["parent_command"] = _run(["/bin/ps", "-o", "comm=", "-p", proc["parent_pid"]]).strip()
        proc["is_same_process_as_server"] = pid == str(server_pid)
        return proc

    def lookup_public_ip(self, ip: str, fetcher: Optional[Callable[[str], Dict[str, Any]]] = None) -> Dict[str, Any]:
        if ip in self._rdap_cache:
            return self._rdap_cache[ip]
        result: Dict[str, Any] = {"reverse_dns": None, "rdap": None}
        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(2.0)
            result["reverse_dns"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(prev_timeout)

        def default_fetch(addr: str) -> Dict[str, Any]:
            req = urllib.request.Request(
                f"https://rdap.org/ip/{addr}",
                headers={"Accept": "application/rdap+json", "User-Agent": "Aegis-Zero-Intel/0.1"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            result["rdap"] = parse_rdap((fetcher or default_fetch)(ip))
        except Exception as exc:
            result["rdap_error"] = type(exc).__name__
        self._rdap_cache[ip] = result
        return result

    @staticmethod
    def http_fingerprint(header_items: List[Tuple[str, str]]) -> Dict[str, Any]:
        names = [k.lower() for k, _ in header_items]
        ua = next((v for k, v in header_items if k.lower() == "user-agent"), "")
        fp = hashlib.sha256(("|".join(names) + "||" + ua).encode("utf-8")).hexdigest()[:16]
        ua_l = ua.lower()
        tools = [label for key, label in TOOL_HINTS.items() if key in ua_l]
        return {
            "user_agent": ua or "(なし)",
            "header_order": names,
            "fingerprint": f"http_{fp}",
            "tool_hints": tools or (["UAなし（自作ツールの可能性）"] if not ua else []),
        }

    def profile(
        self,
        client_ip: str,
        client_port: int,
        header_items: List[Tuple[str, str]],
        server_pid: Optional[int] = None,
        rdap_fetcher: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        ip_class = classify_ip(client_ip)
        profile: Dict[str, Any] = {
            "client_ip": client_ip,
            "client_port": client_port,
            "ip_class": ip_class,
            "http": self.http_fingerprint(header_items),
            "local_process": None,
            "benign_owner_or_os_daemon": False,
            "network_owner": None,
            "summary": "",
        }
        if ip_class == "loopback":
            proc = self.resolve_local_process(client_port, server_pid)
            profile["local_process"] = proc
            profile["benign_owner_or_os_daemon"] = self.is_benign_owner_or_os_process(proc)
            if proc:
                profile["summary"] = (
                    f"このMac上のプロセス {proc.get('command', '?')} (PID {proc.get('pid')}, "
                    f"実行ファイル {proc.get('executable') or '?'}, 親 {proc.get('parent_command') or '?'}) が囮URLにアクセス"
                )
            else:
                profile["summary"] = "このMac上のプロセスからのアクセス（プロセス特定不可：接続が既に閉じた可能性）"
        elif ip_class == "public":
            if self.allow_network:
                owner = self.lookup_public_ip(client_ip, rdap_fetcher)
                profile["network_owner"] = owner
                rd = owner.get("rdap") or {}
                profile["summary"] = (
                    f"外部IP {client_ip}（{rd.get('network_name') or '?'} / {rd.get('country') or '?'}、"
                    f"逆引き {owner.get('reverse_dns') or 'なし'}）からのアクセス"
                )
            else:
                profile["summary"] = f"外部IP {client_ip} からのアクセス（登録情報照会はオフ：AEGIS_INTEL_NETWORK=1 で有効化）"
        else:
            profile["summary"] = f"{ip_class} アドレス {client_ip} からのアクセス（同一LAN内の機器の可能性）"
        return profile


class EvidenceLog:
    """Append-only JSONL evidence log with SHA-256 hash chaining (tamper-evident) and optional external anchor."""

    def __init__(self, path: Optional[str] = None, anchor_path: Optional[str] = None):
        if path is None:
            path = str(Path(__file__).resolve().parent.parent / "data" / "evidence" / "attack_log.jsonl")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ignore = self.path.parent / ".gitignore"
        if not ignore.exists():
            ignore.write_text("*\n", encoding="utf-8")
        self.anchor_path: Optional[Path] = Path(anchor_path) if anchor_path else None
        if self.anchor_path is not None:
            self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @classmethod
    def with_local_anchor(cls, path: Optional[str] = None, anchor_dir: Optional[str] = None) -> "EvidenceLog":
        """Creates an EvidenceLog backed by a separate out-of-directory trust anchor file (Personal/SMB zero-SIEM protection)."""
        resolved_path = Path(
            path or (Path(__file__).resolve().parent.parent / "data" / "evidence" / "attack_log.jsonl")
        ).resolve()
        base_anchor_dir = (
            Path(anchor_dir)
            if anchor_dir
            else (Path.home() / ".config" / "aegis-zero" / "anchors")
        )
        key = hashlib.sha256(str(resolved_path).encode("utf-8")).hexdigest()[:16]
        return cls(path=str(resolved_path), anchor_path=str(base_anchor_dir / f"evidence_{key}.anchor.json"))

    def _read_anchor(self) -> Optional[Dict[str, Any]]:
        if self.anchor_path is None or not self.anchor_path.exists():
            return None
        try:
            data = json.loads(self.anchor_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("entries"), int) and isinstance(data.get("head_hash"), str):
                return data
        except Exception:
            return {"entries": -1, "head_hash": "CORRUPT_ANCHOR"}
        return {"entries": -1, "head_hash": "CORRUPT_ANCHOR"}

    def _write_anchor(self, entries: int, head_hash: str) -> None:
        if self.anchor_path is None:
            return
        payload = json.dumps(
            {
                "entries": entries,
                "head_hash": head_hash,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        self.anchor_path.write_text(payload + "\n", encoding="utf-8")
        if sys.platform != "win32":
            try:
                os.chmod(self.anchor_path, 0o600)
            except Exception:
                pass

    @contextmanager
    def _file_lock(self):
        """Serialize cooperating writers, including other instances/processes."""
        with self.path.with_suffix(self.path.suffix + ".lock").open("a+b") as lock:
            if sys.platform == "win32":
                import msvcrt
                lock.seek(0, os.SEEK_END)
                if not lock.tell():
                    lock.write(b"\0")
                    lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if sys.platform == "win32":
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = ""
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        return json.loads(last)["entry_hash"] if last else "0" * 64

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, self._file_lock():
            chain_state = self._verify_chain_unlocked()
            if not chain_state["valid"]:
                raise ValueError("Refusing to append to a corrupt evidence chain")
            entry = {
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "prev_hash": self._last_hash(),
                "record": record,
            }
            body = json.dumps(entry, ensure_ascii=False, sort_keys=True)
            entry["entry_hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
            with self.path.open("a", encoding="utf-8") as f:
                # A valid externally supplied JSONL file may lack a final newline.
                if f.tell():
                    with self.path.open("rb") as existing:
                        existing.seek(-1, os.SEEK_END)
                        if existing.read(1) != b"\n":
                            f.write("\n")
                f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            if sys.platform == "win32":
                try:
                    username = os.environ.get("USERNAME", "")
                    if username:
                        subprocess.run(
                            ["icacls", str(self.path), "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                            capture_output=True,
                            timeout=2.0,
                            check=False,
                        )
                except Exception:
                    pass
            else:
                os.chmod(self.path, 0o600)
            self._write_anchor(chain_state["entries"] + 1, entry["entry_hash"])
            return entry

    def read_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock, self._file_lock():
            if not self.path.exists() or limit <= 0:
                return []
            if not self._verify_chain_unlocked()["valid"]:
                raise ValueError("Evidence chain is invalid")
            lines = [l for l in self.path.read_text(encoding="utf-8").split("\n") if l.strip()]
            return [json.loads(l) for l in lines[-limit:]][::-1]

    def verify_chain(self) -> Dict[str, Any]:
        with self._lock, self._file_lock():
            return self._verify_chain_unlocked()

    def _verify_chain_unlocked(self) -> Dict[str, Any]:
        anchor = self._read_anchor()
        if not self.path.exists():
            if anchor and anchor.get("entries", 0) > 0:
                return {
                    "valid": False,
                    "entries": 0,
                    "broken_at": 1,
                    "reason": "evidence_file_deleted_anchor_mismatch",
                }
            return {"valid": True, "entries": 0}
        prev = "0" * 64
        n = 0
        try:
            contents = self.path.read_text(encoding="utf-8")
        except UnicodeError:
            return {"valid": False, "entries": 0, "broken_at": 1, "reason": "invalid UTF-8"}
        for n, line in enumerate((l for l in contents.split("\n") if l.strip()), start=1):
            try:
                entry = json.loads(line)
            except (ValueError, TypeError):
                return {"valid": False, "entries": n, "broken_at": n, "reason": "invalid JSON"}
            if not isinstance(entry, dict):
                return {"valid": False, "entries": n, "broken_at": n, "reason": "invalid entry type"}
            claimed = entry.pop("entry_hash", "")
            if entry.get("prev_hash") != prev:
                return {"valid": False, "entries": n, "broken_at": n, "reason": "prev_hash mismatch"}
            calc = hashlib.sha256(json.dumps(entry, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
            if calc != claimed:
                return {"valid": False, "entries": n, "broken_at": n, "reason": "entry_hash mismatch"}
            prev = claimed
        if anchor is not None:
            if n != anchor.get("entries") or prev != anchor.get("head_hash"):
                return {
                    "valid": False,
                    "entries": n,
                    "broken_at": n,
                    "reason": "anchor_mismatch_tail_truncated_or_rehashed",
                }
        return {"valid": True, "entries": n}


class AlertNotifier:
    """Owner-facing alerts: supports silent background digest queuing (`silent_background_mode`) + desktop/webhook notifications."""

    def __init__(
        self,
        mac_notify: Optional[Callable[[str, str], None]] = None,
        webhook_url: Optional[str] = None,
        sender: Optional[Callable[[str, bytes], None]] = None,
        silent_background_mode: bool = False,
    ):
        self.mac_notify = mac_notify
        self.webhook_url = webhook_url if webhook_url is not None else os.environ.get("AEGIS_ALERT_WEBHOOK_URL", "")
        self.sender = sender
        self.silent_background_mode = silent_background_mode or (os.environ.get("AEGIS_SILENT_BACKGROUND", "0") == "1")
        self.silent_digest_queue: List[Dict[str, Any]] = []

    def _post(self, url: str, payload: bytes) -> None:
        if self.sender:
            self.sender(url, payload)
            return
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3.0).read()

    def notify(self, title: str, message: str, quiet: bool = False) -> Dict[str, Any]:
        is_quiet = quiet or self.silent_background_mode
        result: Dict[str, Any] = {"macos": False, "webhook": "disabled", "silent_queued": is_quiet}
        if is_quiet:
            self.silent_digest_queue.append(
                {
                    "recorded_at": datetime.now(timezone.utc).isoformat(),
                    "title": title,
                    "message": message,
                    "delivery": "SILENT_BACKGROUND_DIGEST",
                }
            )
            if len(self.silent_digest_queue) > 200:
                del self.silent_digest_queue[:-200]
            return result
        if self.mac_notify:
            try:
                self.mac_notify(title, message)
                result["macos"] = True
            except Exception:
                pass
        if self.webhook_url.startswith("https://"):
            text = f"{title}\n{message}"
            payload = json.dumps({"text": text, "content": text}, ensure_ascii=False).encode("utf-8")
            try:
                self._post(self.webhook_url, payload)
                result["webhook"] = "sent"
            except Exception as exc:
                result["webhook"] = f"failed:{type(exc).__name__}"
        return result


def build_abuse_report_draft(profile: Dict[str, Any], event_id: str, evidence_hash: str) -> Dict[str, Any]:
    """Creates an abuse-report draft. Never sent automatically."""
    owner = (profile.get("network_owner") or {}).get("rdap") or {}
    to = owner.get("abuse_emails") or []
    body = (
        f"Abuse report (draft) / 不正アクセス通報（下書き）\n"
        f"Event ID: {event_id}\n"
        f"Source IP: {profile.get('client_ip')} ({profile.get('ip_class')})\n"
        f"Network: {owner.get('network_name') or 'unknown'} / {owner.get('country') or 'unknown'}\n"
        f"User-Agent: {profile.get('http', {}).get('user_agent')}\n"
        f"Observed: use of a monitored decoy credential issued only to our own systems.\n"
        f"Evidence SHA-256: {evidence_hash}\n"
        f"Note: source IPs may be spoofed, shared (CGNAT/VPN/Tor) or compromised third-party hosts."
    )
    return {
        "status": "DRAFT_NOT_SENT",
        "requires_human_approval": True,
        "to": to,
        "applicable": profile.get("ip_class") == "public",
        "body": body,
    }
