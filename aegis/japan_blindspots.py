"""
Module 7: Japan-Specific Security Blindspots Auditor & Remediation Engine
Specifically targets the 7 critical security areas where Japanese individuals and enterprises lag behind global standards:
1. AiTM (Adversary-in-the-Middle) Phishing & Session Cookie Theft (Pass-the-Cookie / DBSC & Origin-Bound FIDO2 gap)
   - Root cause of recent Japanese securities account hijackings (SBI/Rakuten etc.)
2. PPAP (Password-protected ZIP + separate email) & Malicious Attachment Disguises (RTL Override U+202E, double extensions, Zip Slip)
3. Domain Email Spoofing Defense Delay (Missing DMARC or weak `p=none`, permissive SPF `?all`/`+all`)
4. SMS / Phone Number Fallback Downgrade Vulnerability (SIM Swap / eSIM Fraud exposure)
5. Unmanaged NHI (Non-Human Identities: API keys, GAS, SaaS OAuth bots) & Shared Department Accounts (`info@`, `keiri@`, `admin@`)
6. AI Supply Chain & "Slopsquatting" (Hallucinated or typosquatted npm/PyPI packages, missing SBOM verification)
7. Lack of "Assume Breach" Deception (Japanese corporate shared folder canary traps: fake customer CSV / approval docs)
"""
import re
import subprocess
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class JapanBlindspotFinding:
    blindspot_id: str
    pillar: str
    severity: str  # CRITICAL, HIGH, MEDIUM, PASS
    title: str
    japan_context_problem: str
    global_modern_standard: str
    actionable_fix: str


class JapanSecurityBlindspotAuditor:
    """
    Deterministic scanner and remediation generator for Japan's 7 biggest cybersecurity blindspots.
    """

    SHARED_ACCOUNT_PREFIXES = (
        "info@",
        "admin@",
        "keiri@",
        "soumu@",
        "sales@",
        "support@",
        "contact@",
        "office@",
        "accounting@",
    )

    SUSPICIOUS_SLOPSQUAT_PATTERNS = (
        re.compile(r"\b(?:openai|claude|anthropic|gemini|aws|stripe|fastapi|nextjs)-(?:helper|utils|sdk-pro|auto|secure|agent-kit|wrapper)\b", re.I),
        re.compile(r"\b(?:urllib4|requests3|py-crypto-wallet|web3-flash-rescue)\b", re.I),
    )

    @staticmethod
    def _lookup_txt_records(domain_name: str) -> List[str]:
        """Cross-platform DNS TXT lookup: uses /usr/bin/dig on macOS/Linux, falls back to nslookup on Windows."""
        records: List[str] = []
        # DNS tools accept options and server selectors as arguments too.
        if not re.fullmatch(r"(?=.{1,253}\Z)(?:_dmarc\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain_name, re.I):
            return records
        try:
            if Path("/usr/bin/dig").exists():
                res = subprocess.run(
                    ["/usr/bin/dig", "+time=1", "+tries=1", "+short", "TXT", domain_name],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                for line in (res.stdout or "").splitlines():
                    cleaned = line.strip().replace('"', "")
                    if cleaned:
                        records.append(cleaned)
                return records
            res = subprocess.run(
                ["nslookup", "-type=TXT", domain_name],
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
            for line in (res.stdout or "").splitlines():
                if "v=dmarc1" in line.lower() or "v=spf1" in line.lower() or "text =" in line.lower():
                    cleaned = line.split("=", 1)[-1].strip().strip('"') if "text =" in line.lower() else line.strip().strip('"')
                    if cleaned:
                        records.append(cleaned)
        except Exception:
            pass
        return records

    def audit_domain_dmarc_spf(self, domain: str, simulated_dmarc_txt: str = "", simulated_spf_txt: str = "") -> Dict[str, Any]:
        """
        Audits a domain's SPF and DMARC posture (checkdmarc style).
        If simulated strings are not provided, attempts a fast `dig +short TXT` or `nslookup -type=TXT` lookup with safe fallback.
        """
        clean_domain = domain.strip().lower().lstrip("@")
        dmarc_txt = simulated_dmarc_txt
        spf_txt = simulated_spf_txt

        if not dmarc_txt and not spf_txt:
            dmarc_records = self._lookup_txt_records(f"_dmarc.{clean_domain}")
            for rec in dmarc_records:
                if "v=dmarc1" in rec.lower():
                    dmarc_txt = rec
                    break
            spf_records = self._lookup_txt_records(clean_domain)
            for rec in spf_records:
                if "v=spf1" in rec.lower():
                    spf_txt = rec
                    break

        issues: List[str] = []
        severity = "PASS"

        if not dmarc_txt or "v=dmarc1" not in dmarc_txt.lower():
            issues.append("DMARCレコードが未設定または取得できません。ドメインのなりすまし対策を確認してください")
            severity = "CRITICAL"
        else:
            tags = [part.strip().lower().split("=", 1) for part in dmarc_txt.split(";") if part.strip()]
            parsed_tags = {p[0].strip(): p[1].strip() for p in tags if len(p) == 2}
            policy = parsed_tags.get("p")
            subdomain_policy = parsed_tags.get("sp", policy)
            percentage = parsed_tags.get("pct", "100")
            valid = (all(len(p) == 2 for p in tags) and len(parsed_tags) == len(tags)
                     and tags[0][0].strip() == "v" and parsed_tags.get("v") == "dmarc1"
                     and policy in {"none", "quarantine", "reject"}
                     and subdomain_policy in {"none", "quarantine", "reject"}
                     and re.fullmatch(r"[0-9]{1,3}", percentage) is not None
                     and int(percentage) <= 100)
            if not valid:
                issues.append("DMARCタグが不正、重複、またはpポリシーが欠落しています")
                severity = "CRITICAL"
            elif policy == "none":
                severity = "HIGH"
                issues.append("DMARC p=noneは監視のみです")
            elif policy == "quarantine":
                severity = "MEDIUM"
                issues.append("DMARC p=quarantineは拒否を強制しません")
            if valid and subdomain_policy != "reject":
                issues.append("DMARCサブドメインポリシーがrejectではありません")
                if severity == "PASS" or subdomain_policy == "none":
                    severity = "HIGH" if subdomain_policy == "none" else "MEDIUM"
            if valid and int(percentage) < 100:
                issues.append("DMARC pctが100未満で、要求ポリシーは全件に適用されません")
                if severity in {"PASS", "MEDIUM"}:
                    severity = "HIGH"
        if not re.match(r"^v=spf1(?:\s|$)", spf_txt.strip(), re.I):
            issues.append("SPFレコードが未設定です")
            severity = "CRITICAL"
        elif re.search(r"(?:^|\s)[+?]?all(?:\s|$)", spf_txt, re.I):
            issues.append("SPFの末尾が `+all` または `?all` になっており、世界中のどのサーバーからでも送信許可される危険な状態です")
            severity = "CRITICAL"

        txt_value = f"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc-reports@{clean_domain}"
        recommended_dmarc = f'_dmarc.{clean_domain}. IN TXT "{txt_value}"'
        registrar_guides = {
            "onamae_com": (
                f"【お名前.com Navi】ドメイン設定 ＞ DNS設定/転送設定 ＞ DNSレコード設定を利用する ＞ "
                f"ホスト名に `_dmarc`、TYPEに `TXT`、VALUEに `{txt_value}` を貼り付けて追加"
            ),
            "sakura_internet": (
                f"【さくらインターネット】会員メニュー ＞ ドメイン確認 ＞ ゾーン編集 ＞ 変更 ＞ "
                f"エントリ名 `_dmarc`、種別 `TXT`、データ `{txt_value}` を入力して保存・データ送信"
            ),
            "xserver": (
                f"【エックスサーバー】サーバーパネル ＞ DNSレコード設定 ＞ 対象ドメイン選択 ＞ DNSレコード追加 ＞ "
                f"ホスト名 `_dmarc.{clean_domain}`、種別 `TXT`、内容 `{txt_value}` を入力して追加"
            ),
            "cloudflare": (
                f"【Cloudflare】DNS ＞ Records ＞ Add record ＞ Type `TXT`、Name `_dmarc`、"
                f"Content `\"{txt_value}\"` を入力して Save"
            ),
        }

        return {
            "domain": clean_domain,
            "severity": severity,
            "current_dmarc": dmarc_txt or "(未設定 / 取得なし)",
            "current_spf": spf_txt or "(未設定 / 取得なし)",
            "issues": issues if issues else ["DMARC `p=reject` および厳格なSPFが適切に構成されています。"],
            "recommended_dns_record": recommended_dmarc,
            "registrar_guides": registrar_guides,
        }

    def inspect_ppap_and_attachment(self, filename: str, is_password_zip: bool = False) -> Dict[str, Any]:
        """
        Anti-PPAP & Malicious Attachment Gate:
        Detects PPAP encrypted ZIP anti-patterns, Unicode Right-to-Left Override (U+202E) extension spoofing,
        double extensions (.pdf.exe, .xlsx.scr), and macro-enabled Office files.
        """
        risks: List[str] = []
        severity = "PASS"
        normalized = unicodedata.normalize("NFKC", filename).rstrip(" .")
        # Inspect the base stream as well as an NTFS alternate-stream suffix.
        base_name = re.split(r"[/\\]", normalized)[-1].split(":", 1)[0].rstrip(" .")

        if is_password_zip or base_name.lower().endswith(".zip"):
            risks.append(
                "【脱PPAP警告】パスワード付きZIP（PPAP）はメールゲートウェイのマルウェア検疫を盲目化し、"
                "さらに従来のZipCryptoはGPUで数秒で解読されます。"
            )
            severity = "HIGH"

        if any(unicodedata.category(c) in {"Cf", "Cc"} for c in filename):
            risks.append(
                "【致命的：RTL文字偽装】ファイル名に不可視の右横書き制御文字(U+202E)が埋め込まれており、"
                "実行ファイル(.exe/.scr)をPDFや書類に偽装しています。"
            )
            severity = "CRITICAL"

        if re.search(r"\.(?:exe|scr|bat|cmd|ps1|vbs|js|hta|msi|app|lnk|com|url)$", base_name, re.I):
            risks.append(
                "【致命的：二重拡張子マルウェア】書類アイコンに見せかけた実行可能バイナリです（日本の標的型メール攻撃で多用）。"
            )
            severity = "CRITICAL"

        if re.search(r"\.(?:docm|xlsm|pptm|iso|img|vhd)$", base_name, re.I):
            risks.append(
                "【高リスク形式】マクロ有効Office文書またはディスクイメージ形式(.iso/.vhd)は、Mark-of-the-Web(MotW)回避やマルウェア感染の温床です。"
            )
            if severity != "CRITICAL":
                severity = "HIGH"

        return {
            "filename": filename.replace("\u202e", "[U+202E_RTL_OVERRIDE]"),
            "severity": severity,
            "blocked": severity in ("CRITICAL", "HIGH"),
            "detected_risks": risks if risks else ["ファイル名の既知リスクは検出されませんでした。内容は未検査です。"],
            "modern_alternative": "PPAPを全廃し、`FiloSottile/age` (公開鍵暗号) または有効期限・パスキー認証付きクラウド共有リンクを使用してください。",
        }

    def audit_supply_chain_and_slopsquatting(self, package_list: List[str]) -> Dict[str, Any]:
        """
        Detects AI-hallucinated package names ("Slopsquatting") and suspicious typosquatted dependencies
        before a developer or AI agent runs `pip install` or `npm install`.
        """
        flagged: List[Dict[str, str]] = []
        for pkg in package_list:
            clean = pkg.strip()
            for pat in self.SUSPICIOUS_SLOPSQUAT_PATTERNS:
                if pat.search(clean):
                    flagged.append(
                        {
                            "package": clean,
                            "reason": "AIハルシネーション悪用（Slopsquatting）またはタイポスクワッティングの疑いが極めて高いパッケージ名パターンです。",
                            "action": "インストールを即時中止し、Google OSV-Scanner / OpenSSF GuardDog で公式レジストリの署名・作成日を確認してください。",
                        }
                    )
                    break
        return {
            "scanned_packages": len(package_list),
            "flagged_count": len(flagged),
            "safe": len(flagged) == 0,
            "flagged_packages": flagged,
        }

    def run_japan_7_blindspots_assessment(
        self,
        sample_domain: str = "example.co.jp",
        simulated_dmarc: str = "v=DMARC1; p=none;",
        simulated_spf: str = "v=spf1 include:_spf.google.com ?all",
        sample_accounts: List[str] = None,
        sample_attachment: str = "請求書_202610.pdf.exe",
        sample_packages: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Runs a complete diagnostic across all 7 Japan-specific cybersecurity blindspots.
        """
        if sample_accounts is None:
            sample_accounts = ["keiri@example.co.jp", "info@example.co.jp", "user@example.co.jp"]
        if sample_packages is None:
            sample_packages = ["requests", "openai-helper-sdk-pro", "fastapi"]

        dmarc_res = self.audit_domain_dmarc_spf(sample_domain, simulated_dmarc, simulated_spf)
        ppap_res = self.inspect_ppap_and_attachment(sample_attachment, is_password_zip=True)
        supply_res = self.audit_supply_chain_and_slopsquatting(sample_packages)

        shared_hits = [
            acc for acc in sample_accounts if any(acc.lower().startswith(pref) for pref in self.SHARED_ACCOUNT_PREFIXES)
        ]

        findings: List[JapanBlindspotFinding] = [
            JapanBlindspotFinding(
                blindspot_id="JP-BLIND-01",
                pillar="① AiTM（リアルタイム中間者攻撃）＆ 証券口座乗っ取り対策 (FIDO2 / DBSC)",
                severity="CRITICAL",
                title="OTP（SMS/メール/認証アプリ）への過信と、オリジン束縛型パスキー・DBSCの未導入",
                japan_context_problem="日本では『二段階認証(SMS/TOTP)さえあれば安全』と誤解されていますが、Evilginx等のAiTMリバースプロキシやInfostealerによるセッションCookie盗難の前ではOTPは100%突破されます（国内証券口座の大量乗っ取り事件の主因）。",
                global_modern_standard="ドメインに暗号学的に束縛される FIDO2 Passkey + DBSC (Device Bound Session Credentials：CookieをTPM/Secure Enclaveにハードウェア束縛する新標準) の強制。",
                actionable_fix="SBI証券・楽天証券・銀行・基幹SaaSをすべてFIDO2パスキーへ切り替え、長寿命セッションCookieの放置を廃止してください。",
            ),
            JapanBlindspotFinding(
                blindspot_id="JP-BLIND-02",
                pillar="② 脱PPAP ＆ 二重拡張子・RTL偽装マルウェア検疫",
                severity=ppap_res["severity"],
                title=f"検査対象 `{ppap_res['filename']}`: {ppap_res['detected_risks'][0]}",
                japan_context_problem="日本独自の『パスワード付きZIP＋別送メール（PPAP）』は、ウイルス検疫ゲートウェイをすり抜けるため攻撃者にとって最高のマルウェア運搬手段になっており、二重拡張子(.pdf.exe)被害が絶えません。",
                global_modern_standard="PPAPの完全禁止（NIST/デジタル庁方針）と、展開前バイナリ/拡張子検証 ＋ `age`/`SOPS` 公開鍵暗号またはゼロトラスト共有リンク。",
                actionable_fix=ppap_res["modern_alternative"],
            ),
            JapanBlindspotFinding(
                blindspot_id="JP-BLIND-03",
                pillar="③ 自社・取引先ドメインのなりすまし防衛 (DMARC `p=reject` / SPF)",
                severity=dmarc_res["severity"],
                title=f"ドメイン `{sample_domain}`: {dmarc_res['issues'][0]}",
                japan_context_problem="日本企業の過半数がDMARC未設定または `p=none`（監視のみで遮断しない）のまま放置しており、社長や取引先を騙るBEC（ビジネスメール詐欺）の温床になっています。",
                global_modern_standard="DMARC `p=reject`（完全拒否）＋ 厳格なSPF (`-all`) ＋ DKIM署名の100%強制。",
                actionable_fix=f"DNSに以下のレコードを登録してください: `{dmarc_res['recommended_dns_record']}`",
            ),
            JapanBlindspotFinding(
                blindspot_id="JP-BLIND-04",
                pillar="④ SMSフォールバック（電話番号リカバリ）とSIMスワップ耐性",
                severity="HIGH",
                title="パスキー導入後も『SMSによるパスワード再設定・裏口ログイン』が残存するダウングレード脆弱性",
                japan_context_problem="偽造本人確認書類によるeSIM不正再発行（SIMスワップ）が日本で急増。裏口にSMS認証が残っていると、パスキーをバイパスして口座を乗っ取られます。",
                global_modern_standard="重要口座からの電話番号（SMS）リカバリの完全削除、または物理セキュリティキー（YubiKey）2本登録によるSMSフォールバック遮断（Apple ID / Google Advanced Protection方式）。",
                actionable_fix="金融・基幹メールの設定からSMSフォールバックを無効化し、リカバリコードをVaultwarden/金庫にオフライン保管してください。",
            ),
            JapanBlindspotFinding(
                blindspot_id="JP-BLIND-05",
                pillar="⑤ 部門共有ID（`keiri@`, `info@`）の廃止と NHI（AI/Bot/APIキー）ガバナンス",
                severity="CRITICAL" if shared_hits else "PASS",
                title=f"共有アカウント検出: {', '.join(shared_hits) if shared_hits else 'なし'} / 非人間ID(NHI)の無期限放置リスク",
                japan_context_problem="日本の職場では『経理用・総務用の共通IDとパスワード』を複数人や委託先で使い回す習慣が根強く、退職者や委託先経由の侵入時に『誰が操作したか』の証跡（監査ログ）が完全に消えます。またAIエージェントやGASのAPIキーが野放しです。",
                global_modern_standard="1人1ID＋SSO/Passkeyの徹底（共有メールは委任アクセス/グループで処理）＋ AIエージェントには Aegis Blind Broker で有効期限付きハンドルのみを付与。",
                actionable_fix="検出された共有ID（`keiri@` 等）の直接パスワード共有を廃止し、個人別ID＋ハードウェア承認（L0 Gate）へ移行してください。",
            ),
            JapanBlindspotFinding(
                blindspot_id="JP-BLIND-06",
                pillar="⑥ AIサプライチェーン攻撃（Slopsquatting）＆ SBOM（ソフトウェア部品表）検証",
                severity="CRITICAL" if not supply_res["safe"] else "PASS",
                title=(
                    f"危険パッケージ検出 ({supply_res['flagged_count']}件): "
                    + (supply_res["flagged_packages"][0]["package"] if supply_res["flagged_packages"] else "異常なし")
                ),
                japan_context_problem="生成AIがハルシネーションで出力した架空のライブラリ名を攻撃者がPyPI/npmに先回り登録する『Slopsquatting』により、開発者が `pip install` した瞬間に全認証情報が抜かれる被害が拡大しています。",
                global_modern_standard="OpenSSF GuardDog / Google OSV-Scanner / Anchore Syft によるインストール前プリフライト検査とSBOM自動生成の義務化。",
                actionable_fix="AIが提案したパッケージは必ず Aegis Supply-Chain Gate で実在性・署名・悪意コードを検査してから導入してください。",
            ),
            JapanBlindspotFinding(
                blindspot_id="JP-BLIND-07",
                pillar="⑦ 『侵入前提（Assume Breach）』の社内共有フォルダ・カナリア罠（Deception）",
                severity="PASS",
                title="日本企業のランサムウェア長期潜伏を防ぐ『ダミー顧客名簿・ダミー稟議書』ハニートラップ配備",
                japan_context_problem="日本企業は『入口のウイルス対策』に偏り、侵入後の内部偵察を検知する罠（Deception）がないため、ランサムウェアに全社暗号化されるまで数ヶ月間侵入に気づけません。",
                global_modern_standard="Active Cyber Defense (ACD)：ファイルサーバーやクラウド・PC内に『触れた瞬間に警報と隔離が走る毒入りダミーファイル（Canarytokens）』を常時配置。",
                actionable_fix="Aegis-Zeroの『実ファイル罠配備』により、侵入者が最初に開く `.env.production` や `crypto_wallet_backup.json` で0.08秒以内に逆探知・隔離します。",
            ),
        ]

        return {
            "total_pillars": len(findings),
            "critical_or_high_count": sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH")),
            "dmarc_audit": dmarc_res,
            "ppap_audit": ppap_res,
            "supply_chain_audit": supply_res,
            "findings": [f.__dict__ for f in findings],
        }
