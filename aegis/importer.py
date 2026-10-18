"""
Zero-Knowledge CSV Importer & Direct Action URL Resolver
Supports importing exported CSVs from:
- Google Chrome / Brave / Edge (name, url, username, password)
- Apple Passwords / Safari (Title, URL, Username, Password, OTPAuth)
- Bitwarden (folder, favorite, type, name, notes, fields, reprompt, login_uri, login_username, login_password, login_totp)
- 1Password (Title, Url, Username, Password, OTPAuth)

Security Guarantee:
Plaintext passwords in the CSV are hashed in-memory (SHA-256 salted fingerprint + SHA-1 5-char prefix)
and immediately discarded. Plaintext is NEVER saved to disk or sent over the network.
"""
import csv
import hashlib
import io
import secrets
from typing import Dict, List
from urllib.parse import urlparse

from .models import AccountRecord, AuthMethod, SecurityZone


DIRECT_SECURITY_SETTINGS_URLS: Dict[str, str] = {
    "google.com": "https://myaccount.google.com/signinoptions/passkeys",
    "apple.com": "https://account.apple.com/sign-in",
    "proton.me": "https://account.proton.me/u/0/mail/security",
    "sbisec.co.jp": "https://site2.sbisec.co.jp/ETGate/",
    "rakuten-sec.co.jp": "https://www.rakuten-sec.co.jp/web/security/passkey/",
    "monex.co.jp": "https://www.monex.co.jp/service/passkey/index.html",
    "netbk.co.jp": "https://www.netbk.co.jp/contents/lineup/smartauth/neo/",
    "gmo-aozora.com": "https://gmo-aozora.com/security/",
    "mufg.jp": "https://direct.bk.mufg.jp/",
    "binance.com": "https://www.binance.com/en/my/security",
    "bitbank.cc": "https://app.bitbank.cc/account/security",
    "coincheck.com": "https://coincheck.com/ja/settings/two_factor_auth",
    "github.com": "https://github.com/settings/security",
    "aws.amazon.com": "https://console.aws.amazon.com/iam/home#/security_credentials",
    "cloudflare.com": "https://dash.cloudflare.com/profile/authentication",
    "x.com": "https://x.com/settings/account/login_verification",
    "amazon.co.jp": "https://www.amazon.co.jp/a/settings/approval",
}


class ZeroKnowledgeCSVImporter:
    """
    Parses browser/password-manager CSV exports in-memory without retaining plaintext passwords.
    """

    def __init__(self):
        # Ephemeral per-session salt so fingerprints cannot be rainbow-tabled
        self._session_salt = secrets.token_hex(16)

    @staticmethod
    def normalize_domain(raw_url_or_domain: str) -> str:
        raw = (raw_url_or_domain or "").strip().lower()
        if not raw:
            return "unknown.local"
        if "://" not in raw:
            raw = "https://" + raw
        try:
            host = urlparse(raw).hostname or "unknown.local"
        except ValueError:
            return "unknown.local"
        if host.startswith("www."):
            host = host[4:]
        # Map subdomains of known major financial/cloud services to root domain
        for root_dom in DIRECT_SECURITY_SETTINGS_URLS:
            if host == root_dom or host.endswith("." + root_dom):
                return root_dom
        if host == "twitter.com" or host.endswith(".twitter.com"):
            return "x.com"
        return host

    def parse_csv_content(self, csv_text: str) -> List[AccountRecord]:
        """
        Detects CSV column format automatically (Chrome, Safari/Apple, Bitwarden, 1Password)
        and converts rows into sanitized AccountRecord objects.
        """
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        records: List[AccountRecord] = []

        for idx, row in enumerate(reader, start=1):
            if None in row:
                raise ValueError("CSV row contains more fields than its header")
            norm_row = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}

            raw_url = (
                norm_row.get("url")
                or norm_row.get("login_uri")
                or norm_row.get("website")
                or norm_row.get("domain")
                or norm_row.get("name")
                or norm_row.get("title")
                or ""
            )
            domain = self.normalize_domain(raw_url)

            username = (
                norm_row.get("username")
                or norm_row.get("login_username")
                or norm_row.get("email")
                or "unknown@user"
            )

            raw_password = (
                norm_row.get("password")
                or norm_row.get("login_password")
                or ""
            )

            totp_secret = (
                norm_row.get("otpauth")
                or norm_row.get("login_totp")
                or norm_row.get("totp")
                or ""
            )

            explicit_auth = norm_row.get("auth_method", "").lower()
            if explicit_auth in {m.value for m in AuthMethod}:
                auth_method = AuthMethod(explicit_auth)
            elif "passkey" in norm_row.get("notes", "").lower() or "fido" in norm_row.get("notes", "").lower():
                auth_method = AuthMethod.PASSKEY
            elif totp_secret:
                auth_method = AuthMethod.TOTP
            else:
                auth_method = AuthMethod.PASSWORD_ONLY

            # Zero-Knowledge conversion: compute length, salted reuse fingerprint, and 5-char SHA-1 prefix
            pw_len = len(raw_password)
            if raw_password:
                sha1_prefix = hashlib.sha1(raw_password.encode("utf-8")).hexdigest().upper()[:5]
                salted_fp = hashlib.sha256(f"{self._session_salt}:{raw_password}".encode("utf-8")).hexdigest()[:20]
            else:
                sha1_prefix = None
                salted_fp = None

            # Delete raw_password reference immediately
            del raw_password

            is_alias = any(
                tag in username.lower()
                for tag in ("simplelogin", "addy.io", "anonaddy", "duck.com", "passmail.net", "+")
            )

            records.append(
                AccountRecord(
                    account_id=f"IMP-{idx:03d}",
                    domain=domain,
                    username_or_email=username,
                    current_auth=auth_method,
                    password_sha1_prefix=sha1_prefix,
                    password_hash_fingerprint=salted_fp,
                    password_length=pw_len,
                    is_alias_email=is_alias,
                )
            )

        return records

    @staticmethod
    def get_direct_action_url(domain: str) -> str:
        """Returns the direct security/passkey settings URL for 1-click hardening."""
        first_domain = domain.split(",")[0].strip()
        return DIRECT_SECURITY_SETTINGS_URLS.get(first_domain, f"https://{first_domain}")
