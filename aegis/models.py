"""
Aegis-Zero Enterprise: Data Models & Security Ontology
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class SecurityZone(str, Enum):
    """3-Tier Blast Radius Isolation Zones"""
    ZONE_0_NUCLEAR = "ZONE_0_NUCLEAR"      # Banking, Securities, Cold Crypto, Root Email (AI Read-Only Audit, Hardware Key Required)
    ZONE_1_GUARDED = "ZONE_1_GUARDED"      # Cloud Infra, GitHub, Hot Wallet, Core SaaS (Blind Proxy + L0 Biometric Approval)
    ZONE_2_EPHEMERAL = "ZONE_2_EPHEMERAL"  # General EC, Subscribed Services, Trial Accounts (1-Account-1-Alias + AI Rotation)


class AuthMethod(str, Enum):
    """Authentication factor strength hierarchy"""
    HARDWARE_FIDO2 = "hardware_fido2"  # YubiKey / Secure Enclave (Strongest)
    PASSKEY = "passkey"                # Synced or Device-bound WebAuthn Passkey
    TOTP = "totp"                      # Authenticator App (RFC 6238)
    SMS_EMAIL = "sms_email"            # Vulnerable to SIM Swap / Phishing
    PASSWORD_ONLY = "password_only"    # Critical Vulnerability


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class AccountRecord:
    """User or Enterprise Account Asset Record"""
    account_id: str
    domain: str
    username_or_email: str
    current_auth: AuthMethod
    password_sha1_prefix: Optional[str] = None     # First 5 chars of SHA-1 for k-Anonymity
    password_hash_fingerprint: Optional[str] = None  # Local salted fingerprint to detect reuse without storing plaintext
    password_length: int = 0
    assigned_zone: Optional[SecurityZone] = None
    is_alias_email: bool = False
    has_withdrawal_whitelist: bool = False
    wallet_address: Optional[str] = None
    unlimited_approvals_count: int = 0


@dataclass
class VulnerabilityFinding:
    """Deterministic Security Hole Finding"""
    finding_id: str
    account_id: str
    domain: str
    severity: Severity
    category: str
    title: str
    description: str
    remediation: str
    risk_score_impact: int


@dataclass
class HoneyToken:
    """Poisoned Credential / Canary Trap"""
    token_id: str
    token_type: str  # "aws_iam", "crypto_private_key", "securities_api_key", "canary_email_alias"
    decoy_identifier: str
    decoy_secret_value: str
    planted_location: str
    canary_webhook_url: str
    created_at: str


@dataclass
class AttackTelemetry:
    """Captured Attacker Telemetry from Honey-Vault or Mirage Tarpit"""
    event_id: str
    timestamp: str
    triggered_token_id: str
    attacker_ip: str
    attacker_ja4_fingerprint: str
    attacker_user_agent: str
    attempted_action: str
    raw_payload: str
    attacker_wallet_or_c2: Optional[str] = None


@dataclass
class ImmuneAntibody:
    """Self-Generated Defense Vaccine (Cedar Policy + Nuclei Template)"""
    antibody_id: str
    source_event_id: str
    attack_class: str
    extracted_signature: str
    cedar_policy_code: str
    nuclei_template_yaml: str
    sandbox_efficacy_rate: float       # Must be 1.0 (100% blocks attack variants)
    sandbox_false_positive_rate: float # Must be 0.0 (0% blocks legitimate traffic)
    promoted_to_production: bool = False
