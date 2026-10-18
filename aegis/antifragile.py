"""
Module 3: Antifragile Self-Evolving Cyber Immune System
- Extracts Attack Signatures (TTPs) from captured Deception Telemetry
- Synthesizes Deterministic Defense Antibodies:
  1. AWS Cedar Policy-as-Code rules (Authorization Gate)
  2. ProjectDiscovery Nuclei YAML templates (Internal Regression Scanner)
- Runs Deterministic Self-Play Sandbox (Red Team vs Blue Team) to prove:
  * 100% Attack Block Efficacy
  * 0% False Positive Rate on legitimate owner/enterprise operations (prevents autoimmune lockout)
"""
import hashlib
import ipaddress
import json
import re
import unicodedata
from typing import Any, Dict, List

from .models import AttackTelemetry, ImmuneAntibody

PROTECTED_NEVER_BLOCK_IPS = {"127.0.0.1", "::1", "localhost", "100.64.0.1", "100.64.0.10"}


def _is_protected_ip(ip_str: str) -> bool:
    if ip_str in PROTECTED_NEVER_BLOCK_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_loopback or addr.is_unspecified
    except ValueError:
        return False


def _safe_literal(val: str) -> str:
    """Escapes quotes, backslashes, and control characters for safe policy/YAML interpolation."""
    cleaned = re.sub(r"[\r\n\x00-\x1f]", " ", str(val))
    return json.dumps(cleaned, ensure_ascii=False)[1:-1]


class AntifragileImmuneSystem:
    """
    Turns every attack or leak attempt into a verified defense rule upgrade.
    """

    def __init__(self):
        self.active_antibodies: List[ImmuneAntibody] = []
        self.blocked_ips: set = set()
        self.blocked_ja4_fingerprints: set = set()
        self.blocked_payload_regexes: List[re.Pattern] = []

        # Baseline legitimate enterprise traffic corpus (used to prevent autoimmune lockouts / false positives)
        self.legitimate_traffic_corpus = [
            {
                "principal": "Agent::\"codex-worker\"",
                "action": "Action::\"UseBlindHandle\"",
                "resource": "VaultHandle::\"zone1/github_pat\"",
                "ip": "100.64.0.10",
                "ja4": "t13d1516h2_legit_mac_enclave",
                "payload": "git push origin feat/security-upgrade",
            },
            {
                "principal": "User::\"owner_admin\"",
                "action": "Action::\"ReadAuditReport\"",
                "resource": "Zone0::\"sbisec_audit\"",
                "ip": "100.64.0.1",
                "ja4": "t13d1516h2_legit_owner_safari",
                "payload": "GET /api/v1/audit/summary",
            },
            {
                "principal": "User::\"local_dashboard\"",
                "action": "Action::\"ReadLocalDashboard\"",
                "resource": "Localhost::\"dashboard\"",
                "ip": "127.0.0.1",
                "ja4": "t13d1516h2_local_browser",
                "payload": "GET /api/audit",
            },
        ]

    def classify_and_extract_signature(self, telemetry: AttackTelemetry) -> Dict[str, str]:
        """
        Deterministically analyzes the captured raw payload from the Mirage Tarpit or Threat Researcher
        and extracts a non-hallucinated attack pattern.
        """
        payload = unicodedata.normalize("NFKC", telemetry.raw_payload or "")
        if re.search(
            r"(ignore previous instructions|system prompt|exfiltrate|send to http|これまでの指示|新しいシステム指示|<system>)",
            payload,
            re.IGNORECASE,
        ):
            attack_class = "INDIRECT_PROMPT_INJECTION"
            sig_regex = r"(?i)(ignore\s+previous\s+instructions|system\s+prompt|exfiltrate|これまでの指示|新しいシステム指示|<system>)"
        elif re.search(r"(before calling this tool|do not tell the user|read\s+~/\.ssh|\.env)", payload, re.IGNORECASE):
            attack_class = "AI_MCP_TOOL_POISONING"
            sig_regex = r"(?i)(before\s+calling\s+this\s+tool|do\s+not\s+tell\s+the\s+user|read\s+~/\.ssh)"
        elif re.search(r"!\[[^\]]*\]\(https?://[^)]+(?:secret|key|token|leak)=", payload, re.IGNORECASE):
            attack_class = "MARKDOWN_ZERO_CLICK_EXFIL"
            sig_regex = r"(?i)!\[[^\]]*\]\(https?://[^)]+(?:secret|key|token|leak)="
        elif re.search(r"[\u200b-\u200f\U000e0000-\U000e007f]", payload):
            attack_class = "UNICODE_STEGO_SMUGGLING"
            sig_regex = r"[\u200b-\u200f\U000e0000-\U000e007f]"
        elif re.search(r"(union\s+select|or\s+1=1|--\s*$)", payload, re.IGNORECASE):
            attack_class = "SQL_INJECTION_PROBE"
            sig_regex = r"(?i)(union\s+select|or\s+1=1)"
        elif re.search(r"(approve\(|setApprovalForAll|0xffffffffffffffff)", payload, re.IGNORECASE):
            attack_class = "MALICIOUS_WEB3_DRAIN_PERMIT"
            sig_regex = r"(?i)(setApprovalForAll|0xffffffffffffffff)"
        else:
            attack_class = "CREDENTIAL_STUFFING_OR_HONEYTOKEN_ABUSE"
            token_val = telemetry.triggered_token_id or "HONEYTOKEN_TRIPWIRE"
            if payload and not re.match(r"^(GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+/", payload):
                sig_regex = re.escape(payload[:24])
            else:
                sig_regex = re.escape(token_val[:32])

        return {
            "attack_class": attack_class,
            "signature_regex": sig_regex,
        }

    def synthesize_antibody(self, telemetry: AttackTelemetry) -> ImmuneAntibody:
        """
        Synthesizes a Cedar Policy and a Nuclei Scanner Template from captured attack telemetry,
        then validates it inside the Deterministic Self-Play Sandbox before promotion.
        """
        analysis = self.classify_and_extract_signature(telemetry)
        attack_class = analysis["attack_class"]
        sig_regex = analysis["signature_regex"]
        antibody_id = f"AB-{hashlib.sha256(telemetry.event_id.encode()).hexdigest()[:8].upper()}"

        safe_ev = _safe_literal(telemetry.event_id)
        safe_ip = _safe_literal(telemetry.attacker_ip)
        safe_ja4 = _safe_literal(telemetry.attacker_ja4_fingerprint)
        safe_tok = _safe_literal(telemetry.triggered_token_id)
        safe_sig = _safe_literal(sig_regex)
        ip_condition = f'context.source_ip == "{safe_ip}"' if not _is_protected_ip(telemetry.attacker_ip) else "false"
        ja4_condition = f'context.ja4_fingerprint == "{safe_ja4}"' if telemetry.attacker_ja4_fingerprint else "false"
        token_condition = f'context.triggered_honeytoken == "{safe_tok}"' if telemetry.triggered_token_id else "false"

        # 1. Generate AWS Cedar Policy-as-Code (with strict literal escaping against Policy Injection)
        cedar_policy = f"""// Auto-synthesized by Aegis-Zero Immune Loop from Event {safe_ev}
// Attack Class: {attack_class}
forbid (
    principal,
    action,
    resource
)
when {{
    {ip_condition} ||
    {ja4_condition} ||
    {token_condition} ||
    context.payload_matches_signature == true
}};"""

        # 2. Generate ProjectDiscovery Nuclei YAML Template
        nuclei_yaml = f"""id: aegis-auto-{antibody_id.lower()}
info:
  name: "Aegis Auto-Immunization Check - {attack_class}"
  author: aegis-zero-immune-engine
  severity: critical
  reference:
    - "event://{safe_ev}"
  tags: aegis,antifragile,{attack_class.lower()}

http:
  - method: POST
    path:
      - "{{{{BaseURL}}}}/api/v1/verify-immunization"
    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "{safe_sig}"
      - type: status
        status:
          - 403
          - 200
"""

        candidate = ImmuneAntibody(
            antibody_id=antibody_id,
            source_event_id=telemetry.event_id,
            attack_class=attack_class,
            extracted_signature=sig_regex,
            cedar_policy_code=cedar_policy,
            nuclei_template_yaml=nuclei_yaml,
            sandbox_efficacy_rate=0.0,
            sandbox_false_positive_rate=1.0,
            promoted_to_production=False,
        )

        # 3. Deterministic Self-Play Verification (Red Team Replay + Legitimate Traffic Regression)
        self._verify_and_promote_in_sandbox(candidate, telemetry)
        return candidate

    def _verify_and_promote_in_sandbox(self, candidate: ImmuneAntibody, telemetry: AttackTelemetry) -> None:
        """
        Tests the candidate antibody against:
        1. Attack Replay Suite (original attack + mutated variants) -> must block 100%
        2. Legitimate Enterprise Corpus -> must block 0% (0 false positives)
        """
        compiled_sig = re.compile(candidate.extracted_signature)
        can_block_ip = not _is_protected_ip(telemetry.attacker_ip)

        def sandbox_policy_evaluator(req: Dict[str, str]) -> bool:
            """Returns True if BLOCKED by the candidate antibody, False if ALLOWED."""
            if can_block_ip and req.get("ip") == telemetry.attacker_ip:
                return True
            if telemetry.attacker_ja4_fingerprint and req.get("ja4") == telemetry.attacker_ja4_fingerprint:
                return True
            if compiled_sig.search(unicodedata.normalize("NFKC", req.get("payload", ""))):
                return True
            return False

        # Replay only observed evidence: inventing a matching token masks misses.
        effective_payload = telemetry.raw_payload or ""

        # Red-Team Attack Replay (original + 2 mutations)
        attack_variants = [
            {
                "ip": telemetry.attacker_ip,
                "ja4": telemetry.attacker_ja4_fingerprint,
                "payload": effective_payload,
            },
            {
                "ip": "198.51.100.99",  # Attacker rotated IP, kept same tool/JA4
                "ja4": telemetry.attacker_ja4_fingerprint,
                "payload": "benign looking wrapper",
            },
            {
                "ip": "203.0.113.55",  # Attacker rotated IP & JA4, reused exploit payload/token
                "ja4": "t13d1516h2_new_proxy",
                "payload": effective_payload + " --mutation-1",
            },
        ]

        blocked_attacks = sum(1 for atk in attack_variants if sandbox_policy_evaluator(atk))
        candidate.sandbox_efficacy_rate = blocked_attacks / len(attack_variants)

        # Blue-Team Regression Check (Legitimate operations must NEVER be blocked)
        false_positives = sum(1 for legit in self.legitimate_traffic_corpus if sandbox_policy_evaluator(legit))
        candidate.sandbox_false_positive_rate = false_positives / len(self.legitimate_traffic_corpus)

        # Strict Promotion Gate: Efficacy == 1.0 AND False Positive == 0.0
        if candidate.sandbox_efficacy_rate == 1.0 and candidate.sandbox_false_positive_rate == 0.0:
            candidate.promoted_to_production = True
            if not any(ab.antibody_id == candidate.antibody_id for ab in self.active_antibodies):
                self.active_antibodies.append(candidate)
            if can_block_ip:
                self.blocked_ips.add(telemetry.attacker_ip)
            if telemetry.attacker_ja4_fingerprint:
                self.blocked_ja4_fingerprints.add(telemetry.attacker_ja4_fingerprint)
            if not any(r.pattern == compiled_sig.pattern for r in self.blocked_payload_regexes):
                self.blocked_payload_regexes.append(compiled_sig)

    def evaluate_live_request(self, ip: str, ja4: str, payload: str) -> Dict[str, Any]:
        """Evaluates incoming request against all promoted antibodies."""
        if not _is_protected_ip(ip) and ip in self.blocked_ips:
            return {"allowed": False, "reason": f"BLOCKED_BY_ANTIBODY_IP ({ip})"}
        if ja4 in self.blocked_ja4_fingerprints:
            return {"allowed": False, "reason": f"BLOCKED_BY_ANTIBODY_JA4 ({ja4})"}
        for regex in self.blocked_payload_regexes:
            if regex.search(unicodedata.normalize("NFKC", payload)):
                return {"allowed": False, "reason": f"BLOCKED_BY_ANTIBODY_SIGNATURE ({regex.pattern})"}
        return {"allowed": True, "reason": "CLEAN"}
