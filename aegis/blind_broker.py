"""
Module 4: Blind Credential Broker & Zero-Trust Enclave Gate
- Prevents AI Agents (LLMs) from ever seeing plaintext passwords, API keys, or private keys
- Enforces 3-Tier Blast Radius Zoning:
  * ZONE_0_NUCLEAR: AI execution strictly forbidden (Read-only security audit only)
  * ZONE_1_GUARDED: Requires Hardware L0 Approval (Touch ID / Secretive / YubiKey) + Blind Injection
  * ZONE_2_EPHEMERAL: Allows AI blind execution & automated credential rotation
- Scans outbound agent payloads to prevent Indirect Prompt Injection exfiltration
"""
import base64
import re
import urllib.parse
from typing import Any, Callable, Dict, Iterable, Optional, Set

from .models import SecurityZone


class BlindCredentialBroker:
    """
    OneCLI / Infisical Agent style Blind Broker.
    AI Agents only hold opaque handles like `handle://zone1/github_pat`.
    Plaintext secrets live inside the broker memory space (in production, an isolated daemon/Keychain)
    and are never returned into the LLM context window.
    """

    def __init__(self):
        self._enclave_secrets: Dict[str, str] = {}
        self._handle_zones: Dict[str, SecurityZone] = {}
        self._handle_allowed_domains: Dict[str, Set[str]] = {}

    @staticmethod
    def _derive_default_domains(opaque_handle: str) -> Set[str]:
        slug = opaque_handle.rsplit("/", 1)[-1].lower()
        head = slug.split("_")[0]
        derived = {f"{head}.com", f"api.{head}.com", f"{head}.co.jp", f"api.{head}.co.jp"}
        return derived

    def register_secret(
        self,
        opaque_handle: str,
        plaintext_secret: str,
        zone: SecurityZone,
        allowed_domains: Optional[Iterable[str]] = None,
    ) -> str:
        """
        Stores a secret inside the broker and binds it deterministically to a SecurityZone
        and an explicit allowlist of destination domains (Fail-Closed).
        """
        if not opaque_handle.startswith("handle://"):
            raise ValueError("Opaque handle must start with 'handle://'")
        if not isinstance(zone, SecurityZone):
            raise ValueError("A valid SecurityZone is required")
        if not isinstance(plaintext_secret, str) or not plaintext_secret:
            raise ValueError("A non-empty secret is required")
        self._enclave_secrets[opaque_handle] = plaintext_secret
        self._handle_zones[opaque_handle] = zone
        if allowed_domains is not None:
            self._handle_allowed_domains[opaque_handle] = {d.strip().lower() for d in allowed_domains if d.strip()}
        else:
            self._handle_allowed_domains[opaque_handle] = self._derive_default_domains(opaque_handle)
        return opaque_handle

    @classmethod
    def _scrub_secret_variants(cls, text: str, secret_val: str) -> str:
        """Scrubs plaintext, Base64, URL-encoded, and Hex representations of the secret."""
        if not secret_val:
            return text
        b64_val = base64.b64encode(secret_val.encode("utf-8")).decode("ascii")
        b64_nopad = b64_val.rstrip("=")
        url_val = urllib.parse.quote(secret_val, safe="")
        hex_val = secret_val.encode("utf-8").hex()
        variants = {secret_val, b64_val, b64_nopad, url_val, hex_val, hex_val.upper()}
        pattern = "|".join(re.escape(v) for v in sorted(variants, key=lambda v: (-len(v), v)) if v)
        return re.sub(pattern, lambda _: "[REDACTED_BY_AEGIS_BLIND_BROKER]", text)

    def execute_blind_request(
        self,
        agent_id: str,
        opaque_handle: str,
        target_domain: str,
        request_template: str,
        l0_hardware_approved: bool = False,
        executor_fn: Optional[Callable[[str], str]] = None,
        actor_authority: str = "AUTONOMOUS_AI_AGENT",
    ) -> Dict[str, Any]:
        """
        Executes an authenticated action on behalf of an AI agent or Privileged Human Owner
        without exposing the secret to logs/context.
        - Autonomous AI Agents (`AUTONOMOUS_AI_AGENT`) are strictly blocked from Zone 0 and require L0 on Zone 1.
        - Privileged Human Owners (`PRIVILEGED_OWNER`) are never obstructed on their own allowlisted domains.
        """
        if opaque_handle not in self._enclave_secrets:
            return {"status": "DENIED", "reason": "UNKNOWN_HANDLE"}

        zone = self._handle_zones[opaque_handle]
        secret_val = self._enclave_secrets[opaque_handle]
        allowed_domains = self._handle_allowed_domains.get(opaque_handle, set())
        norm_domain = (target_domain or "").strip().lower()
        valid_domain = bool(re.fullmatch(
            r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", norm_domain
        ))
        is_privileged_owner = actor_authority == "PRIVILEGED_OWNER"

        # Rule 1: ZONE_0_NUCLEAR is physically off-limits to autonomous AI execution (human owner is never blocked)
        if zone == SecurityZone.ZONE_0_NUCLEAR and not is_privileged_owner:
            return {
                "status": "BLOCKED_ZONE_0_NUCLEAR",
                "reason": (
                    f"Zone 0 (Banking/Securities/Cold Crypto) execution by AI agent '{agent_id}' is strictly prohibited. "
                    "Only read-only configuration auditing is permitted."
                ),
            }

        # Rule 2: ZONE_1_GUARDED requires explicit L0 Hardware Enclave approval for AI agents
        if zone == SecurityZone.ZONE_1_GUARDED and l0_hardware_approved is not True and not is_privileged_owner:
            return {
                "status": "REQUIRE_L0_HANDSHAKE",
                "reason": (
                    f"Zone 1 resource '{opaque_handle}' requires physical L0 approval (Touch ID / Apple Watch / YubiKey) "
                    "before blind credential injection."
                ),
            }

        # Rule 3: Deterministic Destination Domain Allowlist + Anti-Exfiltration Guard (Fail-Closed)
        if (
            not valid_domain
            or norm_domain not in allowed_domains
            or "exfiltrate" in request_template.lower()
            or "webhook.site" in norm_domain
        ):
            return {
                "status": "BLOCKED_EXFILTRATION_ATTEMPT",
                "reason": (
                    f"Destination domain '{norm_domain}' is not in the deterministic allowlist "
                    f"({sorted(allowed_domains)}) for handle '{opaque_handle}' or template was flagged."
                ),
            }

        # Inject secret exclusively inside the isolated network layer
        injected_payload = request_template.replace("{{BLIND_SECRET}}", secret_val)

        if executor_fn is not None:
            raw_output = executor_fn(injected_payload)
        else:
            raw_output = f"Executed authenticated request to {norm_domain} using {opaque_handle} [200 OK]"

        # Rule 4: Multi-Encoding Output Scrubbing (Plaintext + Base64 + URL + Hex)
        sanitized_output = self._scrub_secret_variants(raw_output, secret_val)

        return {
            "status": "SUCCESS_PRIVILEGED_OWNER_EXECUTED" if is_privileged_owner else "SUCCESS_BLIND_EXECUTED",
            "zone": zone.value,
            "agent_id": agent_id,
            "actor_authority": actor_authority,
            "sanitized_response": sanitized_output,
        }
