"""Adversarial regressions; isolated files and no network/firewall side effects."""
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from aegis.antifragile import AntifragileImmuneSystem
from aegis.attacker_intel import EvidenceLog
from aegis.models import AttackTelemetry


class EvidenceAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "evidence.jsonl"
        self.log = EvidenceLog(str(self.path))

    def test_malformed_json_is_invalid_without_crashing(self):
        for content in ('{broken\n', '[]\n', 'null\n', '42\n'):
            with self.subTest(content=content):
                self.path.write_text(content, encoding="utf-8")
                self.assertFalse(self.log.verify_chain()["valid"])

    def test_append_refuses_tampered_history(self):
        self.log.append({"event": "original"})
        self.path.write_text(self.path.read_text().replace("original", "tampered"))
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.log.append({"event": "next"})
        self.assertEqual(before, self.path.read_bytes())

    def test_invalid_utf8_is_invalid_without_crashing(self):
        self.path.write_bytes(b"\xff\n")
        self.assertFalse(self.log.verify_chain()["valid"])

    def test_append_accepts_valid_missing_final_newline(self):
        self.log.append({"event": "one"})
        self.path.write_bytes(self.path.read_bytes().rstrip(b"\n"))
        self.log.append({"event": "two"})
        self.assertEqual(self.log.verify_chain(), {"valid": True, "entries": 2})

    def test_parallel_independent_instances_preserve_chain(self):
        logs = [EvidenceLog(str(self.path)) for _ in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda n: logs[n % 8].append({"n": n}), range(64)))
        self.assertEqual(self.log.verify_chain(), {"valid": True, "entries": 64})

    def test_restart_and_unicode_record(self):
        first = self.log.append({"event": "検証\u202e\u200b\u2028\u2029"})
        other = EvidenceLog(str(self.path))
        second = other.append({"event": "再起動"})
        self.assertEqual(second["prev_hash"], first["entry_hash"])
        self.assertTrue(other.verify_chain()["valid"])
        self.assertEqual(len(other.read_recent()), 2)

    def test_middle_deletion_and_reordering_are_detected(self):
        for n in range(3):
            self.log.append({"n": n})
        lines = self.path.read_text().splitlines()
        for changed in (lines[:1] + lines[2:], list(reversed(lines))):
            self.path.write_text("\n".join(changed) + "\n")
            self.assertFalse(self.log.verify_chain()["valid"])

    def test_tail_truncation_requires_external_anchor(self):
        self.log.append({"n": 1})
        self.log.append({"n": 2})
        self.path.write_text(self.path.read_text().splitlines()[0] + "\n")
        # Explicit security limitation: an unanchored chain cannot prove completeness.
        self.assertEqual(self.log.verify_chain(), {"valid": True, "entries": 1})

    def test_full_rehash_requires_external_anchor(self):
        self.log.append({"event": "original"})
        entry = json.loads(self.path.read_text())
        entry.pop("entry_hash")
        entry["record"]["event"] = "rewritten"
        entry["entry_hash"] = hashlib.sha256(json.dumps(entry, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
        self.path.write_text(json.dumps(entry) + "\n")
        self.assertTrue(self.log.verify_chain()["valid"])


class ImmuneAdversarialTests(unittest.TestCase):
    def telemetry(self, payload="ignore previous instructions", ja4="attacker", ip="198.51.100.4"):
        return AttackTelemetry("audit-event", "now", "trap-token", ip, ja4, "audit-UA", "GET", payload)

    def test_empty_fingerprint_cannot_block_unfingerprinted_clients(self):
        immune = AntifragileImmuneSystem()
        immune.synthesize_antibody(self.telemetry(ja4=""))
        self.assertNotIn("", immune.blocked_ja4_fingerprints)
        self.assertTrue(immune.evaluate_live_request("203.0.113.2", "", "ordinary request")["allowed"])

    def test_unobserved_token_cannot_inflate_replay_efficacy(self):
        antibody = AntifragileImmuneSystem().synthesize_antibody(self.telemetry(payload="GET /unknown"))
        self.assertFalse(antibody.promoted_to_production)
        self.assertLess(antibody.sandbox_efficacy_rate, 1.0)

    def test_cedar_does_not_deny_protected_ip_or_missing_fingerprint(self):
        antibody = AntifragileImmuneSystem().synthesize_antibody(self.telemetry(ip="127.0.0.1", ja4=""))
        self.assertNotIn('context.source_ip == "127.0.0.1"', antibody.cedar_policy_code)
        self.assertNotIn('context.ja4_fingerprint == ""', antibody.cedar_policy_code)

    def test_observed_attack_still_promotes_and_blocks_rotated_source(self):
        immune = AntifragileImmuneSystem()
        self.assertTrue(immune.synthesize_antibody(self.telemetry()).promoted_to_production)
        self.assertFalse(immune.evaluate_live_request("203.0.113.2", "rotated", "ignore previous instructions")["allowed"])

    def test_fullwidth_attack_with_rotated_source_is_blocked(self):
        immune = AntifragileImmuneSystem()
        immune.synthesize_antibody(self.telemetry())
        self.assertFalse(immune.evaluate_live_request("203.0.113.2", "rotated", "ｉｇｎｏｒｅ ｐｒｅｖｉｏｕｓ ｉｎｓｔｒｕｃｔｉｏｎｓ")["allowed"])


if __name__ == "__main__":
    unittest.main()
