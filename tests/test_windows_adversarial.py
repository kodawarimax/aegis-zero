"""Adversarial Windows fixtures; no Windows commands or network calls execute."""
import base64
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.mac_live_scanner import LiveFileHoneyTrapManager, RealMacSecurityScanner


class WindowsAdversarialTests(unittest.TestCase):
    def posture(self, **outputs):
        def runner(cmd):
            return outputs.get(cmd[0], "")
        with patch.object(RealMacSecurityScanner, "_audit_ssh_directory", return_value={
            "id": "WIN-SSH-05", "status": "PASS", "severity": "LOW"
        }):
            result = RealMacSecurityScanner(cmd_runner=runner).scan_windows_posture()
        return {item["id"]: item for item in result["checks"]}

    def test_suspended_bitlocker_is_not_protected(self):
        item = self.posture(**{"manage-bde": "Conversion Status: Fully Encrypted\nProtection Status: Protection Off"})
        self.assertEqual(item["WIN-BL-01"]["status"], "WARN")

    def test_bitlocker_explicit_protection_in_english_and_japanese(self):
        for output in ("Protection Status: Protection On", "保護の状態: 保護はオン"):
            self.assertEqual(self.posture(**{"manage-bde": output})["WIN-BL-01"]["status"], "PASS")

    def test_firewall_header_is_not_on_state(self):
        item = self.posture(netsh="Connection failed")
        self.assertEqual(item["WIN-FW-02"]["status"], "WARN")

    def test_firewall_requires_three_explicit_states(self):
        for output, status in [("State ON\nState ON\nState ON", "PASS"),
                               ("状態 オン\n状態 オン\n状態 オフ", "WARN"),
                               ("State ON", "WARN")]:
            with self.subTest(output=output):
                self.assertEqual(self.posture(netsh=output)["WIN-FW-02"]["status"], status)

    def test_empty_or_failed_netstat_is_not_a_pass(self):
        for output in ("", "Access is denied.", "Proto Local Address Foreign Address State PID\nTCP [::]:445",
                       "TCP [::]:445 [::]:0 LＩSTENING 42", "TCP [[::1]]:80 [::]:0 LISTENING 42"):
            self.assertEqual(self.posture(netstat=output)["WIN-PORT-06"]["status"], "WARN")

    def test_netstat_non_loopback_ipv4_ipv6_and_mapped_ipv6(self):
        for addr in ("192.0.2.8:445", "[2001:db8::1]:445", "[::]:445",
                     "[fe80::1%12]:445", "[::ffff:192.0.2.8]:445"):
            with self.subTest(addr=addr):
                self.assertEqual(self.posture(netstat=f"TCP {addr} [::]:0 LISTENING 42")["WIN-PORT-06"]["status"], "WARN")

    def test_netstat_loopback_and_non_listening_rows(self):
        for addr in ("127.0.0.1:80", "[::1]:80", "[::ffff:127.0.0.1]:80"):
            with self.subTest(addr=addr):
                self.assertEqual(self.posture(netstat=f"TCP {addr} [::]:0 LISTENING 42")["WIN-PORT-06"]["status"], "PASS")
        self.assertEqual(self.posture(netstat="TCP 192.0.2.1:80 192.0.2.2:90 ESTABLISHED 42")["WIN-PORT-06"]["status"], "PASS")

    def test_cp932_and_utf16_windows_output(self):
        source = "保護状態: 保護はオン\n状態 オン"
        for encoding in ("cp932", "utf-16", "utf-8"):
            with self.subTest(encoding=encoding), patch("aegis.mac_live_scanner.sys.platform", "win32"), patch(
                "aegis.mac_live_scanner.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, source.encode(encoding), b""),
            ):
                self.assertEqual(RealMacSecurityScanner()._run_cmd(["manage-bde"]), source)

    def test_cp932_real_subprocess_and_failed_command_output(self):
        source = "保護の状態: 保護はオン"
        child = f"import sys; sys.stdout.buffer.write(bytes.fromhex('{source.encode('cp932').hex()}'))"
        with patch("aegis.mac_live_scanner.sys.platform", "win32"):
            self.assertEqual(RealMacSecurityScanner()._run_cmd([sys.executable, "-c", child]), source)
        with patch("aegis.mac_live_scanner.subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"State ON", b"")):
            self.assertEqual(RealMacSecurityScanner()._run_cmd(["netsh"]), "")

    def test_defender_requires_actual_boolean_properties(self):
        for output, status in [('{"RealTimeProtectionEnabled":\ttrue,"IsTamperProtected":\ntrue}', "PASS"),
                               ('{"Other":{"RealTimeProtectionEnabled":true,"IsTamperProtected":true}}', "WARN"),
                               ('{"RealTimeProtectionEnabled":"true","IsTamperProtected":"true"}', "WARN"),
                               ('{"RealTimeProtectionEnabled":true,"IsTamperProtected":true} trailing', "WARN")]:
            with self.subTest(output=output):
                self.assertEqual(self.posture(powershell=output)["WIN-DEF-03"]["status"], status)

    def test_notification_uses_literal_powershell_strings(self):
        payload = "$(Start-Process calc); ${env:USERNAME}; O'Brien‘’"
        with patch("aegis.mac_live_scanner.sys.platform", "win32"), patch(
            "aegis.mac_live_scanner.subprocess.run"
        ) as run:
            LiveFileHoneyTrapManager.send_macos_notification(payload, payload)
        script = run.call_args.args[0][-1]
        self.assertNotIn("$(Start-Process calc)", script)
        self.assertNotIn(payload, script)
        self.assertIn(base64.b64encode(payload.encode("utf-8")).decode("ascii"), script)

    def test_bait_deployment_does_not_follow_existing_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trap = root / "trap"
            trap.mkdir()
            target = root / "untouched.txt"
            target.write_text("preserve", encoding="utf-8")
            (trap / ".env.production.bait").symlink_to(target)
            with self.assertRaises(ValueError):
                LiveFileHoneyTrapManager(str(trap)).deploy_real_bait_files()
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve")

    def test_bait_redeployment_works_and_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            trap = root / "trap"
            manager = LiveFileHoneyTrapManager(str(trap))
            self.assertEqual(len(manager.deploy_real_bait_files()), 3)
            self.assertEqual(len(manager.deploy_real_bait_files()), 3)
            self.assertEqual(len(manager.get_deployed_baits()), 3)
            link = root / "link"
            link.symlink_to(trap, target_is_directory=True)
            with self.assertRaises(ValueError):
                LiveFileHoneyTrapManager(str(link)).deploy_real_bait_files()


if __name__ == "__main__":
    unittest.main()
