"""
Regression tests for the local dashboard server's P0 hardening:
token auth, Host/Origin validation (CSRF / DNS rebinding), path restriction, XSS escaping, honest labels.
"""
import http.client
import threading
import unittest
import tempfile
from pathlib import Path
from http.server import HTTPServer

from aegis.server import AegisAppState, create_request_handler
from aegis.access_policy import AccessPolicy
from aegis.attacker_intel import AttackerProfiler, AlertNotifier
from http_harness import request


class TestServerSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        policy = AccessPolicy.from_dict({"allowed_scan_paths": [cls.temp.name]})
        cls.state = AegisAppState(port=0, access_policy=policy,
                                  evidence_path=str(Path(cls.temp.name) / "evidence.jsonl"))
        cls.state.profiler = AttackerProfiler(allow_network=False)
        cls.state.notifier = AlertNotifier(mac_notify=lambda *args: None, webhook_url="")
        try:
            cls.httpd = HTTPServer(("127.0.0.1", 0), create_request_handler(cls.state))
        except PermissionError:
            cls.httpd = None
            cls.port = 8765
            cls.state.port = cls.port
            print("HTTP tests: socket bind unavailable; exercising parser/handler in memory")
            return
        cls.port = cls.httpd.server_address[1]
        cls.state.port = cls.port
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        if cls.httpd is not None:
            cls.httpd.shutdown()
            cls.httpd.server_close()
        cls.temp.cleanup()

    def _req(self, method, path, headers=None, body=None):
        if self.httpd is None:
            return request(self.state, method, path, headers, body)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": f"127.0.0.1:{self.port}"}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        conn.close()
        return resp.status, data

    def _auth(self):
        return {"X-Aegis-Token": self.state.token}

    def test_api_without_token_is_rejected(self):
        status, _ = self._req("GET", "/api/audit")
        self.assertEqual(status, 403)
        status, _ = self._req("POST", "/api/deploy-baits", {"Content-Type": "text/plain"}, body="x")
        self.assertEqual(status, 403)

    def test_api_with_token_succeeds(self):
        status, data = self._req("GET", "/api/audit", self._auth())
        self.assertEqual(status, 200)
        self.assertIn('"is_demo": true', data)

    def test_dns_rebinding_host_is_rejected(self):
        status, _ = self._req("GET", "/", {"Host": f"evil.example.com:{self.port}"})
        self.assertEqual(status, 403)

    def test_foreign_origin_is_rejected_even_with_token(self):
        h = self._auth()
        h["Origin"] = "https://evil.example.com"
        status, _ = self._req("GET", "/api/audit", h)
        self.assertEqual(status, 403)

    def test_scan_folder_outside_allowed_roots_is_rejected(self):
        status, _ = self._req("GET", "/api/scan-folder?path=/etc", self._auth())
        self.assertEqual(status, 403)
        status, _ = self._req("GET", "/api/scan-folder?path=/tmp/aegis-honey-trap/../../etc", self._auth())
        self.assertEqual(status, 403)

    def test_dashboard_embeds_token_and_escapes_and_has_no_false_claims(self):
        status, html = self._req("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn("__AEGIS_TOKEN__", html)
        self.assertIn(self.state.token, html)
        self.assertIn("function esc(", html)
        self.assertIn("${esc(f.domain)}", html)
        for banned in ("0.08秒", "100%阻止", "誤遮断0%", "数学的"):
            self.assertNotIn(banned, html, banned)

    def test_oversized_body_rejected(self):
        h = self._auth()
        h["Content-Length"] = str(10 * 1024 * 1024)
        if self.httpd is None:
            status, _ = self._req("POST", "/api/import-csv", h)
            self.assertEqual(status, 413)
            return
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/api/import-csv", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        for k, v in h.items():
            conn.putheader(k, v)
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 413)
        conn.close()

    def test_host_access_policy_devices_ips_and_paths(self):
        import tempfile
        from pathlib import Path
        from aegis.access_policy import AccessPolicy, AccessPolicyError

        with self.assertRaises(AccessPolicyError):
            AccessPolicy.from_dict({"bind_address": "0.0.0.0"})
        with self.assertRaises(AccessPolicyError):
            AccessPolicy.from_dict({"allowed_scan_paths": ["/"]})

        with tempfile.TemporaryDirectory() as tmpdir:
            policy = AccessPolicy.from_dict(
                {
                    "bind_address": "100.100.1.1",
                    "port": 8765,
                    "allowed_hosts": ["my-mac.tailnet.ts.net"],
                    "allowed_client_ips": ["127.0.0.1", "100.64.0.0/10"],
                    "trusted_devices": [{"name": "Owner-iPhone", "ip": "100.101.102.103"}],
                    "allowed_scan_paths": [tmpdir],
                }
            )
            ok_dev, dev_name = policy.client_status("100.101.102.103")
            self.assertTrue(ok_dev)
            self.assertEqual(dev_name, "Owner-iPhone")
            ok_ext, _ = policy.client_status("203.0.113.55")
            self.assertFalse(ok_ext)
            self.assertTrue(policy.host_allowed("my-mac.tailnet.ts.net:8765"))
            self.assertFalse(policy.host_allowed("evil.com:8765"))
            path_ok, _ = policy.path_allowed(str(Path(tmpdir) / "subdir"))
            self.assertTrue(path_ok)
            path_bad, _ = policy.path_allowed("/etc/passwd")
            self.assertFalse(path_bad)

    def test_trap_beacon_profiles_attacker_and_logs_tamper_evident_evidence(self):
        import json
        import tempfile
        from pathlib import Path
        from aegis.attacker_intel import AlertNotifier, AttackerProfiler, EvidenceLog, parse_rdap

        status, body = self._req(
            "GET",
            "/api/trap-beacon?token=sbi_live_decoy123&warn=1",
            {"User-Agent": "python-requests/2.31.0"},
        )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIn("evidence_sha256", payload)
        self.assertIn("legal_warning_banner", payload)

        status_ev, ev_body = self._req("GET", "/api/evidence-log", self._auth())
        self.assertEqual(status_ev, 200)
        ev_data = json.loads(ev_body)
        self.assertTrue(ev_data["chain_verification"]["valid"])
        self.assertGreaterEqual(ev_data["chain_verification"]["entries"], 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "evidence.jsonl"
            ev = EvidenceLog(str(log_file))
            ev.append({"event": "one"})
            ev.append({"event": "two"})
            self.assertTrue(ev.verify_chain()["valid"])
            # Tamper with the first entry
            lines = log_file.read_text(encoding="utf-8").splitlines()
            lines[0] = lines[0].replace('"one"', '"tampered"')
            log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertFalse(ev.verify_chain()["valid"])

        rdap_sample = {
            "name": "EXAMPLE-NET",
            "country": "JP",
            "startAddress": "203.0.113.0",
            "endAddress": "203.0.113.255",
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.jp"]]],
                }
            ],
        }
        parsed = parse_rdap(rdap_sample)
        self.assertEqual(parsed["abuse_emails"], ["abuse@example.jp"])
        sent = []
        notifier = AlertNotifier(
            mac_notify=lambda t, m: sent.append((t, m)),
            webhook_url="https://hooks.example.com/alert",
            sender=lambda u, b: sent.append((u, b)),
        )
        res = notifier.notify("Title", "Body")
        self.assertTrue(res["macos"])
        self.assertEqual(res["webhook"], "sent")
        self.assertEqual(len(sent), 2)


if __name__ == "__main__":
    unittest.main()
