# Author: zhekui
# Purpose: Verify route enable, authenticated local probes, and rollback on failure.
# Main entry point: unittest discovers RouteManagementTests.
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ORIGIN = "https://upstream-a.invalid"
SPEC = importlib.util.spec_from_file_location("dashboard_remote_test", Path(__file__).parents[1] / "server/dashboard_remote.py")
remote = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote)


class RouteManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        relay = Path(self.temp.name) / "relay"
        nginx = relay / "nginx"
        (relay / "backups").mkdir(parents=True)
        nginx.mkdir()
        self.paths = {
            "RELAY_DIR": relay, "NGINX_DIR": nginx,
            "CANDIDATES_FILE": nginx / "upstream-auth-key-candidates",
            "ACTIVE_FILE": nginx / "upstream-auth-keys",
            "AUTH_FILE": nginx / "upstream-auth.conf",
            "STATE_FILE": nginx / ".upstream-auth-key-index",
            "PROBE_STATUS_FILE": nginx / "upstream-auth-key-probe.status",
            "QUARANTINE_FILE": nginx / "upstream-auth-route-quarantine",
            "DISABLED_FILE": nginx / "upstream-auth-route-disabled",
            "LOCK_FILE": nginx / ".upstream-auth-key.lock",
            "MANAGEMENT_BACKUP_MARKER": nginx / ".last-route-management-backup",
        }
        for name, path in self.paths.items():
            setattr(remote, name, path)
        self.paths["CANDIDATES_FILE"].write_text(f"user\t{ORIGIN}\tuser-key\ncurrent\t{ORIGIN}\tcurrent-key\n")
        self.paths["ACTIVE_FILE"].write_text(f"current\t{ORIGIN}\tcurrent-key\n")
        self.paths["AUTH_FILE"].write_text(f'set $relay_route_label "current";\nproxy_pass {ORIGIN};\n')
        self.paths["STATE_FILE"].write_text("0\n")
        self.paths["DISABLED_FILE"].write_text(f"user\t{ORIGIN}\t1\n")
        self.paths["QUARANTINE_FILE"].write_text("")
        self.paths["PROBE_STATUS_FILE"].write_text("checked_at=before\nroute=user status=disabled http=000\n")
        self.commands = []
        self.original_run = remote.run

    def tearDown(self):
        remote.run = self.original_run
        self.temp.cleanup()

    def snapshot(self):
        return {name: path.read_bytes() for name, path in self.paths.items()
                if name not in {"LOCK_FILE", "MANAGEMENT_BACKUP_MARKER"} and path.is_file()}

    def fake_run(self, argv, timeout=30, check=True):
        self.commands.append((list(argv), timeout))
        if argv[:2] == ["/usr/bin/ss", "-ltn"]:
            return subprocess.CompletedProcess(argv, 0, "LISTEN 127.0.0.1:18080\n", "")
        return subprocess.CompletedProcess(argv, 0, "active\n" if "is-active" in argv else "", "")

    def test_enable_waits_and_passes_private_header_to_probe(self):
        def run(argv, timeout=30, check=True):
            result = self.fake_run(argv, timeout, check)
            if argv == ["/usr/bin/systemctl", "--user", "start", "codex-relay-key-probe.service"]:
                self.paths["ACTIVE_FILE"].write_text(f"user\t{ORIGIN}\tuser-key\ncurrent\t{ORIGIN}\tcurrent-key\n")
                self.paths["STATE_FILE"].write_text("1\n")
                self.paths["PROBE_STATUS_FILE"].write_text("checked_at=after\nroute=user status=healthy http=200\n")
            return result
        remote.run = run
        result = remote.manage_route("enable", "user")
        self.assertTrue(result["active"])
        self.assertIn((["/usr/bin/systemctl", "--user", "start", "codex-relay-key-probe.service"], 180), self.commands)
        curl = next(argv for argv, _ in self.commands if argv[0] == "/usr/bin/curl")
        self.assertIn(f"@{self.paths['NGINX_DIR'] / 'local-client.header'}", curl)

    def test_enable_rolls_back_when_route_is_not_active(self):
        before = self.snapshot()
        remote.run = self.fake_run
        with self.assertRaisesRegex(RuntimeError, "rolled back"):
            remote.manage_route("enable", "user")
        self.assertEqual(self.snapshot(), before)

    def test_enable_rolls_back_when_probe_fails(self):
        before = self.snapshot()
        def run(argv, timeout=30, check=True):
            if argv == ["/usr/bin/systemctl", "--user", "start", "codex-relay-key-probe.service"]:
                raise subprocess.CalledProcessError(1, argv)
            return self.fake_run(argv, timeout, check)
        remote.run = run
        with self.assertRaisesRegex(RuntimeError, "rolled back"):
            remote.manage_route("enable", "user")
        self.assertEqual(self.snapshot(), before)

    def test_enable_preserves_concurrent_state_when_probe_fails(self):
        concurrent = f"user\t{ORIGIN}\tuser-key\ncurrent\t{ORIGIN}\tcurrent-key\nnew\t{ORIGIN}\tnew-key\n"
        def run(argv, timeout=30, check=True):
            if argv == ["/usr/bin/systemctl", "--user", "start", "codex-relay-key-probe.service"]:
                self.paths["CANDIDATES_FILE"].write_text(concurrent)
                raise subprocess.CalledProcessError(1, argv)
            return self.fake_run(argv, timeout, check)
        remote.run = run
        with self.assertRaisesRegex(RuntimeError, "managed state changed after write, rollback skipped"):
            remote.manage_route("enable", "user")
        self.assertEqual(self.paths["CANDIDATES_FILE"].read_text(), concurrent)
        self.assertFalse(any("stop" in argv for argv, _ in self.commands))

    def test_add_preserves_concurrent_state_when_probe_fails(self):
        concurrent = f"user\t{ORIGIN}\tuser-key\ncurrent\t{ORIGIN}\tcurrent-key\nextra\t{ORIGIN}\textra-key\n"
        def run(argv, timeout=30, check=True):
            if argv == ["/usr/bin/systemctl", "--user", "start", "codex-relay-key-probe.service"]:
                self.paths["CANDIDATES_FILE"].write_text(concurrent)
                raise subprocess.CalledProcessError(1, argv)
            return self.fake_run(argv, timeout, check)
        remote.run = run
        old_probe = remote.probe_credential
        remote.probe_credential = lambda *_args: None
        try:
            with self.assertRaisesRegex(RuntimeError, "managed state changed after write, rollback skipped"):
                remote.add_route({"label": "third", "origin": ORIGIN, "api_key": "third-key"})
        finally:
            remote.probe_credential = old_probe
        self.assertEqual(self.paths["CANDIDATES_FILE"].read_text(), concurrent)
        self.assertFalse(any("stop" in argv for argv, _ in self.commands))

    def test_own_probe_update_then_local_failure_is_not_called_concurrent(self):
        def run(argv, timeout=30, check=True):
            if argv == ["/usr/bin/systemctl", "--user", "start", "codex-relay-key-probe.service"]:
                self.paths["PROBE_STATUS_FILE"].write_text("checked_at=after\n")
                return self.fake_run(argv, timeout, check)
            if argv[0] == "/usr/bin/curl":
                raise subprocess.CalledProcessError(1, argv)
            return self.fake_run(argv, timeout, check)
        remote.run = run
        with self.assertRaisesRegex(RuntimeError, "managed state changed after write, rollback skipped"):
            remote.manage_route("enable", "user")
        self.assertEqual(self.paths["PROBE_STATUS_FILE"].read_text(), "checked_at=after\n")
        self.assertFalse(any("stop" in argv for argv, _ in self.commands))

    def test_disable_failure_does_not_stop_an_unrelated_probe(self):
        self.paths["DISABLED_FILE"].write_text("")
        self.paths["ACTIVE_FILE"].write_text(f"user\t{ORIGIN}\tuser-key\ncurrent\t{ORIGIN}\tcurrent-key\n")
        self.paths["STATE_FILE"].write_text("1\n")
        before = self.snapshot()
        def run(argv, timeout=30, check=True):
            if argv[0] == "/usr/bin/curl":
                raise subprocess.CalledProcessError(1, argv)
            return self.fake_run(argv, timeout, check)
        remote.run = run
        with self.assertRaisesRegex(RuntimeError, "rolled back"):
            remote.manage_route("disable", "user")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(any("stop" in argv for argv, _ in self.commands))


if __name__ == "__main__":
    unittest.main()
