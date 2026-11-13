# Author: zhekui
# Purpose: Test input validation, rendered configuration, and installation failure handling.
# Main entry point: unittest discovers the InstallerTests methods.
"""Exercise installer validation, generated files, and failure handling locally."""

import importlib.util
import contextlib
import io
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("relay_install", Path(__file__).parents[1] / "install.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_command_error_diagnostics_redact_key(self):
        output = io.StringIO()
        error = subprocess.CalledProcessError(1, ["curl"], stderr="bad Bearer test-key")
        with patch("builtins.input", return_value="https://api.example.com"), \
                patch.object(installer.getpass, "getpass", return_value="test-key"), \
                patch.object(installer, "install", side_effect=error), \
                contextlib.redirect_stderr(output):
            self.assertEqual(installer.main(), 1)
        self.assertIn("Failed command: curl", output.getvalue())
        self.assertNotIn("test-key", output.getvalue())

    def test_origin_validation(self):
        self.assertEqual(installer.parse_origin("https://api.example.com/"), ("https://api.example.com", "api.example.com"))
        for value in ("http://api.example.com", "https://upstream-a.invalid", "https://user:pass@api.example.com", "https://api.example.com/v1", "https://api.example.com?x=1", "https://api.example.com:8443"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                installer.parse_origin(value)

    def test_changed_nginx_template_fails_closed(self):
        for template in ("http {\n location /v1/ {\n", "http {\n        location /v1/ {\n        location /v1/ {\n"):
            with self.subTest(template=template), self.assertRaisesRegex(RuntimeError, "security anchors"):
                installer.secure_nginx_config(template, Path("/tmp/example"))

    def test_probe_passes_key_through_stdin(self):
        completed = subprocess.CompletedProcess([], 0, "200", "")
        with patch.object(installer, "run", return_value=completed) as run:
            installer.probe_key("https://api.example.com", "test-key")
        args, kwargs = run.call_args
        self.assertNotIn("test-key", str(args))
        self.assertIn("test-key", kwargs["data"])

    def test_rejected_key_does_not_create_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_home = Path(tmp)
            with patch.object(installer, "preflight", return_value="/usr/sbin/nginx"), \
                    patch.object(installer, "probe_key", side_effect=RuntimeError("HTTP 401")):
                with self.assertRaisesRegex(RuntimeError, "HTTP 401"):
                    installer.install(task_home, "https://api.example.com", "api.example.com", "test-key")
            self.assertFalse((task_home / ".local/share/codex-relay").exists())

    def test_loaded_systemd_unit_blocks_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_home = Path(tmp)
            def fake_run(argv, **kwargs):
                output = "LoadState=loaded\nActiveState=active\n" if "show" in argv else ""
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(installer.sys, "platform", "linux"), \
                    patch.object(os, "geteuid", return_value=1000), \
                    patch.object(installer.shutil, "which", return_value="/usr/sbin/nginx"), \
                    patch.object(installer, "CA_FILE", task_home), \
                    patch.object(Path, "is_file", return_value=True), \
                    patch.object(os.path, "isfile", return_value=True), \
                    patch.object(os, "access", return_value=True), \
                    patch.object(installer, "run", side_effect=fake_run):
                with self.assertRaisesRegex(RuntimeError, "already exists or is active"):
                    installer.preflight(task_home, task_home / "relay", task_home / "units")

    def test_install_renders_files_and_enables_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_home = Path(tmp)
            commands = []

            def fake_run(argv, **kwargs):
                commands.append(argv)
                output = "200" if "http://127.0.0.1:18080/v1/models" in argv else ""
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(installer, "preflight", return_value="/usr/sbin/nginx"), \
                    patch.object(installer, "probe_key") as probe, \
                    patch.object(installer, "run", side_effect=fake_run):
                installer.install(task_home, "https://api.example.com", "api.example.com", "test-key")

            relay = task_home / ".local/share/codex-relay"
            config = (relay / "nginx/nginx.conf").read_text()
            self.assertIn("proxy_pass https://api.example.com/v1/;", config)
            self.assertIn("if ($relay_local_authorized = 0) { return 401; }", config)
            self.assertIn("map_hash_bucket_size 128;", config)
            self.assertIn("proxy_ssl_verify on;", config)
            self.assertNotIn("upstream-a.invalid", config)
            self.assertNotIn("Bearer ", config)
            self.assertIn("https://api.example.com", (relay / "route-lib.sh").read_text())
            self.assertIn("https://api.example.com", (relay / "dashboard_remote.py").read_text())
            self.assertEqual(stat.S_IMODE((relay / "nginx/upstream-auth.conf").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((relay / "nginx/upstream-auth-key-candidates").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((relay / "nginx/local-client.header").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((relay / "nginx/local-auth-map.conf").stat().st_mode), 0o600)
            self.assertTrue(all("test-key" not in str(command) for command in commands))
            self.assertEqual(sum(command[2:4] == ["enable", "--now"] for command in commands), 4)
            probe.assert_called_once_with("https://api.example.com", "test-key")

    def test_existing_install_fails_before_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_home = Path(tmp)
            relay = task_home / ".local/share/codex-relay"
            relay.mkdir(parents=True)
            marker = relay / "keep"
            marker.write_text("unchanged")
            with patch.object(installer.sys, "platform", "linux"), patch.object(os, "geteuid", return_value=1000):
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    installer.install(task_home, "https://api.example.com", "api.example.com", "test-key")
            self.assertEqual(marker.read_text(), "unchanged")

    def test_failure_disables_only_created_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_home = Path(tmp)
            calls = []

            def fake_run(argv, **kwargs):
                if argv[0] == "systemctl" and "enable" in argv:
                    raise subprocess.CalledProcessError(1, argv)
                return subprocess.CompletedProcess(argv, 0, "", "")

            def fake_cleanup(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(installer, "preflight", return_value="/usr/sbin/nginx"), \
                    patch.object(installer, "probe_key"), \
                    patch.object(installer, "run", side_effect=fake_run), \
                    patch.object(installer.subprocess, "run", side_effect=fake_cleanup):
                with self.assertRaises(subprocess.CalledProcessError):
                    installer.install(task_home, "https://api.example.com", "api.example.com", "test-key")
            self.assertEqual({call[-1] for call in calls}, set(installer.START_UNITS))
            self.assertTrue((task_home / ".local/share/codex-relay/nginx/upstream-auth.conf").exists())

    def test_interrupt_stops_created_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_home = Path(tmp)
            calls = []

            def fake_run(argv, **kwargs):
                if argv[0] == "systemctl" and "enable" in argv:
                    raise KeyboardInterrupt()
                return subprocess.CompletedProcess(argv, 0, "", "")

            def fake_cleanup(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")

            with patch.object(installer, "preflight", return_value="/usr/sbin/nginx"), \
                    patch.object(installer, "probe_key"), \
                    patch.object(installer, "run", side_effect=fake_run), \
                    patch.object(installer.subprocess, "run", side_effect=fake_cleanup):
                with self.assertRaises(KeyboardInterrupt):
                    installer.install(task_home, "https://api.example.com", "api.example.com", "test-key")
            self.assertEqual({call[-1] for call in calls}, set(installer.START_UNITS))

    def test_redirect_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            task_home = Path(tmp)
            def fake_run(argv, **kwargs):
                output = "302" if "http://127.0.0.1:18080/v1/models" in argv else ""
                return subprocess.CompletedProcess(argv, 0, output, "")
            with patch.object(installer, "preflight", return_value="/usr/sbin/nginx"), \
                    patch.object(installer, "probe_key"), \
                    patch.object(installer, "run", side_effect=fake_run), \
                    patch.object(installer.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                with self.assertRaisesRegex(RuntimeError, "HTTP 302"):
                    installer.install(task_home, "https://api.example.com", "api.example.com", "test-key")


if __name__ == "__main__":
    unittest.main()
