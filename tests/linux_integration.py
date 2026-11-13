#!/usr/bin/env python3
# Author: zhekui
# Purpose: Exercise the interactive installer and authenticated relay in disposable Linux.
# Main functions: run_installer drives the TTY; request checks the relay; main owns the fixture.
"""Run only as root inside the disposable systemd test container."""

import http.client
import http.server
import os
import pty
import pwd
import select
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


FAKE_KEY = "integration-fixture-key"
ORIGIN = "https://upstream.test"


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        authorized = self.headers.get("Authorization") == "Bearer " + FAKE_KEY
        self.send_response(200 if authorized and self.path == "/v1/models" else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"object":"list","data":[]}')

    def log_message(self, *_args):
        pass


def run_installer(account):
    child, fd = pty.fork()
    if child == 0:
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        env = {
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "XDG_RUNTIME_DIR": f"/run/user/{account.pw_uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{account.pw_uid}/bus",
        }
        os.execve("/usr/bin/python3", ["python3", "/workspace/install.py"], env)
    output = b""
    sent_origin = sent_key = False
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 1)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            if not sent_origin and b"Upstream HTTPS origin" in output:
                os.write(fd, (ORIGIN + "\n").encode())
                sent_origin = True
            if not sent_key and b"API Key (input hidden)" in output:
                os.write(fd, (FAKE_KEY + "\n").encode())
                sent_key = True
        pid, status = os.waitpid(child, os.WNOHANG)
        if pid:
            return os.waitstatus_to_exitcode(status), output.decode(errors="replace")
    os.close(fd)
    pid, status = os.waitpid(child, os.WNOHANG)
    if not pid:
        os.kill(child, 15)
        os.waitpid(child, 0)
        raise RuntimeError("installer did not finish within the test timeout")
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


def request(path, header=None):
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=10)
    conn.request("GET", path, headers={"Authorization": header} if header else {})
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response.status, body


def main():
    if (os.geteuid() != 0 or os.environ.get("RELAY_TEST_DISPOSABLE") != "1"
            or not Path("/.dockerenv").is_file()
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or not Path("/workspace/install.py").is_file()):
        raise RuntimeError("run only in the disposable container with the repository mounted")
    subprocess.run(["useradd", "-m", "-s", "/bin/bash", "relaytest"], check=True)
    account = pwd.getpwnam("relaytest")
    Path("/etc/hosts").open("a").write("\n127.0.0.1 upstream.test\n")
    with tempfile.TemporaryDirectory(prefix="relay-test-", dir="/root") as tmp:
        cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
        certificate = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=upstream.test",
            "-addext", "subjectAltName=DNS:upstream.test",
        ], capture_output=True, text=True)
        if certificate.returncode:
            raise RuntimeError(f"fixture certificate creation failed: {certificate.stderr.strip()}")
        with open("/etc/ssl/certs/ca-certificates.crt", "ab") as bundle:
            bundle.write(cert.read_bytes())
        httpd = http.server.HTTPServer(("127.0.0.1", 443), Upstream)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        for _ in range(45):
            probe = subprocess.run(["loginctl", "list-users", "--no-legend"], capture_output=True, text=True)
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            failed = subprocess.run(["systemctl", "--no-pager", "--failed"], capture_output=True, text=True)
            raise RuntimeError(f"system bus/logind not ready: {probe.stderr.strip()}; {failed.stdout.strip()} {failed.stderr.strip()}")
        subprocess.run(["loginctl", "enable-linger", account.pw_name], check=True)
        env = os.environ | {
            "XDG_RUNTIME_DIR": f"/run/user/{account.pw_uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{account.pw_uid}/bus",
        }
        for _ in range(30):
            probe = subprocess.run(["runuser", "-u", account.pw_name, "--", "systemctl", "--user", "show-environment"],
                                   env=env, capture_output=True)
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("user systemd session did not become ready")

        code, output = run_installer(account)
        if FAKE_KEY in output:
            raise RuntimeError("fixture key appeared in installer output")
        if code != 0:
            raise RuntimeError(f"installer failed (exit {code}): {output}")
        header_path = Path(account.pw_dir) / ".local/share/codex-relay/nginx/local-client.header"
        header = header_path.read_text().strip().removeprefix("Authorization: ")
        assert request("/healthz")[0] == 200
        assert request("/v1/models")[0] == 401
        status, body = request("/v1/models", header)
        assert status == 200 and b'"data"' in body
        assert header_path.stat().st_mode & 0o777 == 0o600
        result = subprocess.run(["runuser", "-u", account.pw_name, "--", "systemctl", "--user", "is-active",
                                 *["codex-relay-nginx.service", "codex-relay-key-probe.timer",
                                   "codex-relay-key-rotate.timer", "codex-relay-key-failure-monitor.service"]],
                                env=env, capture_output=True, text=True, check=True)
        assert result.stdout.splitlines() == ["active"] * 4
        print("PASS: installer, authenticated relay, upstream TLS and all four units")
        httpd.shutdown()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"integration failed: {error}", file=sys.stderr)
        sys.exit(1)
