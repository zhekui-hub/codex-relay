#!/usr/bin/env python3
# Author: zhekui
# Purpose: Install the relay as a Linux user service without overwriting an existing installation.
# Main functions: parse_origin validates the upstream; preflight checks the environment;
# probe_key validates credentials; install renders and starts services; main handles input.
"""Install the relay for the current Linux user without changing existing installs."""

import getpass
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
PLACEHOLDER_HOST = "upstream-a.invalid"
PLACEHOLDER_HOME = "/home/relay-user"
LABEL = "initial"
CA_FILE = Path("/etc/ssl/certs/ca-certificates.crt")
UNIT_NAMES = (
    "codex-relay-nginx.service",
    "codex-relay-key-probe.service",
    "codex-relay-key-probe.timer",
    "codex-relay-key-rotate.service",
    "codex-relay-key-rotate.timer",
    "codex-relay-key-failure-monitor.service",
)
START_UNITS = (
    "codex-relay-nginx.service",
    "codex-relay-key-probe.timer",
    "codex-relay-key-rotate.timer",
    "codex-relay-key-failure-monitor.service",
)
KEY_RE = re.compile(r"^[A-Za-z0-9._/+=:-]{1,512}$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def parse_origin(value):
    parsed = urlsplit(value.strip())
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid upstream port") from error
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or not HOST_RE.fullmatch(host)
        or host.endswith(".invalid")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or (port is not None and port != 443)
    ):
        raise ValueError("upstream must be an HTTPS origin on port 443, without path or credentials")
    origin = f"https://{host}"
    return origin, host


def render(source, home, nginx_bin, origin, host):
    text = source.replace(PLACEHOLDER_HOME + "/.local/share/codex-relay/bin/nginx", nginx_bin)
    text = text.replace(PLACEHOLDER_HOME, home)
    text = text.replace("https://" + PLACEHOLDER_HOST, origin)
    return text.replace(PLACEHOLDER_HOST, host)


def secure_nginx_config(config, nginx_dir):
    http_anchor = "http {\n"
    route_anchor = "        location /v1/ {\n"
    if config.count(http_anchor) != 1 or config.count(route_anchor) != 1:
        raise RuntimeError("Nginx template does not have the expected unique security anchors")
    config = config.replace(http_anchor, f"http {{\n    map_hash_bucket_size 128;\n    include {nginx_dir}/local-auth-map.conf;\n", 1)
    return config.replace(
        route_anchor,
        route_anchor
        + "            if ($relay_local_authorized = 0) { return 401; }\n"
        + "            proxy_ssl_verify on;\n"
        + "            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;\n"
        + "            proxy_ssl_verify_depth 3;\n",
        1,
    )


def write_private(path, content, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def run(argv, *, data=None, timeout=30):
    return subprocess.run(argv, input=data, text=True, capture_output=True, timeout=timeout, check=True)


def preflight(home, relay_dir, unit_dir):
    if sys.platform != "linux":
        raise RuntimeError("Linux with a user systemd session is required")
    if os.geteuid() == 0:
        raise RuntimeError("run as the intended ordinary user, not root")
    if not SAFE_PATH_RE.fullmatch(str(home)):
        raise RuntimeError("the home path contains unsupported characters")
    if relay_dir.exists() or relay_dir.is_symlink():
        raise RuntimeError(f"relay directory already exists: {relay_dir}")
    for name in UNIT_NAMES:
        path = unit_dir / name
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"systemd unit already exists: {path}")
    for name in ("nginx", "systemctl", "curl", "flock", "ss"):
        if shutil.which(name) is None:
            raise RuntimeError(f"missing dependency: {name}")
    for binary in ("/bin/bash", "/bin/chmod", "/bin/cp", "/bin/date", "/bin/mv", "/bin/printf",
                   "/bin/rm", "/bin/sed", "/bin/sleep", "/usr/bin/awk", "/usr/bin/curl",
                   "/usr/bin/flock", "/usr/bin/install", "/usr/bin/mktemp", "/usr/bin/ss",
                   "/usr/bin/systemctl", "/usr/bin/tail"):
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise RuntimeError(f"required executable not available: {binary}")
    nginx_bin = shutil.which("nginx")
    if not SAFE_PATH_RE.fullmatch(nginx_bin):
        raise RuntimeError("nginx path contains unsupported characters")
    if not CA_FILE.is_file():
        raise RuntimeError(f"CA bundle not found: {CA_FILE}")
    run(["systemctl", "--user", "show-environment"], timeout=10)
    for name in UNIT_NAMES:
        state = run(["systemctl", "--user", "show", name, "-p", "LoadState", "-p", "ActiveState"], timeout=10)
        fields = dict(line.split("=", 1) for line in state.stdout.splitlines() if "=" in line)
        if fields.get("LoadState") != "not-found" or fields.get("ActiveState") != "inactive":
            raise RuntimeError(f"systemd unit already exists or is active: {name}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 18080))
    return nginx_bin


def probe_key(origin, key):
    # curl reads the credential from stdin, never from process arguments.
    curl_config = f'header = "Authorization: Bearer {key}"\n'
    result = run(
        ["curl", "--config", "-", "--silent", "--show-error", "--output", "/dev/null",
         "--write-out", "%{http_code}", "--connect-timeout", "5", "--max-time", "20",
         origin + "/v1/models"],
        data=curl_config,
        timeout=25,
    )
    if result.stdout.strip() != "200":
        raise RuntimeError(f"upstream credential probe returned HTTP {result.stdout.strip() or '000'}")


def install(home, origin, host, key):
    relay_dir = home / ".local/share/codex-relay"
    nginx_dir = relay_dir / "nginx"
    unit_dir = home / ".config/systemd/user"
    nginx_bin = preflight(home, relay_dir, unit_dir)
    probe_key(origin, key)

    relay_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    relay_dir.mkdir(mode=0o700)
    unit_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    created_units = []
    try:
        nginx_dir.mkdir(mode=0o700)
        (relay_dir / "backups").mkdir(mode=0o700)
        (nginx_dir / "logs").mkdir(mode=0o700)
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (nginx_dir / "temp" / name).mkdir(parents=True, mode=0o700)

        for source in sorted((ROOT / "server").glob("*")):
            if source.suffix not in (".sh", ".py"):
                continue
            rendered = render(source.read_text(), str(home), nginx_bin, origin, host)
            write_private(relay_dir / source.name, rendered, 0o700)

        token = secrets.token_urlsafe(32)
        write_private(nginx_dir / "local-client.header", f"Authorization: Bearer {token}\n")
        write_private(nginx_dir / "local-auth-map.conf", (
            "map $http_authorization $relay_local_authorized {\n"
            "    default 0;\n"
            f'    "Bearer {token}" 1;\n'
            "}\n"
        ))
        config = render((ROOT / "nginx/nginx.conf").read_text(), str(home), nginx_bin, origin, host)
        config = secure_nginx_config(config, nginx_dir)
        write_private(nginx_dir / "nginx.conf", config)
        route = f"{LABEL}\t{origin}\t{key}\n"
        for name in ("upstream-auth-key-candidates", "upstream-auth-keys"):
            write_private(nginx_dir / name, route)
        auth = (
            f'set $relay_route_label "{LABEL}";\n'
            f"proxy_pass {origin};\n"
            f'proxy_set_header Host "{host}";\n'
            f'proxy_set_header Authorization "Bearer {key}";\n'
            "proxy_ssl_server_name on;\n"
            f'proxy_ssl_name "{host}";\n'
        )
        write_private(nginx_dir / "upstream-auth.conf", auth)
        write_private(nginx_dir / ".upstream-auth-key-index", "0\n")
        for name in ("upstream-auth-route-disabled", "upstream-auth-route-quarantine"):
            write_private(nginx_dir / name, "")
        write_private(nginx_dir / "logs/access.log", "")
        run([nginx_bin, "-t", "-g", f"error_log {nginx_dir}/logs/error.log warn;",
             "-p", str(nginx_dir), "-c", "nginx.conf"], timeout=15)

        for name in UNIT_NAMES:
            source = (ROOT / "systemd" / name).read_text()
            write_private(unit_dir / name, render(source, str(home), nginx_bin, origin, host))
            created_units.append(name)
        run(["systemctl", "--user", "daemon-reload"], timeout=15)
        for name in START_UNITS:
            run(["systemctl", "--user", "enable", "--now", name], timeout=30)
        result = run(["curl", "--silent", "--show-error", "--output", "/dev/null",
                      "--write-out", "%{http_code}", "--max-time", "10", "--header",
                      f"@{nginx_dir / 'local-client.header'}", "http://127.0.0.1:18080/v1/models"], timeout=15)
        if result.stdout.strip() != "200":
            raise RuntimeError(f"local relay probe returned HTTP {result.stdout.strip() or '000'}")
    except BaseException:
        # Preserve files for inspection; stop only units whose files this attempt created.
        cleanup_failed = []
        for name in START_UNITS:
            if name in created_units:
                try:
                    result = subprocess.run(["systemctl", "--user", "disable", "--now", name],
                                            capture_output=True, timeout=30, check=False)
                    if result.returncode != 0:
                        cleanup_failed.append(name)
                except (OSError, subprocess.SubprocessError):
                    cleanup_failed.append(name)
        if cleanup_failed:
            print("Could not stop/disable these units: " + ", ".join(cleanup_failed), file=sys.stderr)
        raise


def main():
    os.umask(0o077)
    key = ""
    def terminate(_signum, _frame):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, terminate)
    try:
        origin, host = parse_origin(input("Upstream HTTPS origin (without /v1): "))
        key = getpass.getpass("API Key (input hidden): ")
        if not KEY_RE.fullmatch(key):
            raise ValueError("API Key has an unsupported format")
        install(Path.home(), origin, host, key)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Installation failed: {error.__class__.__name__}. Check prerequisites and local service status.", file=sys.stderr)
        if isinstance(error, (ValueError, RuntimeError)):
            print(str(error), file=sys.stderr)
        elif isinstance(error, subprocess.CalledProcessError):
            program = Path(error.cmd[0]).name if isinstance(error.cmd, (tuple, list)) else "command"
            detail = (error.stderr or "").strip().splitlines()
            message = " | ".join(detail[-4:]) if detail else "no error detail"
            if key:
                message = message.replace(key, "[redacted]")
            message = re.sub(r"(?i)Bearer\s+[^\s'\";]+", "Bearer [redacted]", message)
            print(f"Failed command: {program}; exit {error.returncode}; {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Installation interrupted. Check the local service status and retained files.", file=sys.stderr)
        return 130
    print("Relay installed and /v1/models passed. Connect using an SSH local forward to 127.0.0.1:18080.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
