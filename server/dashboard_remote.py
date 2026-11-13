#!/usr/bin/env python3
"""Return metadata-only relay status and run allowlisted operations."""

import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path


HOME = Path.home()
RELAY_DIR = HOME / ".local/share/codex-relay"
NGINX_DIR = RELAY_DIR / "nginx"
SERVICE_UNITS = (
    "codex-relay-nginx.service",
    "codex-relay-key-probe.timer",
    "codex-relay-key-rotate.timer",
    "codex-relay-key-failure-monitor.service",
)
ALLOWED_ORIGINS = {
    "https://upstream-a.invalid",
    "https://upstream-b.invalid",
}
ADDABLE_ORIGINS = {"https://upstream-a.invalid"}
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9._/+=:-]+$")
MAX_LABEL_LENGTH = 64
CANDIDATES_FILE = NGINX_DIR / "upstream-auth-key-candidates"
ACTIVE_FILE = NGINX_DIR / "upstream-auth-keys"
AUTH_FILE = NGINX_DIR / "upstream-auth.conf"
STATE_FILE = NGINX_DIR / ".upstream-auth-key-index"
PROBE_STATUS_FILE = NGINX_DIR / "upstream-auth-key-probe.status"
QUARANTINE_FILE = NGINX_DIR / "upstream-auth-route-quarantine"
DISABLED_FILE = NGINX_DIR / "upstream-auth-route-disabled"
LOCK_FILE = NGINX_DIR / ".upstream-auth-key.lock"
MANAGEMENT_BACKUP_MARKER = NGINX_DIR / ".last-route-management-backup"


def run(argv, timeout=30, check=True):
    return subprocess.run(
        argv,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def read_lines(path):
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, PermissionError):
        return []


def valid_label(value):
    return isinstance(value, str) and len(value) <= MAX_LABEL_LENGTH and LABEL_RE.fullmatch(value)


def route_records(path, default_origin=None):
    records = []
    for line in read_lines(path):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) == 3:
            label, origin, _credential = fields
        elif len(fields) == 2 and default_origin:
            label, _credential = fields
            origin = default_origin
        else:
            continue
        if valid_label(label) and origin in ALLOWED_ORIGINS:
            records.append({"label": label, "origin": origin})
    return records


def private_route_records(path):
    records = []
    labels = set()
    for line in read_lines(path):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) == 3:
            label, origin, credential = fields
        elif len(fields) == 2:
            label, credential = fields
            origin = "https://upstream-a.invalid"
        else:
            raise RuntimeError(f"invalid route record in {path.name}")
        if (
            not valid_label(label)
            or label in labels
            or origin not in ALLOWED_ORIGINS
            or not CREDENTIAL_RE.fullmatch(credential)
        ):
            raise RuntimeError(f"invalid route record in {path.name}")
        labels.add(label)
        records.append((label, origin, credential))
    return records


def route_control_records(path):
    records = []
    labels = set()
    for line in read_lines(path):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 3:
            raise RuntimeError(f"invalid route control record in {path.name}")
        label, origin, observed = fields
        if (
            not valid_label(label)
            or label in labels
            or origin not in ALLOWED_ORIGINS
            or not observed.isdigit()
        ):
            raise RuntimeError(f"invalid route control record in {path.name}")
        labels.add(label)
        records.append((label, origin, int(observed)))
    return records


def atomic_write(path, lines):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line)
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def format_private_routes(records):
    return ["\t".join(record) for record in records]


def format_control_routes(records):
    return [f"{label}\t{origin}\t{observed}" for label, origin, observed in records]


def create_management_backup(paths):
    stamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    backup = RELAY_DIR / "backups" / f"route-management-{stamp}-{time.time_ns()}"
    backup.mkdir(mode=0o700, parents=True)
    existing = set()
    for path in paths:
        if path.exists():
            shutil.copy2(path, backup / path.name)
            existing.add(path.name)
    return backup, existing


def restore_management_backup(backup, existing, paths):
    for path in paths:
        source = backup / path.name
        if path.name in existing:
            shutil.copy2(source, path)
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def managed_fingerprints(paths):
    result = {}
    for path in paths:
        try:
            result[path.name] = hashlib.sha256(path.read_bytes()).digest()
        except FileNotFoundError:
            result[path.name] = None
    return result


def management_backup_name():
    marker = read_lines(MANAGEMENT_BACKUP_MARKER)
    return Path(marker[0]).name if marker else ""


def probe_status():
    result = {"checked_at": "", "candidate_count": 0, "healthy_count": 0, "routes": {}}
    for line in read_lines(NGINX_DIR / "upstream-auth-key-probe.status"):
        if line.startswith("checked_at="):
            result["checked_at"] = line.split("=", 1)[1]
        elif line.startswith("candidate_count="):
            result["candidate_count"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("healthy_count="):
            result["healthy_count"] = int(line.split("=", 1)[1] or 0)
        else:
            match = re.match(r"^(?:route|key)=([^ ]+) status=([^ ]+) http=([0-9]{3})$", line)
            if match and valid_label(match.group(1)):
                result["routes"][match.group(1)] = {
                    "state": match.group(2),
                    "http": match.group(3),
                }
    return result


def current_route():
    label = ""
    origin = ""
    for line in read_lines(NGINX_DIR / "upstream-auth.conf"):
        label_match = re.search(r'set\s+\$relay_route_label\s+"([A-Za-z0-9._-]+)";', line)
        if label_match:
            label = label_match.group(1)
        origin_match = re.search(r"proxy_pass\s+(https://[^;]+);", line)
        if origin_match and origin_match.group(1) in ALLOWED_ORIGINS:
            origin = origin_match.group(1)
    try:
        index = int((NGINX_DIR / ".upstream-auth-key-index").read_text().strip())
    except (FileNotFoundError, ValueError):
        index = -1
    return {"label": label, "origin": origin, "index": index}


def quarantine_records():
    now = int(time.time())
    records = []
    for line in read_lines(NGINX_DIR / "upstream-auth-route-quarantine"):
        fields = line.split("\t")
        if len(fields) != 3:
            continue
        label, origin, observed = fields
        try:
            observed_epoch = int(observed)
        except ValueError:
            continue
        if valid_label(label) and origin in ALLOWED_ORIGINS:
            records.append(
                {
                    "label": label,
                    "origin": origin,
                    "observed_epoch": observed_epoch,
                    "age_seconds": max(0, now - observed_epoch),
                }
            )
    return records


def disabled_records():
    now = int(time.time())
    return [
        {
            "label": label,
            "origin": origin,
            "observed_epoch": observed,
            "age_seconds": max(0, now - observed),
        }
        for label, origin, observed in route_control_records(DISABLED_FILE)
    ]


def service_state(unit):
    completed = run(
        ["/usr/bin/systemctl", "--user", "is-active", unit],
        timeout=8,
        check=False,
    )
    return completed.stdout.strip() or "unknown"


def timer_state(unit):
    completed = run(
        [
            "/usr/bin/systemctl",
            "--user",
            "show",
            unit,
            "-p",
            "LastTriggerUSec",
            "-p",
            "NextElapseUSecRealtime",
        ],
        timeout=8,
        check=False,
    )
    values = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return {
        "last": values.get("LastTriggerUSec", ""),
        "next": values.get("NextElapseUSecRealtime", ""),
    }


def recent_requests(limit=16):
    entries = []
    allowed = {
        "method",
        "path",
        "route",
        "status",
        "upstream_status",
        "request_time",
        "upstream_time",
    }
    for line in read_lines(NGINX_DIR / "logs/access.log")[-200:]:
        fields = line.split()
        if not fields:
            continue
        entry = {"time": fields[0]}
        for field in fields[1:]:
            if "=" not in field:
                continue
            key, value = field.split("=", 1)
            if key in allowed:
                entry[key] = value
        if entry.get("path", "").startswith("/v1/"):
            entries.append(entry)
    return entries[-limit:][::-1]


def listener_state():
    completed = run(["/usr/bin/ss", "-ltn"], timeout=8, check=False)
    return "127.0.0.1:18080" in completed.stdout


def last_failure():
    result = {}
    for line in read_lines(NGINX_DIR / "upstream-auth-key-failure.status"):
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"failed_route", "failed_route_index", "remaining_count", "observed_at"}:
            result[key] = value
    return result


def build_status():
    candidates = route_records(
        NGINX_DIR / "upstream-auth-key-candidates",
        default_origin="https://upstream-a.invalid",
    )
    active = route_records(
        NGINX_DIR / "upstream-auth-keys",
        default_origin="https://upstream-a.invalid",
    )
    active_labels = {item["label"] for item in active}
    quarantined = quarantine_records()
    quarantined_labels = {item["label"] for item in quarantined}
    disabled = disabled_records()
    disabled_labels = {item["label"] for item in disabled}
    probe = probe_status()
    current = current_route()
    routes = []
    for item in candidates:
        label = item["label"]
        route_probe = probe["routes"].get(label, {})
        routes.append(
            {
                "label": label,
                "origin": item["origin"],
                "probe_state": route_probe.get("state", "unknown"),
                "http": route_probe.get("http", ""),
                "active": label in active_labels,
                "current": label == current["label"],
                "quarantined": label in quarantined_labels,
                "disabled": label in disabled_labels,
            }
        )
    backup_marker = read_lines(NGINX_DIR / ".last-route-upgrade-backup")
    return {
        "host": socket.gethostname(),
        "listener": listener_state(),
        "services": {unit: service_state(unit) for unit in SERVICE_UNITS},
        "timers": {
            "probe": timer_state("codex-relay-key-probe.timer"),
            "rotate": timer_state("codex-relay-key-rotate.timer"),
        },
        "current": current,
        "candidate_count": len(candidates),
        "active_count": len(active),
        "probe": probe,
        "routes": routes,
        "quarantine": quarantined,
        "disabled": disabled,
        "last_failure": last_failure(),
        "recent_requests": recent_requests(),
        "backup": Path(backup_marker[0]).name if backup_marker else "",
        "management_backup": management_backup_name(),
    }


def manage_route(action, label, confirmation=""):
    if action not in {"disable", "enable", "delete"} or not valid_label(label):
        raise ValueError("unsupported route operation")
    if action == "delete" and confirmation != label:
        raise ValueError("route deletion confirmation mismatch")

    managed_paths = (
        CANDIDATES_FILE,
        ACTIVE_FILE,
        AUTH_FILE,
        STATE_FILE,
        PROBE_STATUS_FILE,
        QUARANTINE_FILE,
        DISABLED_FILE,
        MANAGEMENT_BACKUP_MARKER,
    )
    backup = None
    existing = set()
    LOCK_FILE.touch(mode=0o600, exist_ok=True)
    LOCK_FILE.chmod(0o600)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        candidates = private_route_records(CANDIDATES_FILE)
        active = private_route_records(ACTIVE_FILE)
        quarantine = route_control_records(QUARANTINE_FILE)
        disabled = route_control_records(DISABLED_FILE)
        current = current_route()
        candidate = next((item for item in candidates if item[0] == label), None)
        if candidate is None:
            raise ValueError("route does not exist")
        if current["label"] == label:
            raise ValueError("current route must be rotated before management")
        disabled_labels = {item[0] for item in disabled}
        if action == "disable" and label in disabled_labels:
            raise ValueError("route is already disabled")
        if action == "enable" and label not in disabled_labels:
            raise ValueError("route is not disabled")
        if action == "delete" and len(candidates) <= 1:
            raise ValueError("at least one candidate route must remain")

        next_candidates = candidates
        next_active = active
        next_quarantine = quarantine
        next_disabled = disabled
        if action == "disable":
            next_active = [item for item in active if item[0] != label]
            next_disabled = [item for item in disabled if item[0] != label]
            next_disabled.append((candidate[0], candidate[1], int(time.time())))
        elif action == "enable":
            next_disabled = [item for item in disabled if item[0] != label]
        else:
            next_candidates = [item for item in candidates if item[0] != label]
            next_active = [item for item in active if item[0] != label]
            next_quarantine = [item for item in quarantine if item[0] != label]
            next_disabled = [item for item in disabled if item[0] != label]

        current_index = next(
            (
                index
                for index, item in enumerate(next_active)
                if item[0] == current["label"] and item[1] == current["origin"]
            ),
            -1,
        )
        if not next_active or current_index < 0:
            raise RuntimeError("route operation would invalidate the active route")

        backup, existing = create_management_backup(managed_paths)
        try:
            atomic_write(CANDIDATES_FILE, format_private_routes(next_candidates))
            atomic_write(ACTIVE_FILE, format_private_routes(next_active))
            atomic_write(STATE_FILE, [str(current_index)])
            atomic_write(QUARANTINE_FILE, format_control_routes(next_quarantine))
            atomic_write(DISABLED_FILE, format_control_routes(next_disabled))
            atomic_write(MANAGEMENT_BACKUP_MARKER, [str(backup)])
            after_write = managed_fingerprints(managed_paths)
        except Exception:
            restore_management_backup(backup, existing, managed_paths)
            raise
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    try:
        if action == "enable":
            run(
                [
                    "/usr/bin/systemctl",
                    "--user",
                    "start",
                    "codex-relay-key-probe.service",
                ],
                timeout=180,
            )
        run(
            [
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "25",
                "--header",
                f"@{NGINX_DIR / 'local-client.header'}",
                "http://127.0.0.1:18080/v1/models",
            ],
            timeout=30,
        )
        status = build_status()
        route = next((item for item in status["routes"] if item["label"] == label), None)
        if action == "disable" and (
            route is None or not route["disabled"] or route["active"]
        ):
            raise RuntimeError("route disable did not reach the requested state")
        if action == "enable" and (route is None or not route["active"] or route["disabled"] or route["quarantined"]):
            raise RuntimeError("route enable did not reach the requested state")
        if action == "delete" and route is not None:
            raise RuntimeError("route delete did not reach the requested state")
    except Exception as error:
        with LOCK_FILE.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if managed_fingerprints(managed_paths) != after_write:
                raise RuntimeError("route operation failed; managed state changed after write, rollback skipped; inspect the retained backup") from error
            restore_management_backup(backup, existing, managed_paths)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        reload_result = run(
            [
                "/usr/bin/systemctl",
                "--user",
                "reload",
                "codex-relay-nginx.service",
            ],
            timeout=15,
            check=False,
        )
        if reload_result.returncode != 0:
            raise RuntimeError("route operation rollback completed but Nginx reload failed") from error
        raise RuntimeError("route operation failed validation and was rolled back") from error

    return {
        "action": action,
        "state": "completed",
        "changed": True,
        "label": label,
        "active": bool(route and route["active"]),
        "backup": backup.name,
    }


def probe_credential(origin, credential):
    """Probe a credential without exposing it in argv, logs, or status output."""
    descriptor, header_path = tempfile.mkstemp(
        prefix=".upstream-auth-key-probe-", dir=NGINX_DIR
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"Authorization: Bearer {credential}\n")
        probe = run(
            [
                "/usr/bin/curl",
                "--silent",
                "--connect-timeout",
                "5",
                "--max-time",
                "15",
                "--header",
                f"@{header_path}",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                f"{origin}/v1/models",
            ],
            timeout=25,
            check=False,
        )
        status = probe.stdout.strip() or "000"
        if status != "200":
            raise RuntimeError(f"new route probe failed: HTTP {status}")
    finally:
        try:
            Path(header_path).unlink()
        except FileNotFoundError:
            pass


def rewrite_auth_config(lines, label, origin, credential):
    """Update only the route-specific Nginx directives while preserving the template."""
    host = origin.split("://", 1)[1].rstrip("/")
    rewritten = []
    found = {"label": False, "pass": False, "host": False, "auth": False, "ssl": False}
    for line in lines:
        if re.match(r'\s*set\s+\$relay_route_label\s+', line):
            line = f'set $relay_route_label "{label}";'
            found["label"] = True
        elif re.match(r"\s*proxy_pass\s+https://", line):
            line = f"proxy_pass {origin};"
            found["pass"] = True
        elif re.match(r'\s*proxy_set_header\s+Host\s+', line):
            line = f'proxy_set_header Host "{host}";'
            found["host"] = True
        elif re.match(r'\s*proxy_set_header\s+Authorization\s+', line):
            line = f'proxy_set_header Authorization "Bearer {credential}";'
            found["auth"] = True
        elif re.match(r'\s*proxy_ssl_name\s+', line):
            line = f'proxy_ssl_name "{host}";'
            found["ssl"] = True
        rewritten.append(line)
    if not all(found.values()):
        raise RuntimeError("invalid upstream auth template")
    return rewritten


def update_probe_status(
    lines, old_label, new_label, candidate_count, healthy_count, state=None, http=None
):
    rewritten = []
    found = False
    for line in lines:
        match = re.match(r"^((?:route|key)=)([^ ]+)( status=[^ ]+ http=[0-9]{3})$", line)
        if match and match.group(2) == old_label:
            suffix = match.group(3)
            if state is not None and http is not None:
                suffix = f" status={state} http={http}"
            line = f"{match.group(1)}{new_label}{suffix}"
            found = True
        if line.startswith("candidate_count=") or line.startswith("healthy_count="):
            continue
        rewritten.append(line)
    if not found and state is not None and http is not None:
        rewritten.append(f"route={new_label} status={state} http={http}")
    rewritten.extend(
        [f"candidate_count={candidate_count}", f"healthy_count={healthy_count}"]
    )
    return rewritten


def update_route(payload):
    """Rename a route and optionally replace its credential in one rollback-safe transaction."""
    if not isinstance(payload, dict):
        raise ValueError("invalid route update payload")
    old_label = payload.get("label")
    new_label = payload.get("new_label")
    origin = payload.get("origin")
    credential = payload.get("api_key", "")
    if (
        not valid_label(old_label)
        or not valid_label(new_label)
        or not isinstance(origin, str)
        or origin not in ALLOWED_ORIGINS
        or not isinstance(credential, str)
        or len(credential) > 512
        or (credential and not CREDENTIAL_RE.fullmatch(credential))
    ):
        raise ValueError("invalid route update payload")
    credential = credential or None

    if credential is not None:
        probe_credential(origin, credential)

    managed_paths = (
        CANDIDATES_FILE,
        ACTIVE_FILE,
        AUTH_FILE,
        STATE_FILE,
        PROBE_STATUS_FILE,
        QUARANTINE_FILE,
        DISABLED_FILE,
        MANAGEMENT_BACKUP_MARKER,
    )
    backup = None
    existing = set()
    LOCK_FILE.touch(mode=0o600, exist_ok=True)
    LOCK_FILE.chmod(0o600)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        candidates = private_route_records(CANDIDATES_FILE)
        active = private_route_records(ACTIVE_FILE)
        quarantine = route_control_records(QUARANTINE_FILE)
        disabled = route_control_records(DISABLED_FILE)
        candidate = next((item for item in candidates if item[0] == old_label), None)
        if candidate is None:
            raise ValueError("route does not exist")
        if origin != candidate[1] and credential is None:
            raise ValueError("route origin change requires a new credential")
        if credential is not None and any(
            item[0] != old_label and item[2] == credential for item in candidates
        ):
            raise ValueError("route credential already exists")
        if credential == candidate[2]:
            credential = None
        if new_label == old_label and origin == candidate[1] and credential is None:
            return {
                "action": "update",
                "state": "completed",
                "changed": False,
                "label": old_label,
                "previous_label": old_label,
                "active": any(item[0] == old_label for item in active),
                "backup": "",
            }
        all_labels = {
            item[0]
            for item in candidates + active + quarantine + disabled
            if item[0] != old_label
        }
        if new_label in all_labels:
            raise ValueError("route label already exists")
        replacement = (new_label, origin, credential or candidate[2])
        current = current_route()
        is_current = current["label"] == old_label and current["origin"] == candidate[1]

        def replace_private(records):
            return [replacement if item[0] == old_label else item for item in records]

        def replace_control(records):
            return [
                (new_label, origin, item[2]) if item[0] == old_label else item
                for item in records
            ]

        next_candidates = replace_private(candidates)
        next_active = replace_private(active)
        next_quarantine = replace_control(quarantine)
        next_disabled = replace_control(disabled)
        is_disabled = any(item[0] == old_label for item in disabled)
        is_quarantined = any(item[0] == old_label for item in quarantine)
        if credential is not None and not is_disabled and not is_quarantined:
            if not any(item[0] == new_label for item in next_active):
                next_active.append(replacement)
            probe_state = "healthy"
            probe_http = "200"
        else:
            probe_state = None
            probe_http = None
        next_probe_status = update_probe_status(
            read_lines(PROBE_STATUS_FILE),
            old_label,
            new_label,
            len(next_candidates),
            len(next_active),
            probe_state,
            probe_http,
        )
        current_label = new_label if is_current else current["label"]
        current_origin = origin if is_current else current["origin"]
        current_index = next(
            (
                index
                for index, item in enumerate(next_active)
                if item[0] == current_label and item[1] == current_origin
            ),
            -1,
        )
        if not next_active or current_index < 0:
            raise RuntimeError("route update would invalidate the active route")

        next_auth = read_lines(AUTH_FILE)
        if is_current:
            next_auth = rewrite_auth_config(next_auth, new_label, origin, replacement[2])
        backup, existing = create_management_backup(managed_paths)
        try:
            atomic_write(CANDIDATES_FILE, format_private_routes(next_candidates))
            atomic_write(ACTIVE_FILE, format_private_routes(next_active))
            atomic_write(STATE_FILE, [str(current_index)])
            atomic_write(QUARANTINE_FILE, format_control_routes(next_quarantine))
            atomic_write(DISABLED_FILE, format_control_routes(next_disabled))
            if PROBE_STATUS_FILE.exists():
                atomic_write(PROBE_STATUS_FILE, next_probe_status)
            if is_current:
                atomic_write(AUTH_FILE, next_auth)
            atomic_write(MANAGEMENT_BACKUP_MARKER, [str(backup)])
            run(
                [
                    "/usr/bin/systemctl",
                    "--user",
                    "reload",
                    "codex-relay-nginx.service",
                ],
                timeout=15,
            )
            run(
                [
                    "/usr/bin/curl",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "25",
                    "--header",
                    f"@{NGINX_DIR / 'local-client.header'}",
                    "http://127.0.0.1:18080/v1/models",
                ],
                timeout=30,
            )
            status = build_status()
            route = next(
                (item for item in status["routes"] if item["label"] == new_label),
                None,
            )
            expected_active = any(item[0] == new_label for item in next_active)
            expected_disabled = any(item[0] == new_label for item in next_disabled)
            expected_quarantined = any(item[0] == new_label for item in next_quarantine)
            if (
                route is None
                or route["active"] != expected_active
                or route["disabled"] != expected_disabled
                or route["quarantined"] != expected_quarantined
                or route["current"] != is_current
                or status["current"]["index"] != current_index
            ):
                raise RuntimeError("route update did not reach the requested state")
        except Exception as error:
            restore_management_backup(backup, existing, managed_paths)
            reload_result = run(
                [
                    "/usr/bin/systemctl",
                    "--user",
                    "reload",
                    "codex-relay-nginx.service",
                ],
                timeout=15,
                check=False,
            )
            if reload_result.returncode != 0:
                raise RuntimeError(
                    "route update rollback completed but Nginx reload failed"
                ) from error
            raise RuntimeError("route update failed validation and was rolled back") from error
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    return {
        "action": "update",
        "state": "completed",
        "changed": True,
        "label": new_label,
        "previous_label": old_label,
        "active": bool(route and route["active"]),
        "backup": backup.name,
    }


def add_route(payload):
    """Add one candidate only after an authenticated upstream probe succeeds."""
    if not isinstance(payload, dict):
        raise ValueError("invalid route payload")
    label = payload.get("label")
    origin = payload.get("origin")
    credential = payload.get("api_key")
    if (
        not isinstance(label, str)
        or not valid_label(label)
        or not isinstance(origin, str)
        or origin not in ADDABLE_ORIGINS
        or not isinstance(credential, str)
        or len(credential) > 512
        or not CREDENTIAL_RE.fullmatch(credential)
    ):
        raise ValueError("invalid route payload")

    # Probe before mutation. The credential is written only to a 0600 temporary header.
    probe_credential(origin, credential)

    managed_paths = (
        CANDIDATES_FILE,
        ACTIVE_FILE,
        AUTH_FILE,
        STATE_FILE,
        PROBE_STATUS_FILE,
        QUARANTINE_FILE,
        DISABLED_FILE,
        MANAGEMENT_BACKUP_MARKER,
    )
    backup = None
    existing = set()
    LOCK_FILE.touch(mode=0o600, exist_ok=True)
    LOCK_FILE.chmod(0o600)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        candidates = private_route_records(CANDIDATES_FILE)
        active = private_route_records(ACTIVE_FILE)
        quarantine = route_control_records(QUARANTINE_FILE)
        disabled = route_control_records(DISABLED_FILE)
        if any(item[0] == label for item in candidates + active + quarantine + disabled):
            raise ValueError("route label already exists")
        if any(item[2] == credential for item in candidates):
            raise ValueError("route credential already exists")
        current = current_route()
        current_index = next(
            (
                index
                for index, item in enumerate(active)
                if item[0] == current["label"] and item[1] == current["origin"]
            ),
            -1,
        )
        if not active or current_index < 0:
            raise RuntimeError("route add would invalidate the active route")
        backup, existing = create_management_backup(managed_paths)
        try:
            atomic_write(
                CANDIDATES_FILE,
                format_private_routes(candidates + [(label, origin, credential)]),
            )
            atomic_write(ACTIVE_FILE, format_private_routes(active))
            atomic_write(STATE_FILE, [str(current_index)])
            atomic_write(QUARANTINE_FILE, format_control_routes(quarantine))
            atomic_write(DISABLED_FILE, format_control_routes(disabled))
            atomic_write(MANAGEMENT_BACKUP_MARKER, [str(backup)])
            after_write = managed_fingerprints(managed_paths)
        except Exception:
            restore_management_backup(backup, existing, managed_paths)
            raise
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    try:
        run(
            [
                "/usr/bin/systemctl",
                "--user",
                "start",
                "codex-relay-key-probe.service",
            ],
            timeout=210,
        )
        run(
            [
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "25",
                "--header",
                f"@{NGINX_DIR / 'local-client.header'}",
                "http://127.0.0.1:18080/v1/models",
            ],
            timeout=30,
        )
        status = build_status()
        route = next((item for item in status["routes"] if item["label"] == label), None)
        if (
            route is None
            or not route["active"]
            or route["disabled"]
            or route["quarantined"]
            or route["probe_state"] != "healthy"
        ):
            raise RuntimeError("new route did not enter the healthy pool")
    except Exception as error:
        with LOCK_FILE.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if managed_fingerprints(managed_paths) != after_write:
                raise RuntimeError("route add failed; managed state changed after write, rollback skipped; inspect the retained backup") from error
            restore_management_backup(backup, existing, managed_paths)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        reload_result = run(
            [
                "/usr/bin/systemctl",
                "--user",
                "reload",
                "codex-relay-nginx.service",
            ],
            timeout=15,
            check=False,
        )
        if reload_result.returncode != 0:
            raise RuntimeError("route add rollback completed but Nginx reload failed") from error
        raise RuntimeError("route add failed validation and was rolled back") from error

    return {
        "action": "add",
        "state": "completed",
        "changed": True,
        "label": label,
        "active": True,
        "backup": backup.name,
    }


def operate(action):
    if action == "probe":
        unit = "codex-relay-key-probe.service"
        timeout = 180
        before = probe_status().get("checked_at", "")
    elif action == "rotate":
        unit = "codex-relay-key-rotate.service"
        timeout = 45
        before = current_route()
    else:
        raise ValueError("unsupported operation")
    try:
        run(["/usr/bin/systemctl", "--user", "start", unit], timeout=timeout)
    except subprocess.TimeoutExpired:
        if service_state(unit) == "active":
            return {"action": action, "state": "running", "changed": False}
        raise
    if action == "probe":
        after = probe_status().get("checked_at", "")
        if after == before:
            if service_state(unit) == "active":
                return {"action": action, "state": "running", "changed": False}
            raise RuntimeError("probe finished without updating checked_at")
    else:
        after = current_route()
        if after["label"] == before["label"] and after["index"] == before["index"]:
            if service_state(unit) == "active":
                return {"action": action, "state": "running", "changed": False}
            raise RuntimeError("rotation finished without changing route")
    if action == "rotate":
        run(
            [
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "25",
                "--header",
                f"@{NGINX_DIR / 'local-client.header'}",
                "http://127.0.0.1:18080/v1/models",
            ],
            timeout=30,
        )
    return {"action": action, "state": "completed", "changed": True}


def main():
    os.umask(0o077)
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action in {"probe", "rotate"}:
        operation = operate(action)
    elif action == "add":
        if len(sys.argv) != 2:
            raise SystemExit("invalid route add arguments")
        try:
            operation = add_route(json.load(sys.stdin))
        except json.JSONDecodeError as error:
            raise SystemExit("invalid route add payload") from error
    elif action == "update":
        if len(sys.argv) != 2:
            raise SystemExit("invalid route update arguments")
        try:
            operation = update_route(json.load(sys.stdin))
        except json.JSONDecodeError as error:
            raise SystemExit("invalid route update payload") from error
    elif action in {"disable", "enable", "delete"}:
        expected_args = 4 if action == "delete" else 3
        if len(sys.argv) != expected_args:
            raise SystemExit("invalid route operation arguments")
        confirmation = sys.argv[3] if action == "delete" else ""
        operation = manage_route(action, sys.argv[2], confirmation)
    elif action != "status":
        raise SystemExit("unsupported operation")
    else:
        operation = None
    status = build_status()
    if operation is not None:
        status["operation"] = operation
    print(json.dumps(status, ensure_ascii=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
