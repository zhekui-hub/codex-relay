#!/usr/bin/env bash
# Watch metadata-only access logs and quarantine the active route on auth failure.
set -euo pipefail
umask 077

relay_dir="$HOME/.local/share/codex-relay"
nginx_dir="$relay_dir/nginx"
access_log="$nginx_dir/logs/access.log"
quarantine_script="$relay_dir/quarantine-current-key.sh"

[[ -r "$access_log" && -x "$quarantine_script" ]] || exit 1

/usr/bin/tail -n 0 -F "$access_log" | while IFS= read -r line; do
  case "$line" in
    *' status=401 upstream_status=401 '*|*' status=402 upstream_status=402 '*)
      route_label=$(/bin/sed -n 's/.* route=\([^ ]*\) status=.*/\1/p' <<< "$line")
      if [[ "$route_label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
        "$quarantine_script" "$route_label" >/dev/null 2>&1 || true
      fi
      ;;
  esac
done
