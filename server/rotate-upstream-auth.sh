#!/usr/bin/env bash
# Rotate the private Nginx upstream route without logging its credential.
set -euo pipefail
umask 077

relay_dir="$HOME/.local/share/codex-relay"
nginx_dir="$relay_dir/nginx"
routes_file="$nginx_dir/upstream-auth-keys"
auth_file="$nginx_dir/upstream-auth.conf"
state_file="$nginx_dir/.upstream-auth-key-index"
nginx_service='codex-relay-nginx.service'
lock_file="$nginx_dir/.upstream-auth-key.lock"
route_lib="$relay_dir/route-lib.sh"
auth_tmp=''
previous_tmp=''
state_tmp=''

cleanup() {
  [[ -n "$auth_tmp" && -e "$auth_tmp" ]] && /bin/rm -f "$auth_tmp"
  [[ -n "$previous_tmp" && -e "$previous_tmp" ]] && /bin/rm -f "$previous_tmp"
  [[ -n "$state_tmp" && -e "$state_tmp" ]] && /bin/rm -f "$state_tmp"
  return 0
}
trap cleanup EXIT

[[ -r "$route_lib" ]] || {
  echo 'Codex relay route library is missing.' >&2
  exit 1
}
# shellcheck source=/dev/null
source "$route_lib"

exec 9>"$lock_file"
/usr/bin/flock -x 9

[[ -r "$routes_file" && -f "$auth_file" ]] || {
  echo 'Codex relay route rotation is not configured.' >&2
  exit 1
}

mapfile -t routes < <(/usr/bin/awk 'NF { print }' "$routes_file")
(( ${#routes[@]} >= 1 )) || {
  echo 'Codex relay route rotation has no healthy routes.' >&2
  exit 1
}

current_index=-1
if [[ -r "$state_file" ]]; then
  IFS= read -r current_index < "$state_file" || true
fi
[[ "$current_index" =~ ^-?[0-9]+$ ]] || current_index=-1
if (( current_index < -1 || current_index >= ${#routes[@]} )); then
  current_index=-1
fi
next_index=$(( (current_index + 1) % ${#routes[@]} ))

IFS=$'\t' read -r label base_url api_key extra <<< "${routes[$next_index]}"
if [[ -n "${extra:-}" ]] || ! codex_validate_route "$label" "$base_url" "$api_key"; then
  echo 'Codex relay selected an invalid route.' >&2
  exit 1
fi

auth_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth.conf.XXXXXX")
previous_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth.previous.XXXXXX")
state_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-index.XXXXXX")
/bin/chmod 600 "$auth_tmp" "$previous_tmp" "$state_tmp"
/bin/cp -p "$auth_file" "$previous_tmp"
codex_render_route "$label" "$base_url" "$api_key" > "$auth_tmp"

/bin/mv "$auth_tmp" "$auth_file"
auth_tmp=''
if ! /usr/bin/systemctl --user reload "$nginx_service"; then
  /bin/cp -p "$previous_tmp" "$auth_file"
  /usr/bin/systemctl --user reload "$nginx_service" >/dev/null 2>&1 || true
  echo 'Codex relay reload failed; previous route was restored.' >&2
  exit 1
fi

printf '%s\n' "$next_index" > "$state_tmp"
/bin/mv "$state_tmp" "$state_file"
state_tmp=''
