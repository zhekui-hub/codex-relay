#!/usr/bin/env bash
# Remove the route currently serving Nginx after an upstream auth/quota failure.
set -euo pipefail
umask 077

relay_dir="$HOME/.local/share/codex-relay"
nginx_dir="$relay_dir/nginx"
active_file="$nginx_dir/upstream-auth-keys"
auth_file="$nginx_dir/upstream-auth.conf"
state_file="$nginx_dir/.upstream-auth-key-index"
lock_file="$nginx_dir/.upstream-auth-key.lock"
event_file="$nginx_dir/upstream-auth-key-failure.status"
cooldown_file="$nginx_dir/.upstream-auth-key-failure.cooldown"
quarantine_file="$nginx_dir/upstream-auth-route-quarantine"
route_lib="$relay_dir/route-lib.sh"
active_tmp=''
auth_tmp=''
state_tmp=''
event_tmp=''
quarantine_tmp=''
active_previous=''
auth_previous=''
state_previous=''
quarantine_previous=''

cleanup() {
  [[ -n "$active_tmp" && -e "$active_tmp" ]] && /bin/rm -f "$active_tmp"
  [[ -n "$auth_tmp" && -e "$auth_tmp" ]] && /bin/rm -f "$auth_tmp"
  [[ -n "$state_tmp" && -e "$state_tmp" ]] && /bin/rm -f "$state_tmp"
  [[ -n "$event_tmp" && -e "$event_tmp" ]] && /bin/rm -f "$event_tmp"
  [[ -n "$quarantine_tmp" && -e "$quarantine_tmp" ]] && /bin/rm -f "$quarantine_tmp"
  [[ -n "$active_previous" && -e "$active_previous" ]] && /bin/rm -f "$active_previous"
  [[ -n "$auth_previous" && -e "$auth_previous" ]] && /bin/rm -f "$auth_previous"
  [[ -n "$state_previous" && -e "$state_previous" ]] && /bin/rm -f "$state_previous"
  [[ -n "$quarantine_previous" && -e "$quarantine_previous" ]] && /bin/rm -f "$quarantine_previous"
  return 0
}
trap cleanup EXIT

[[ -r "$route_lib" ]] || exit 1
# shellcheck source=/dev/null
source "$route_lib"

expected_label="${1:-}"
[[ "$expected_label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || exit 0

[[ -r "$active_file" && -f "$auth_file" ]] || exit 0
[[ -f "$quarantine_file" ]] || /usr/bin/install -m 600 /dev/null "$quarantine_file"
exec 9>"$lock_file"
/usr/bin/flock -x 9

now_epoch=$(/bin/date +%s)
last_epoch=0
if [[ -r "$cooldown_file" ]]; then
  IFS= read -r last_epoch < "$cooldown_file" || true
fi
[[ "$last_epoch" =~ ^[0-9]+$ ]] || last_epoch=0
if (( now_epoch - last_epoch < 10 )); then
  exit 0
fi

mapfile -t active_routes < <(/usr/bin/awk 'NF { print }' "$active_file")
(( ${#active_routes[@]} > 1 )) || exit 0

current_index=-1
if [[ -r "$state_file" ]]; then
  IFS= read -r current_index < "$state_file" || true
fi
[[ "$current_index" =~ ^[0-9]+$ ]] || exit 0
(( current_index < ${#active_routes[@]} )) || exit 0
IFS=$'\t' read -r current_label current_base current_key current_extra \
  <<< "${active_routes[$current_index]}"
[[ -z "${current_extra:-}" ]] || exit 1
codex_validate_route "$current_label" "$current_base" "$current_key" || exit 1
[[ "$current_label" == "$expected_label" ]] || exit 0

next_index=0
active_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-keys.XXXXXX")
auth_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth.conf.XXXXXX")
state_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-index.XXXXXX")
event_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-failure.status.XXXXXX")
quarantine_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-route-quarantine.XXXXXX")
active_previous=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-keys.previous.XXXXXX")
auth_previous=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth.previous.XXXXXX")
state_previous=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-index.previous.XXXXXX")
quarantine_previous=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-route-quarantine.previous.XXXXXX")
/bin/chmod 600 "$active_tmp" "$auth_tmp" "$state_tmp" "$event_tmp" \
  "$quarantine_tmp" "$active_previous" "$auth_previous" "$state_previous" \
  "$quarantine_previous"
/bin/cp -p "$active_file" "$active_previous"
/bin/cp -p "$auth_file" "$auth_previous"
/bin/cp -p "$state_file" "$state_previous"
/bin/cp -p "$quarantine_file" "$quarantine_previous"

for index in "${!active_routes[@]}"; do
  if (( index == current_index )); then
    continue
  fi
  printf '%s\n' "${active_routes[$index]}" >> "$active_tmp"
done

remaining_count=$(( ${#active_routes[@]} - 1 ))
if (( current_index >= remaining_count )); then
  next_index=0
else
  next_index=$current_index
fi
mapfile -t remaining_routes < <(/usr/bin/awk 'NF { print }' "$active_tmp")
IFS=$'\t' read -r _label base_url api_key extra <<< "${remaining_routes[$next_index]}"
selected_label="${remaining_routes[$next_index]%%$'\t'*}"
if [[ -n "${extra:-}" ]] || ! codex_validate_route "$selected_label" "$base_url" "$api_key"; then
  echo 'Codex relay selected an invalid failover route.' >&2
  exit 1
fi
codex_render_route "$selected_label" "$base_url" "$api_key" > "$auth_tmp"
printf '%s\n' "$next_index" > "$state_tmp"

while IFS=$'\t' read -r failed_label failed_base failed_epoch failed_extra; do
  [[ -z "$failed_label" && -z "$failed_base" && -z "$failed_epoch" ]] && continue
  [[ -z "${failed_extra:-}" && "$failed_label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ &&
     "$failed_epoch" =~ ^[0-9]+$ ]] && codex_route_host "$failed_base" >/dev/null || exit 1
  if [[ "$failed_label" == "$current_label" && "$failed_base" == "$current_base" ]]; then
    continue
  fi
  printf '%s\t%s\t%s\n' "$failed_label" "$failed_base" "$failed_epoch" >> "$quarantine_tmp"
done < "$quarantine_file"
printf '%s\t%s\t%s\n' "$current_label" "$current_base" "$now_epoch" >> "$quarantine_tmp"

/bin/mv "$active_tmp" "$active_file"
active_tmp=''
/bin/mv "$auth_tmp" "$auth_file"
auth_tmp=''
/bin/mv "$state_tmp" "$state_file"
state_tmp=''
/bin/mv "$quarantine_tmp" "$quarantine_file"
quarantine_tmp=''

if ! /usr/bin/systemctl --user reload codex-relay-nginx.service; then
  /bin/cp -p "$active_previous" "$active_file"
  /bin/cp -p "$auth_previous" "$auth_file"
  /bin/cp -p "$state_previous" "$state_file"
  /bin/cp -p "$quarantine_previous" "$quarantine_file"
  /usr/bin/systemctl --user reload codex-relay-nginx.service >/dev/null 2>&1 || true
  echo 'Codex relay failover reload failed; previous route pool was restored.' >&2
  exit 1
fi

printf 'failed_route=%s\nfailed_route_index=%s\nremaining_count=%s\nobserved_at=%s\n' \
  "$current_label" "$current_index" "$remaining_count" \
  "$(/bin/date --iso-8601=seconds)" > "$event_tmp"
/bin/mv "$event_tmp" "$event_file"
event_tmp=''
/bin/printf '%s\n' "$now_epoch" > "$cooldown_file"
/bin/chmod 600 "$cooldown_file"
