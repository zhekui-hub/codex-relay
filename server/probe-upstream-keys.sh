#!/usr/bin/env bash
# Rebuild the active rotation pool from private candidate routes.
set -euo pipefail
umask 077

relay_dir="$HOME/.local/share/codex-relay"
nginx_dir="$relay_dir/nginx"
candidates_file="$nginx_dir/upstream-auth-key-candidates"
active_file="$nginx_dir/upstream-auth-keys"
auth_file="$nginx_dir/upstream-auth.conf"
state_file="$nginx_dir/.upstream-auth-key-index"
status_file="$nginx_dir/upstream-auth-key-probe.status"
lock_file="$nginx_dir/.upstream-auth-key.lock"
quarantine_file="$nginx_dir/upstream-auth-route-quarantine"
disabled_file="$nginx_dir/upstream-auth-route-disabled"
route_lib="$relay_dir/route-lib.sh"
active_tmp=''
status_tmp=''
state_tmp=''
header_tmp=''
quarantine_tmp=''
response_tmp=''

cleanup() {
  [[ -n "$active_tmp" && -e "$active_tmp" ]] && /bin/rm -f "$active_tmp"
  [[ -n "$status_tmp" && -e "$status_tmp" ]] && /bin/rm -f "$status_tmp"
  [[ -n "$state_tmp" && -e "$state_tmp" ]] && /bin/rm -f "$state_tmp"
  [[ -n "$header_tmp" && -e "$header_tmp" ]] && /bin/rm -f "$header_tmp"
  [[ -n "$quarantine_tmp" && -e "$quarantine_tmp" ]] && /bin/rm -f "$quarantine_tmp"
  [[ -n "$response_tmp" && -e "$response_tmp" ]] && /bin/rm -f "$response_tmp"
  return 0
}
trap cleanup EXIT

[[ -r "$route_lib" ]] || {
  echo 'Codex relay route library is missing.' >&2
  exit 1
}
# shellcheck source=/dev/null
source "$route_lib"

[[ -r "$candidates_file" && -f "$auth_file" ]] || {
  echo 'Codex relay route probe is not configured.' >&2
  exit 1
}
exec 9>"$lock_file"
/usr/bin/flock -x 9

[[ -f "$disabled_file" ]] || /usr/bin/install -m 600 /dev/null "$disabled_file"
declare -A disabled_routes=()
while IFS=$'\t' read -r disabled_label disabled_base disabled_epoch disabled_extra; do
  [[ -z "$disabled_label" && -z "$disabled_base" && -z "$disabled_epoch" ]] && continue
  if [[ -n "${disabled_extra:-}" ||
        ! "$disabled_label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ||
        ! "$disabled_epoch" =~ ^[0-9]+$ ]] ||
     ! codex_route_host "$disabled_base" >/dev/null; then
    echo 'Invalid Codex relay disabled-route record.' >&2
    exit 1
  fi
  route_key="$disabled_label|$disabled_base"
  [[ -z "${disabled_routes[$route_key]:-}" ]] || {
    echo 'Duplicate Codex relay disabled-route record.' >&2
    exit 1
  }
  disabled_routes[$route_key]=1
done < "$disabled_file"

active_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-keys.XXXXXX")
status_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-probe.status.XXXXXX")
state_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-index.XXXXXX")
quarantine_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-route-quarantine.XXXXXX")
/bin/chmod 600 "$active_tmp" "$status_tmp" "$state_tmp" "$quarantine_tmp"
[[ -f "$quarantine_file" ]] || /usr/bin/install -m 600 /dev/null "$quarantine_file"

candidate_count=0
healthy_count=0
printf 'checked_at=%s\n' "$(/bin/date --iso-8601=seconds)" > "$status_tmp"

while IFS=$'\t' read -r label base_url api_key extra; do
  [[ -z "$label" && -z "$base_url" && -z "$api_key" ]] && continue
  if [[ -n "${extra:-}" ]] || ! codex_validate_route "$label" "$base_url" "$api_key"; then
    echo 'Invalid Codex relay candidate-route record.' >&2
    exit 1
  fi
  candidate_count=$((candidate_count + 1))
  route_key="$label|$base_url"
  if [[ -n "${disabled_routes[$route_key]:-}" ]]; then
    printf 'route=%s status=disabled http=000\n' "$label" >> "$status_tmp"
    continue
  fi
  probe_status='000'
  quarantine_epoch=''
  while IFS=$'\t' read -r failed_label failed_base failed_epoch failed_extra; do
    if [[ -z "${failed_extra:-}" && "$failed_label" == "$label" && "$failed_base" == "$base_url" ]]; then
      quarantine_epoch="$failed_epoch"
      break
    fi
  done < "$quarantine_file"
  [[ -z "$quarantine_epoch" || "$quarantine_epoch" =~ ^[0-9]+$ ]] || {
    echo 'Invalid Codex relay quarantine record.' >&2
    exit 1
  }

  for attempt in 1 2; do
    header_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-header.XXXXXX")
    /bin/chmod 600 "$header_tmp"
    printf 'Authorization: Bearer %s\n' "$api_key" > "$header_tmp"
    probe_status=$(/usr/bin/curl --silent --connect-timeout 5 --max-time 15 \
      --header "@$header_tmp" -o /dev/null -w '%{http_code}' \
      "$base_url/v1/models") || probe_status='000'
    /bin/rm -f "$header_tmp"
    header_tmp=''
    [[ "$probe_status" == '200' ]] && break
    (( attempt == 1 )) && /bin/sleep 1
  done

  if [[ "$probe_status" == '200' && -n "$quarantine_epoch" ]]; then
    now_epoch=$(/bin/date +%s)
    if (( now_epoch - quarantine_epoch >= 600 )); then
      header_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-key-header.XXXXXX")
      response_tmp=$(/usr/bin/mktemp "$nginx_dir/.upstream-auth-response.XXXXXX")
      /bin/chmod 600 "$header_tmp" "$response_tmp"
      printf 'Authorization: Bearer %s\n' "$api_key" > "$header_tmp"
      printf '%s\n' '{"model":"gpt-5.6-sol","input":"Reply OK","max_output_tokens":16}' > "$response_tmp"
      probe_status=$(/usr/bin/curl --silent --connect-timeout 5 --max-time 30 \
        --header "@$header_tmp" --header 'Content-Type: application/json' \
        --data-binary "@$response_tmp" -o /dev/null -w '%{http_code}' \
        "$base_url/v1/responses") || probe_status='000'
      /bin/rm -f "$header_tmp" "$response_tmp"
      header_tmp=''
      response_tmp=''
      if [[ "$probe_status" != '200' ]]; then
        quarantine_epoch="$now_epoch"
      else
        quarantine_epoch=''
      fi
    fi
  fi

  if [[ "$probe_status" == '200' && -z "$quarantine_epoch" ]]; then
    printf '%s\t%s\t%s\n' "$label" "$base_url" "$api_key" >> "$active_tmp"
    printf 'route=%s status=healthy http=200\n' "$label" >> "$status_tmp"
    healthy_count=$((healthy_count + 1))
  else
    if [[ -n "$quarantine_epoch" ]]; then
      printf '%s\t%s\t%s\n' "$label" "$base_url" "$quarantine_epoch" >> "$quarantine_tmp"
      printf 'route=%s status=quarantined http=%s\n' "$label" "$probe_status" >> "$status_tmp"
    else
      printf 'route=%s status=unhealthy http=%s\n' "$label" "$probe_status" >> "$status_tmp"
    fi
  fi
done < "$candidates_file"

(( candidate_count >= 1 )) || {
  echo 'Codex relay candidate-route list is empty.' >&2
  exit 1
}

printf 'candidate_count=%s\nhealthy_count=%s\n' "$candidate_count" "$healthy_count" >> "$status_tmp"
/bin/mv "$active_tmp" "$active_file"
active_tmp=''
/bin/mv "$quarantine_tmp" "$quarantine_file"
quarantine_tmp=''

current_key=$(/usr/bin/awk -F'"' '/proxy_set_header[[:space:]]+Authorization/ { sub(/^Bearer /, "", $2); print $2; exit }' "$auth_file")
current_base=$(/usr/bin/awk '/proxy_pass[[:space:]]+https:\/\// { value=$2; sub(/;$/, "", value); print value; exit }' "$auth_file")
current_label=$(/usr/bin/awk -F'"' '/set[[:space:]]+\$relay_route_label/ { print $2; exit }' "$auth_file")
current_index=-1
index=0
while IFS=$'\t' read -r active_label active_base active_key extra; do
  if [[ -z "${extra:-}" && "$active_label" == "$current_label" &&
        "$active_base" == "$current_base" && "$active_key" == "$current_key" ]]; then
    current_index=$index
    break
  fi
  index=$((index + 1))
done < "$active_file"

printf '%s\n' "$current_index" > "$state_tmp"
/bin/mv "$state_tmp" "$state_file"
state_tmp=''
/bin/mv "$status_tmp" "$status_file"
status_tmp=''
/usr/bin/flock -u 9

if (( healthy_count > 0 && current_index < 0 )); then
  /usr/bin/systemctl --user start codex-relay-key-rotate.service
fi
