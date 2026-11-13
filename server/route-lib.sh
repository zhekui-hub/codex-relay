#!/usr/bin/env bash
# Shared validation and Nginx rendering for the private relay route pool.

codex_route_host() {
  case "$1" in
    https://upstream-a.invalid) printf '%s\n' 'upstream-a.invalid' ;;
    https://upstream-b.invalid) printf '%s\n' 'upstream-b.invalid' ;;
    *) return 1 ;;
  esac
}

codex_validate_route() {
  local label="$1" base_url="$2" api_key="$3"
  [[ "$label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
  [[ "$api_key" =~ ^[A-Za-z0-9._/+=:-]+$ ]] || return 1
  codex_route_host "$base_url" >/dev/null
}

codex_render_route() {
  local label="$1" base_url="$2" api_key="$3" host
  codex_validate_route "$label" "$base_url" "$api_key" || return 1
  host=$(codex_route_host "$base_url") || return 1
  printf 'set %s "%s";\n' "\$relay_route_label" "$label"
  printf 'proxy_pass %s;\n' "$base_url"
  printf 'proxy_set_header Host "%s";\n' "$host"
  printf 'proxy_set_header Authorization "Bearer %s";\n' "$api_key"
  printf 'proxy_ssl_server_name on;\n'
  printf 'proxy_ssl_name "%s";\n' "$host"
}
