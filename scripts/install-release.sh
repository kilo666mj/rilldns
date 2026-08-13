#!/bin/sh
set -eu

role=${1:-}
version=${2:-}
archive=${3:-}

case "$role" in primary|secondary) ;; *) echo "role must be primary or secondary" >&2; exit 2;; esac
case "$version" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "invalid release version" >&2; exit 2;; esac
case "$archive" in /tmp/rilldns-*.tar.gz) ;; *) echo "invalid release archive path" >&2; exit 2;; esac
test -f "$archive"

release_root=/var/lib/rilldns/releases
release_dir="$release_root/$version"
work_dir=$(mktemp -d /tmp/rilldns-install.XXXXXX)
trap 'rm -rf "$work_dir" "$archive"' EXIT HUP INT TERM

mkdir -p "$release_dir/previous"
tar -xzf "$archive" -C "$work_dir"
bundle=$(find "$work_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)
test -n "$bundle"

commands='blocklist-merge rill-api rill-blocklist-refresh rill-diff rill-mcp rill-notify rill-reconcile rill-secondary rill-telemetry rill-zone-status'
for command in $commands; do
  test -x "$bundle/bin/$command"
  if test -f "/usr/local/bin/$command"; then
    cp -p "/usr/local/bin/$command" "$release_dir/previous/$command"
  fi
  install -o root -g root -m 0755 "$bundle/bin/$command" "/usr/local/bin/$command"
done

systemctl daemon-reload
services='rilldns-telemetry rilldns-api'
if test "$role" = secondary; then
  services="$services rilldns-secondary"
fi

rollback() {
  for command in $commands; do
    if test -f "$release_dir/previous/$command"; then
      install -o root -g root -m 0755 "$release_dir/previous/$command" "/usr/local/bin/$command"
    fi
  done
  for service in $services; do systemctl try-restart "$service" || true; done
}

for service in $services; do
  if ! systemctl try-restart "$service"; then rollback; exit 1; fi
done
if ! systemctl is-active --quiet rilldns rilldns-telemetry rilldns-api; then rollback; exit 1; fi
if test "$role" = secondary && ! systemctl is-active --quiet rilldns-secondary; then rollback; exit 1; fi
if ! curl --fail --silent --show-error http://127.0.0.1:8053/healthz >/dev/null; then rollback; exit 1; fi

printf '%s\n' "$version" > "$release_root/current"
