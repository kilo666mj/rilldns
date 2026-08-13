#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
blocking_dir="$project_dir/data/blocking"
download_dir=$(mktemp -d)
trap 'rm -rf "$download_dir"' EXIT HUP INT TERM

inputs="$blocking_dir/deny.txt"
index=0
while IFS= read -r source || [ -n "$source" ]; do
    case "$source" in
        ''|'#'*) continue ;;
    esac
    index=$((index + 1))
    destination="$download_dir/source-$index.txt"
    curl --fail --silent --show-error --location \
        --connect-timeout 10 --max-time 60 --max-filesize 52428800 \
        "$source" --output "$destination"
    inputs="$inputs $destination"
done < "$blocking_dir/sources.txt"

# Input paths are generated internally and contain no whitespace.
# shellcheck disable=SC2086
go run "$project_dir/cmd/blocklist-merge" \
    -allow "$blocking_dir/allow.txt" \
    -output "$blocking_dir/merged.hosts" \
    $inputs
