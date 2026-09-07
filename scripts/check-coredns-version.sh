#!/bin/sh
set -eu

compose_version=$(sed -n 's/^[[:space:]]*image:[[:space:]]*coredns\/coredns:\([^[:space:]#]*\).*/\1/p' compose.yaml)
ansible_version=$(sed -n 's/^[[:space:]]*rilldns_coredns_version:[[:space:]]*"\([^"]*\)".*/\1/p' ansible/roles/rilldns/defaults/main.yml)

if [ -z "$compose_version" ] || [ -z "$ansible_version" ]; then
	echo "could not read both CoreDNS version pins" >&2
	exit 1
fi

if [ "$compose_version" != "$ansible_version" ]; then
	echo "CoreDNS version pins differ: Compose=$compose_version Ansible=$ansible_version" >&2
	echo "Update compose.yaml and ansible/roles/rilldns/defaults/main.yml together." >&2
	exit 1
fi

echo "CoreDNS version pins match: $compose_version"
