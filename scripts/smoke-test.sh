#!/bin/sh
set -eu

dns_server=${RILLDNS_SERVER:-127.0.0.1}
dns_port=${RILLDNS_PORT:-1053}

answer=$(dig +short +time=2 +tries=1 @"$dns_server" -p "$dns_port" www.example.test A)
[ "$answer" = "192.0.2.10" ] || {
    echo "authoritative lookup failed: got '$answer'" >&2
    exit 1
}

blocked=$(dig +short +time=2 +tries=1 @"$dns_server" -p "$dns_port" ads.example.test A)
[ "$blocked" = "0.0.0.0" ] || {
    echo "blocklist lookup failed: got '$blocked'" >&2
    exit 1
}

dig +short +time=5 +tries=1 @"$dns_server" -p "$dns_port" example.com A >/dev/null

axfr=$(dig +short +time=2 +tries=1 @"$dns_server" -p "$dns_port" example.test AXFR)
printf '%s\n' "$axfr" | grep -Fq '192.0.2.10' || {
    echo "AXFR lookup did not contain the expected record" >&2
    exit 1
}

curl --fail --silent "http://127.0.0.1:8080/health" >/dev/null
curl --fail --silent "http://127.0.0.1:8181/ready" >/dev/null
curl --fail --silent "http://127.0.0.1:9153/metrics" | grep -q '^coredns_'

echo "RillDNS smoke test passed"
