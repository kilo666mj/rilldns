# RillDNS management API

The first control-plane API manages existing primary zones. It is intentionally bound to `127.0.0.1:8053` and has no remote authentication yet. Access it locally or through an SSH tunnel.

`dns-primary` is the writable PoC primary. `dns-secondary` runs with `-read-only` while
phased primary-to-secondary replication is active, preventing independent API
writes from creating divergent zones.

## Refresh health

The loopback API exposes the last zone-transfer and blocklist refresh results:

```sh
curl -sS http://127.0.0.1:8053/v1/status/refresh
curl -sS http://127.0.0.1:8053/metrics
```

Refresh health becomes false after a failed job, when hourly zone data is more
than two hours old, when daily blocklist data is more than 26 hours old, or when
the earliest transferred DNSSEC signature expires within 12 hours. The metrics
endpoint uses Prometheus text format and includes last-success timestamps,
blocklist domain count, and earliest RRSIG expiry.
The same status response includes the most recent RillDNS primary-versus-secondary
differential result; mismatches or a check older than two hours make aggregate
refresh health unhealthy.

## Query and cache history

`GET /v1/metrics/history?range=6h` returns fixed Prometheus-backed series for
query rate, cache-hit ratio, NXDOMAIN rate, and cache entries. Valid ranges are
`1h`, `6h`, `24h`, and `7d`. The endpoint does not accept PromQL, metric names,
or arbitrary Prometheus URLs from callers.

## Blocklist configuration

`GET /v1/blocklists/config` returns the complete HTTPS source list, explicit
allow/deny domains, and an `ETag` revision. Replace the complete configuration
with `PUT` and the exact current revision:

```sh
curl -sS -X PUT -H "If-Match: \"$revision\"" \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8053/v1/blocklists/config \
  -d '{
    "sources": ["https://example.net/blocklist.txt"],
    "allow": ["needed.example"],
    "deny": ["ads.example"],
    "dry_run": true
  }'
```

Only HTTPS sources are accepted. Inputs are normalized, deduplicated, sorted,
and limited to 32 sources. `dry_run: false` atomically publishes the three
configuration files. The next scheduled refresh compiles them; operators can
start `rilldns-refresh-blocklists.service` for immediate application.

## Read zones

```sh
curl -sS http://127.0.0.1:8053/v1/zones
curl -i http://127.0.0.1:8053/v1/zones/example.test/rrsets
```

The zone response includes an `ETag`. Mutations must send that revision through `If-Match` or `expected_revision`.

## Create or import a zone

`PUT /v1/zones/{zone}` accepts complete RFC 1035 zone text and a `primary` or
`secondary` role. Use `dry_run: true` to validate without publishing.

```sh
curl -sS -X PUT -H 'Content-Type: application/json' \
  http://127.0.0.1:8053/v1/zones/demo.example \
  -d '{"role":"primary","zone_text":"$ORIGIN demo.example.\n@ 300 IN SOA ns.demo.example. hostmaster.demo.example. 2026081201 300 60 86400 60\n@ 300 IN NS ns.demo.example.\nns 300 IN A 192.0.2.53\n"}'
```

Delete requires the exact current revision:

```sh
curl -sS -X DELETE -H "If-Match: \"$revision\"" \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8053/v1/zones/demo.example \
  -d "{\"expected_revision\":\"$revision\"}"
```

Create and delete wait for the cache-free authority to reflect the change,
then send NOTIFY. Failed publication is rolled back. A NOTIFY failure is
returned as a warning because hourly SOA polling remains a replication fallback.

## Preview a record change

```sh
revision=$(curl -sS -D - -o /dev/null \
  http://127.0.0.1:8053/v1/zones/example.test/rrsets \
  | sed -n 's/^[Ee][Tt][Aa][Gg]: "\([^"]*\)".*/\1/p' \
  | tr -d '\r')

curl -sS -X POST \
  -H "If-Match: \"$revision\"" \
  -H 'Content-Type: application/json' \
  -H 'X-RillDNS-Actor: operator' \
  http://127.0.0.1:8053/v1/zones/example.test/changes \
  -d '{
    "dry_run": true,
    "changes": [{
      "action": "upsert",
      "name": "demo",
      "type": "A",
      "ttl": 300,
      "records": ["192.0.2.25"]
    }]
  }'
```

Set `dry_run` to `false` to commit. A committed batch:

1. Checks the expected revision.
2. Applies all RRset changes in memory.
3. Validates the complete zone.
4. Advances the SOA serial once.
5. Saves the prior revision under `/var/lib/rilldns/history`.
6. Atomically publishes and synchronizes the zone file.
7. Waits for CoreDNS to serve the new serial.
8. Restores the prior zone if verification fails.
9. Appends an audit event.

## Change format

Upsert replaces the complete RRset:

```json
{
  "action": "upsert",
  "name": "www",
  "type": "A",
  "ttl": 300,
  "records": ["192.0.2.10", "192.0.2.11"]
}
```

Delete removes the complete RRset:

```json
{
  "action": "delete",
  "name": "old",
  "type": "A"
}
```

SOA records cannot be changed directly. CNAME coexistence, apex SOA/NS requirements, record syntax, duplicate records, owner boundaries, and Internet class are validated server-side.

## Current limitations

- Loopback access only; remote OAuth and role-based authorization come later.
- No idempotency-key store yet.
- No rollback endpoint yet, although prior versions are retained.
- Blocklist configuration publication and blocklist compilation are separate;
  there is not yet an API endpoint to trigger the refresh job.
- Zones with the `secondary` role reject RRset mutations; lifecycle deletion
  still requires an exact revision.
