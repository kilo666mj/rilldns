# Node-local binary deployment

This example deployment runs the pinned CoreDNS binary under the RillDNS name
on `dns-primary` and `dns-secondary` without containers. All names and
addresses are documentation examples and must be replaced. The configuration listens
on UDP/TCP port `53`; port `1056` is reserved for cache-free verification.

Deployment addresses and architectures:

```text
dns-primary  192.0.2.10:53  linux/amd64
dns-secondary  192.0.2.11:53  linux/arm64
```

The `public` firewalld zone permits client DNS on UDP/TCP 53. Health (`18080`),
readiness (`18181`), and CoreDNS Prometheus (`19153`) remain loopback-only. The
API metrics listener on TCP `18053` is permitted only from `prometheus.example.net`.

Files installed on each node:

```text
/usr/local/bin/rilldns
/usr/local/bin/rill-api
/usr/local/bin/rill-mcp
/usr/local/bin/rill-reconcile
/usr/local/bin/rill-diff
/usr/local/bin/rill-zone-status
/usr/local/bin/rill-blocklist-refresh
/usr/local/bin/rill-telemetry
/usr/local/bin/rill-secondary          # dns-secondary
/usr/local/bin/rill-notify             # dns-primary
/etc/rilldns/Corefile
/etc/rilldns/transfer.conf
/etc/rilldns/transfer.keys             # generated, not in Git
/etc/rilldns/transfer.secret           # generated, not in Git
/var/lib/rilldns/zones/example.test.zone
/var/lib/rilldns/zones/*.zone
/var/lib/rilldns/zones/.roles.json
/var/lib/rilldns/history/
/var/lib/rilldns/blocking/merged.hosts
/var/lib/rilldns/status/*.json
/var/lib/rilldns/audit.jsonl
/etc/systemd/system/rilldns.service
/etc/systemd/system/rilldns-telemetry.service
/etc/systemd/system/rilldns-api.service
/etc/systemd/system/rilldns-secondary.service  # dns-secondary
/etc/systemd/system/rilldns-diff.service
/etc/systemd/system/rilldns-diff.service.d/secondary.conf  # dns-secondary
```

The DNS binary is the unmodified, pinned CoreDNS 1.14.6 release for the node
architecture. The unit uses an unprivileged account, a read-only system view,
and only `CAP_NET_BIND_SERVICE` to bind port 53.

The DNS and API processes share a static, unprivileged `rilldns` account. CoreDNS reads the managed data while the loopback-only API can atomically publish zone changes under `/var/lib/rilldns`.

API roles:

```text
dns-primary  writable primary API  127.0.0.1:8053
dns-secondary  read-only API         127.0.0.1:8053
```

Forwarded queries use round-robin selection across the resolvers reachable through `wg0`:

```text
198.51.100.10:5335   upstream-a
198.51.100.11:5335  upstream-b
198.51.100.12:5335  upstream-c
```

Check the service:

```sh
systemctl status rilldns
dig @127.0.0.1 example.test SOA
dig @127.0.0.1 ads.example.test A
dig @127.0.0.1 example.com A
curl http://127.0.0.1:18080/health
curl http://127.0.0.1:19153/metrics
curl http://127.0.0.1:8053/v1/zones
curl http://127.0.0.1:8053/v1/status/refresh
curl http://127.0.0.1:18053/metrics
```

Rollback is isolated and does not affect Nginx or Technitium:

```sh
systemctl disable --now rilldns
```

To remove the PoC network exposure as well:

```sh
firewall-cmd --permanent --zone=public --remove-rich-rule='rule family="ipv4" source address="192.0.2.0/24" port port="1053" protocol="udp" accept'
firewall-cmd --permanent --zone=public --remove-rich-rule='rule family="ipv4" source address="192.0.2.0/24" port port="1053" protocol="tcp" accept'
firewall-cmd --reload
```

## Automatic data refresh

`rilldns-primary-status.timer` runs the native `rill-zone-status` command to
validate all primary zone files every five minutes. Zones requiring native
RillDNS DNSSEC signing are not yet supported.

On `dns-secondary`, `rilldns-secondary.service` listens on TCP/UDP `1054` for NOTIFY
from `dns-primary` only. It compares the SOA and sends a TSIG-authenticated AXFR
request when the serial changes. CoreDNS auto has no usable IXFR journal, and
its fallback can distort TTLs through the cache minimum. The daemon validates
and atomically publishes the fresh snapshot under
`/var/lib/rilldns/zones`.
An hourly SOA poll covers lost NOTIFY messages. Failed transfers leave the last
good snapshot untouched. Newly notified zones are discovered automatically;
authoritative deletion probes remove retired replicas.

The shared 256-bit TSIG secret is generated during deployment and installed as
`/etc/rilldns/transfer.secret` plus CoreDNS-format `transfer.keys`; neither file
is committed. `dns-primary` rejects unsigned AXFR/IXFR. Firewalld on `dns-secondary`
allows port `1054` only from `192.0.2.10`. The obsolete polling-based
`rilldns-refresh-zones` unit has been removed.

The management API verifies auto-plugin publication through a cache-free
authority on port `1056`. On `dns-primary`, firewalld permits that port only from
`dns-secondary`, whose secondary daemon uses it for freshness and deletion probes
while continuing TSIG-authenticated transfers on cache-free port `1056`. After
NOTIFY, the primary API also polls the secondary on port `1056` for the published
SOA serial, returning a warning if replication is not confirmed within 15 seconds.
The port `53` cache excludes all managed authoritative zones, so old RRsets and
NXDOMAIN responses cannot conceal a newly loaded snapshot.

`rilldns-refresh-blocklists.timer` runs the native
`rill-blocklist-refresh` command to download the StevenBlack hosts list and the
HaGeZi multi-domain list every 24 hours. The inputs are parsed, normalized,
deduplicated, filtered through `allow.txt`, and atomically published as
`/var/lib/rilldns/blocking/merged.hosts`. Publication requires at least 100,000
domains, so an error page or truncated download cannot erase the active list.
The writable primary API manages `sources.txt`, `allow.txt`, and `deny.txt` with
optimistic concurrency. Before its daily compile, `dns-secondary` synchronizes those
files through the primary's read-only TCP `18053` endpoint; firewalld permits
that endpoint only from `dns-secondary` and `prometheus.example.net`.

Inspect the jobs with:

```sh
systemctl list-timers rilldns-primary-status.timer rilldns-refresh-blocklists.timer
systemctl status rilldns-secondary.service
journalctl -u rilldns-secondary.service
journalctl -u rilldns-primary-status.service
journalctl -u rilldns-refresh-blocklists.service
systemctl list-timers rilldns-diff.timer
journalctl -u rilldns-diff.service
```

The hourly differential job runs `rill-diff` directly. The command atomically
writes both its detailed report and health status; no shell or JSON utility is
on the production path. It compares normalized TSIG-authenticated AXFR records,
TTLs, and SOA serials between the cache-free RillDNS primary and secondary.
Its full report is stored at `/var/lib/rilldns/differential-report.json`;
summary health is included in the API, MCP, and Prometheus metrics. It also
compares every current owner/type plus deterministic NXDOMAIN and apex-NODATA
queries over UDP and TCP. Optional implementation-specific authority-section
additions are ignored; response code, AA/truncation flags, answer/CNAME chains,
TTLs, and DNSSEC answer records are compared.
