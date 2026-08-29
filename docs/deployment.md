# Production deployment model

This document describes a generic two-node RillDNS deployment. All names and
addresses are examples from domains and networks reserved for documentation.

## Topology

| Node | Example address | Role |
| --- | --- | --- |
| `dns-primary` | `192.0.2.10` | Writable authoritative primary and failback resolver |
| `dns-secondary` | `192.0.2.11` | Read-only replica and normal DNS traffic endpoint |
| DNS VIP | `192.0.2.53` | Client-facing address managed by keepalived or an equivalent mechanism |
| `reverse-proxy` | `192.0.2.30` | TLS termination for `https://dns.example.net` |
| Prometheus | `192.0.2.20` | Scrapes each node's read-only metrics endpoint |

Both nodes run CoreDNS and the RillDNS API. The primary API accepts changes;
the secondary API is explicitly read-only. Keep the management API on
loopback, expose the UI only through an authenticated reverse proxy, and limit
the metrics listener to the monitoring network.

## Replication

The primary publishes validated zone files atomically and sends DNS NOTIFY to
the secondary. The persistent `rill-secondary` daemon compares SOA serials and
requests a TSIG-authenticated AXFR from a cache-free authority when a serial
changes. After NOTIFY, the primary API waits for the cache-free secondary
authority to serve the new SOA serial before returning; an unconfirmed replica
is reported as a publication warning. An hourly SOA poll covers lost NOTIFY
messages.

```text
dns-primary:1056 -- TSIG AXFR/NOTIFY --> dns-secondary:1054
dns-primary API  -- SOA confirmation --> dns-secondary:1056
```

The client-facing listener does not cache positive or negative answers for
managed authoritative zones. This prevents a locally cached old RRset or
NXDOMAIN from hiding an already-published zone snapshot; recursive answers
outside those zones remain cached normally.

Generate the shared TSIG secret during deployment. Install it as root-owned
data on the two nodes; never store it in Git. Restrict the NOTIFY, transfer,
and read-only configuration endpoints to the peer addresses with a host
firewall.

## Blocking and telemetry

Each node downloads and compiles configured hosts/domain lists. Publication is
atomic and refuses an unexpectedly small result, preserving the last known
good snapshot on failure.

CoreDNS sends client-query dnstap frames over loopback to `rill-telemetry`.
The collector compares names with the in-memory block set, increments total and
blocked counters, and immediately discards query names and client addresses.
Prometheus stores aggregate rates and percentages only.

## Authentication

The browser UI uses standard OIDC Authorization Code flow with PKCE. Configure
the issuer, client credentials, exact callback URL, allowed identities, and a
shared encrypted-session key in a root-owned environment file. Pocket ID is one
compatible provider; any conforming OIDC provider should work.

## Operations

- Validate primary zones every five minutes.
- Refresh blocklists daily with randomized delay.
- Run the TSIG-authenticated primary/secondary differential check hourly.
- Alert on stale or failed refreshes, undersized blocklists, differential
  mismatches, and stale differential results.
- Back up zone files, role metadata, audit records, and generated secrets.
- Test failover and restoration before making the VIP the only client path.

The files under [`deploy/systemd`](../deploy/systemd),
[`deploy/nginx`](../deploy/nginx), and
[`deploy/prometheus`](../deploy/prometheus) are examples. Adapt addresses,
firewall policy, paths, users, and service dependencies to your environment.

## Tagged releases

Tags matching `v*` run the same test and build checks as pull requests, build
static `linux/amd64` and `linux/arm64` command bundles, publish checksums and a
GitHub Release. GitHub Actions has no host credentials and performs no
deployment. Production deployment remains an explicit Ansible operation from
the private operations environment, where inventory, secrets, rollout order,
health checks, and rollback policy belong.

Create releases only from protected `main`, for example:

```sh
git tag -s v0.1.0 -m 'RillDNS v0.1.0'
git push origin v0.1.0
```
