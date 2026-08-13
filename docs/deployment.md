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
changes. An hourly SOA poll covers lost NOTIFY messages.

```text
dns-primary:1056 -- TSIG AXFR/NOTIFY --> dns-secondary:1054
```

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

## Tagged releases and deployment

Tags matching `v*` run the same test and build checks as pull requests, build
static `linux/amd64` and `linux/arm64` command bundles, publish checksums and a
GitHub Release, and then enter the protected `production` environment. After
its required approval, deployment installs and verifies the secondary before
touching the primary. A failed service restart or API health check restores the
previous binaries on that node.

Configure these GitHub Environment values before creating a release tag:

- secrets `RILLDNS_PRIMARY_HOST`, `RILLDNS_SECONDARY_HOST`,
  `RILLDNS_SSH_USER`, `RILLDNS_SSH_PRIVATE_KEY`, and
  `RILLDNS_SSH_KNOWN_HOSTS`;
- variables `RILLDNS_PRIMARY_ARCH` and `RILLDNS_SECONDARY_ARCH`, each set to
  `amd64` or `arm64`;
- a required reviewer on the `production` environment.

The deployment account needs narrowly scoped SSH access and passwordless sudo
for the installer operations. Use a dedicated key and pinned `known_hosts`
entries. Create releases only from protected `main`, for example:

```sh
git tag -s v0.1.0 -m 'RillDNS v0.1.0'
git push origin v0.1.0
```
