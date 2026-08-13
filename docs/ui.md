# RillDNS web UI and Pocket ID

RillDNS embeds a dependency-free browser UI in `rill-api`. The UI and its
browser-facing API are exposed on a separate listener protected by Pocket ID;
the existing loopback API remains available to the SSH-stdio MCP adapter.

## Pocket ID client

Create an OIDC client in Pocket ID with this exact callback URL:

```text
https://dns.example.net/api/auth/callback
```

Copy [`deploy/systemd/ui.env.example`](../deploy/systemd/ui.env.example) to
`/etc/rilldns/ui.env`, insert the client ID and secret, and set at least one
subject or group allowlist. RillDNS refuses to start with an empty allowlist,
and email allowlists are rejected because an unverified email claim is not a
safe authorization identity. The file must be owned by root with mode `0600`.

Generate the shared encrypted-session key once and install the same value on
both DNS nodes:

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

Sessions are AES-256-GCM authenticated and encrypted, expire after 12 hours,
and use `Secure`, `HttpOnly`, and `SameSite=Lax` cookies. Browser mutations are
attributed to the authenticated email or Pocket ID subject in the audit log.

## Reverse proxy

[`deploy/nginx/dns.example.net.conf`](../deploy/nginx/dns.example.net.conf)
terminates HTTPS and proxies directly to the writable primary at
`192.0.2.10:8083`. Management deliberately does not follow the DNS VIP:
loss of the primary can make the UI unavailable without affecting DNS service
on the production secondary. Firewalld permits that UI port only from the
reverse proxy.
The separate `dns.example.net-acme.conf` can be enabled before the certificate
exists; enable the HTTPS file only after certificate installation.

The UI provides:

- Prometheus-backed query rate, cache-hit ratio, NXDOMAIN rate, and cache-size
  history over fixed 1-hour, 6-hour, 24-hour, and 7-day ranges;
- aggregate refresh, DNSSEC, blocking, and differential health;
- zone roles, serials, revisions, and RRset browsing;
- RRset dry-run previews and optimistic-concurrency publication;
- zone import/create/delete with server-side verification;
- revisioned blocklist source and allow/deny configuration.
- aggregate blocked-query rate and percentage graphs from dnstap; query names
  and client identities are discarded immediately and are never persisted.

Public `/healthz` on the UI listener supports reverse-proxy health checks. All
`/v1/*` routes require a valid Pocket ID session. Prometheus continues to use
the dedicated metrics listener and MCP continues to use the loopback API.
The metrics listener re-exports localhost CoreDNS metrics, so no additional
CoreDNS port is exposed. Browser history requests use fixed server-side PromQL
definitions; arbitrary PromQL is never accepted from the UI.
