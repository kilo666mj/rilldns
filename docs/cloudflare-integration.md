# Cloudflare DNS integration

## Goal

Manage selected external Cloudflare DNS zones through RillDNS while retaining
the same plan, explicit confirmation, optimistic concurrency, verification, and
audit workflow used for native CoreDNS zones.

Cloudflare zones are provider-backed zones. They are not copied into the local
CoreDNS zone directory and do not participate in NOTIFY or AXFR replication.

## Ownership rule

Each DNS record has exactly one writer. Terraform may continue to manage the
Cloudflare zone, DNSSEC, account settings, rules, and the API-token bootstrap,
but records delegated to RillDNS must be removed from Terraform configuration
and state. Terraform and RillDNS must not manage the same record.

The initial ownership boundary is a complete zone. Per-record ownership may be
added later only if RillDNS can make that boundary explicit and auditable.

## Configuration and credentials

Cloudflare zones are configured as an explicit allowlist of DNS names. RillDNS
resolves each name to its Cloudflare zone ID through the Zones API and caches
the result. It never exposes account-wide discovery through its API. This keeps
the ownership boundary reviewable while avoiding manual zone-ID configuration.

The API token is read from a root-owned file. Start with Zone Read and DNS Read
on only the configured zones. Add DNS Write only when mutation support is
enabled. Never put the token in command-line arguments, logs, API responses, or
repository files.

## Data model

Native and external zones remain distinguishable:

```text
Zone
├── backend: native
│   └── zone file -> CoreDNS -> NOTIFY/AXFR
└── backend: cloudflare
    └── Cloudflare API -> read-back -> authoritative DNS verification
```

RillDNS presents records as RRsets even though Cloudflare assigns an ID to each
individual record. Provider-only attributes live alongside, rather than inside,
portable DNS data. Initial attributes are `proxied`, `comment`, and `tags`.
Cloudflare's automatic TTL value (`1`) must remain distinct from a literal DNS
TTL.

A Cloudflare zone revision is a SHA-256 hash of its normalized record IDs,
owners, types, contents, TTLs, and supported provider attributes. It is a
synthetic optimistic-concurrency token, not a server-side Cloudflare ETag.

## Read workflow

1. Fetch every page of DNS records for the configured zone.
2. Reject malformed or unexpectedly cross-zone records.
3. Normalize names, types, content, ordering, and provider attributes.
4. Group individual records into RRsets.
5. Return the synthetic revision with the result.

## Mutation workflow

1. Read the current records and compare the requested revision.
2. Validate the complete proposed record set and provider attributes.
3. Produce a dry-run plan containing record-ID deletes, patches, puts, and
   creates.
4. On `confirm=true`, read and compare the revision again immediately before
   writing.
5. Submit one Cloudflare batch request.
6. Read back until the API reflects the intended state.
7. Query Cloudflare's authoritative nameservers until the public answers
   converge or the verification deadline expires.
8. Append an audit event. If application or verification fails, attempt a
   compensating batch and report both the original and rollback outcomes.

Cloudflare executes a batch in a database transaction, but propagation through
its distributed DNS store is not atomic. Results must distinguish `accepted`,
`api_verified`, and `dns_verified` states.

## API and MCP shape

The initial read-only surface is deliberately separate from native zones:

- `GET /v1/providers/cloudflare/zones`
- `GET /v1/providers/cloudflare/zones/{zone}/records`
- `dns_cloudflare_list_zones`
- `dns_cloudflare_list_records`

Mutation tools will follow the existing two-step convention:

- `dns_cloudflare_plan_changes`
- `dns_cloudflare_apply_changes` with the exact revision and `confirm=true`

Once behavior and migrations are proven, a unified zone-list view can be added
without removing the provider-specific endpoints.

## Delivery plan

- [x] Read-only client, normalization, pagination, revisions, and tests.
- [x] Explicit zone configuration and secret-file loading in `rill-api`.
- [x] Read-only REST endpoints and control client.
- [x] Read-only MCP tools and documentation.
- [x] Dry-run planner for A, AAAA, CNAME, TXT, MX, CAA, SRV, and NS records.
- [x] Batch apply with second revision check and API read-back verification.
- [x] Authoritative DNS verification, audit events, and compensating rollback.
- [x] Terraform migration report and operator runbook.
- [x] Web console record browsing, planning, and guarded application.

## Non-goals for the first mutation release

- Cloudflare zone creation or deletion.
- DNSSEC, nameserver, account, rules, or proxy-setting administration outside
  record-level attributes.
- Account-wide zone discovery.
- Concurrent Terraform and RillDNS ownership of a record.
- A claim of globally atomic DNS propagation.
