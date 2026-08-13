# RillDNS MCP server

`rill-mcp` is a local stdio MCP server built with the official Go MCP SDK. It is a narrow adapter over the loopback RillDNS REST API; it never edits zone files or invokes CoreDNS directly.

This preserves one mutation path:

```text
MCP client -> rill-mcp -> rill-api -> validate/history/publish/verify/audit -> CoreDNS
```

## Tools

- `dns_list_zones`: list managed zones, serials, and revisions.
- `dns_refresh_status`: inspect zone-transfer, DNSSEC-signature, and blocklist refresh health.
- `dns_list_records`: list every RRset in a zone.
- `dns_plan_changes`: validate and preview an atomic batch without publishing it.
- `dns_apply_changes`: publish a batch only with the current revision and `confirm: true`.
- `dns_create_zone`: validate or publish complete zone text with an explicit role; publication requires `confirm: true`.
- `dns_delete_zone`: validate or delete a zone with its exact revision; deletion requires `confirm: true`.
- `dns_test_resolution`: send a read-only query to the local RillDNS listener.
- `dns_get_blocklist_config`: read sources, allow/deny domains, and revision.
- `dns_update_blocklist_config`: validate or replace the complete configuration; publication requires the exact revision and `confirm: true`.

The apply tool is marked destructive in MCP metadata. Server-side safety does not depend on the MCP host honoring that hint: confirmation, revision checks, validation, limits, audit, publication verification, and rollback are enforced by RillDNS.

## Run locally on a DNS node

```sh
/usr/local/bin/rill-mcp
```

Because stdio carries MCP JSON-RPC, diagnostic logs go only to stderr.

## Run remotely over SSH

Configure an MCP host to launch this command and arguments:

```text
command: ssh
args: root@dns-primary /usr/local/bin/rill-mcp
```

The SSH process transports MCP stdio while `rill-mcp` reaches the API through loopback on `dns-primary`. No API or MCP TCP port is exposed.

Use `dns-primary` for mutations. The API on `dns-secondary` enforces read-only mode, so mutation tools invoked there will return a visible tool error.

## Safety limits

- Maximum 100 RRset changes per MCP call.
- Exact zone revision required for plans and commits.
- Explicit `confirm: true` required for commits, creates, and deletes.
- Exact revision and explicit confirmation required for blocklist configuration publication.
- No zone-file paths or arbitrary command execution.
- No CoreDNS configuration mutation.
- No remote HTTP MCP transport yet.
