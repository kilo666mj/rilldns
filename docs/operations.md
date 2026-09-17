# Operations, backup, and recovery

This runbook complements the [production deployment model](deployment.md) and
[high-availability design](ha.md). It assumes two nodes, explicit active and
standby API roles, TSIG-authenticated transfer, and a client-facing DNS VIP.
Adapt all paths and service names to the reviewed deployment inventory.

## Routine checks

Daily:

- verify UDP and TCP answers through the VIP and directly from both nodes;
- inspect `/healthz`, `/readyz`, `/metrics`, and `/v1/status/ha` on each node;
- confirm the active API is writable and the standby API is read-only;
- check the last successful blocklist refresh and differential comparison;
- confirm the standby snapshot is recent and every zone serial matches;
- review query-analytics retention and mode, especially after configuration
  changes.

Weekly:

- run the Ansible playbook with `--check --diff` and review drift;
- verify release and CoreDNS checksums against the intended versions;
- restore the newest backup into a disposable directory and validate every
  zone with `rill-zonecheck`;
- review TSIG, OIDC, session, Cloudflare, and MCP credential age and ownership;
- inspect audit records and alert history for unexplained gaps.

Use documentation-only targets for synthetic checks:

```sh
dig @192.0.2.10 www.example.test A +tcp
dig @192.0.2.11 www.example.test A +tcp
rill-diff -primary 192.0.2.10:1056 -secondary 192.0.2.11:1054
```

`192.0.2.0/24` and `example.test` are reserved examples. Put real addresses,
zone names, and TSIG material only in ignored inventory and vault files.

## Backup scope

A recoverable backup contains:

- authoritative zone files and revision metadata;
- the last-known-good secondary snapshot;
- role and node configuration;
- audit records required by local policy;
- blocklist allow/deny overrides;
- OIDC and session configuration needed to restore management access;
- TSIG, Cloudflare, and other credentials through the operator secret store,
  not inside a general-purpose archive.

Back up both nodes off-host. Encryption keys and credentials need an independent
recovery path with access controls at least as strong as the live nodes. Query
telemetry in `statistics` or `detailed` mode may contain domain or client
identifiers; apply the configured retention limit to backup copies as well.

## Restore rehearsal

1. Restore into a disposable directory or isolated host with listeners
   disabled.
2. Validate every zone and reject path escapes, malformed records, duplicate
   ownership, and decreasing SOA serials.
3. Start a cache-free authority on a non-production port.
4. Compare its UDP and TCP answers with the intended recovery peer.
5. Verify the management API remains loopback-only and the restored role is
   read-only until explicitly promoted.
6. Record the source backup, validation results, and recovery duration.

Archive existence is not a restore test. Do not attach an unverified restored
node to NOTIFY, AXFR, the DNS VIP, or Cloudflare mutation workflows.

## Upgrade procedure

Deploy tagged, checksum-pinned releases one node at a time:

1. read the release notes and run repository tests;
2. update the ignored deployment inventory and checksums;
3. run `ansible-playbook --check --diff` and review the complete plan;
4. update the standby first and verify direct DNS, replication, metrics, and
   read-only API behavior;
5. move or exercise the DNS VIP, then update the active node;
6. verify serial equality, a clean differential result, blocklist freshness,
   and UI authentication before declaring success.

Rollback uses the previously pinned release plus the last verified compatible
state. Never roll back zone data merely to match an older binary without first
checking format compatibility and SOA serial behavior.

## Failure and troubleshooting guide

| Symptom | Safe first checks | Recovery rule |
| --- | --- | --- |
| VIP answers fail | Query each node directly over UDP and TCP; inspect keepalived health | Move the VIP only to a node already serving correct answers |
| Secondary serial is stale | Check NOTIFY delivery, TSIG, AXFR listener, hourly SOA poll, and snapshot timestamp | Keep the standby API read-only until serials match |
| Differential check fails | Compare cache-free authorities and inspect the exact record/type mismatch | Do not publish or promote while the mismatch is unexplained |
| Blocklist refresh fails | Inspect download, compiler, minimum-size guard, and prior snapshot | Preserve the last-known-good compiled list |
| UI login fails | Verify exact issuer, callback, client ID, clock, and reverse-proxy origin | Do not bypass OIDC by exposing the loopback API |
| Active node is unreachable | Check peer status and replication freshness from an independent host | Follow the fenced promotion sequence in [HA](ha.md); VIP ownership is not writer election |

For migrations, use the dedicated [Technitium](technitium-migration.md) and
[Cloudflare Terraform](cloudflare-terraform-migration.md) guides rather than
improvising a production cutover.
