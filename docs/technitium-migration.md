# Migrating zones from Technitium to RillDNS

## Strategy

Use standard DNS zone transfer or RFC 1035 export rather than reading Technitium's internal binary files. Technitium supports AXFR/IXFR and standard text export, making the migration independent of its storage implementation.

Keep the migration staged and reversible until RillDNS has completed an
appropriate soak period in your environment.

## 1. Inventory

Use Technitium's `/api/zones/list` endpoint with a non-expiring, read-scoped API token to inventory:

- Primary zones.
- Secondary zones and their primaries.
- Stub and conditional-forwarder zones.
- Disabled zones and records.
- Zone transfer and TSIG settings.
- DNSSEC-signed zones.
- Proprietary `ANAME`, `APP`, and `FWD` records.

Do not silently translate proprietary record types. Each requires an explicit replacement decision:

- Conditional forwarders become CoreDNS server blocks or generated forwarding rules.
- `ANAME` needs replacement with explicit A/AAAA management or another flattening mechanism.
- `APP` records need feature-specific replacements.
- Disabled records should be retained in a migration report but not published.

## 2. Capture authoritative data

For every conventional primary zone:

1. Temporarily authorize AXFR from the migration host, preferably with TSIG.
2. Request AXFR over TCP from a Technitium instance.
3. Write the result to a staging file, never directly to the live zone directory.
4. Verify that the transfer begins and ends with the same SOA and contains exactly one apex SOA.
5. Record the source server, source serial, record count, checksum, and capture time.

If AXFR is unavailable, use Technitium's standard RFC 1035 zone export. Do not migrate from cached query results because ordinary DNS queries cannot enumerate a zone reliably.

## 3. Validate and normalize

Run the staged zone through the same RillDNS parser and validator used by the API:

- All owners must belong to the zone except legitimate glue represented within it.
- Exactly one apex SOA and at least one apex NS are required.
- CNAME exclusivity must hold.
- Duplicate records are rejected.
- All record types must parse using standard presentation format.
- Unsupported proprietary records produce a blocking migration error.

Preserve the Technitium SOA serial during import. RillDNS advances it only after a subsequent managed change.

## 4. Stage in RillDNS

- Place validated zones in a staging directory.
- Generate the corresponding CoreDNS authoritative configuration.
- Start or reload RillDNS on the test port, initially `1053`.
- Keep the management API read-only while bulk import is occurring.
- Copy the same snapshot to the read-only node until AXFR-based RillDNS replication is enabled.

The control plane will later expose a dedicated import operation; initially this remains an operator-reviewed CLI workflow.

## 5. Differential testing

For every owner/type pair in each transferred zone, query both Technitium and RillDNS and compare:

- Response code.
- Authoritative flag.
- Answer RRsets and TTLs.
- CNAME chains.
- NXDOMAIN versus NODATA behavior.
- Wildcards.
- Delegations and glue.
- UDP and TCP responses.
- AXFR contents.

Also sample names that do not exist and names immediately below delegations. Normalize record ordering before comparison.

## 6. Freeze and final synchronization

Immediately before cutover:

1. Freeze or coordinate zone changes in Technitium.
2. Read each current SOA serial.
3. Re-transfer zones whose serial changed after the initial capture.
4. Repeat validation and differential tests.
5. Confirm both RillDNS nodes serve the final serial.

## 7. Cutover and rollback

For internal resolver use, move a small client group to RillDNS first, then update DHCP/static resolver configuration gradually.

For authoritative public zones, update delegation or virtual IP routing only after external queries succeed against both RillDNS nodes. Lower relevant TTLs ahead of the maintenance window if necessary.

Keep Technitium running but read-only during the soak period. Rollback consists of restoring the prior resolver/VIP/delegation target; zone data remains unchanged in Technitium.

## Blocklists and forwarding

These are migrated separately from authoritative zones:

- Copy blocklist source URLs into RillDNS configuration.
- Export explicit allowed and blocked names.
- Compare normalization and subtree matching semantics.
- Keep the existing forwarder path during initial migration, or configure a
  tested set of directly reachable upstream resolvers on both RillDNS nodes.

## Further automation to add

A `rill-migrate` CLI should implement:

```text
rill-migrate inventory --technitium URL --token-file FILE
rill-migrate axfr --server HOST:PORT --zone ZONE --tsig-file FILE --output DIR
rill-migrate validate --input DIR --report report.json
rill-migrate diff --technitium HOST:PORT --rilldns HOST:PORT --report diff.json
rill-migrate import --input DIR --dry-run
```

The default for every command that can publish data must remain dry-run.
