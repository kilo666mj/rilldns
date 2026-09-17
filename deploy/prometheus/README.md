# Prometheus examples

`rilldns.yaml` supplies a documentation-only scrape job for both rilldns
nodes. `rilldns.rules.yml` supplies alerts for peer reachability, single-writer
and single-VIP invariants, refresh health, zone and blocklist freshness, DNSSEC
expiry, and authoritative differential results.

Replace the reserved hostnames with reviewed inventory, then validate both
files with the Prometheus tooling used by the deployment before loading them.
Keep both nodes as scrape targets: an aggregate alert is only meaningful when
Prometheus can observe each node independently.

The alert thresholds are operational starting points, not universal policy.
Align them with the refresh intervals and recovery objectives documented in
[the HA guide](../../docs/ha.md) and [operations runbook](../../docs/operations.md).
