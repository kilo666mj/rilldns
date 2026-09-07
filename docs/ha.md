# High availability

RillDNS separates DNS-serving availability from control-plane writer election.
Both nodes serve DNS continuously. The active node owns writable zone and
Cloudflare operations; the standby API remains read-only while it receives
authenticated zone snapshots.

## Status

`GET /v1/status/ha` is available on both the loopback management API and the
read-only metrics listener. It reports the node and role, write capability,
VIP ownership, peer health and latency, differential replication health, and a
summary of the peer's role, write capability, VIP ownership, zone count, and
last successful snapshot. Peer status requests carry a recursion guard so two
nodes cannot repeatedly query each other.

Configure each node through `rill-api.env`:

```sh
RILLDNS_HA_NODE=dns-primary
RILLDNS_HA_ROLE=active
RILLDNS_HA_PEER_NAME=dns-secondary
RILLDNS_HA_PEER_HEALTH_URL=http://192.0.2.11:18053/healthz
RILLDNS_HA_PEER_STATUS_URL=http://192.0.2.11:18053/v1/status/ha
RILLDNS_HA_VIP=192.0.2.53
```

The peer URL must use the read-only metrics listener. Do not expose or probe
the loopback management API remotely.

The dashboard renders these results as two side-by-side node cards. The node
serving the browser request is labelled local; the other is labelled peer.
Each card shows role, health, API write mode, VIP ownership, replication state,
zone count, and snapshot age. The peer card also shows link latency.

## DNS and management failover

Keepalived may automatically move the client-facing DNS VIP when the current
owner's DNS service fails. Both nodes continue serving DNS, independent of
which node owns the VIP.

The HTTPS reverse proxy should use the active node as its normal upstream and
the standby as a backup. This keeps the authenticated dashboard and read-only
status available during an active-node outage. The standby remains read-only,
so management requests that mutate DNS still require a deliberate, fenced
writer promotion.

## Promotion safety

VIP ownership is not writer election. A standby must not become writable until
an operator or quorum-backed controller has fenced the former active node and
verified that replication is current. Two nodes alone cannot distinguish a
failed peer from a network partition.

A safe manual promotion must, in order:

1. verify matching zone serials and a recent clean differential report;
2. fence the old writer so it cannot publish zones or Cloudflare mutations;
3. stop secondary replication on the promoted node;
4. change its API role from standby/read-only to active/writable;
5. reverse replication and NOTIFY direction before returning the old node;
6. record the promotion in an external audit log.

Run the machine-enforced preflight before step 2:

```sh
rill-ha \
  -active-url http://192.0.2.10:18053/v1/status/ha \
  -standby-url http://192.0.2.11:18053/v1/status/ha
```

It exits non-zero unless roles are correct, both nodes are healthy, the
standby's snapshot is fresh, and every zone serial matches. Passing preflight
does not fence the active node and therefore does not itself authorize writes.

Automatic writer failover is intentionally not enabled. It requires an
independent witness or fencing service. Keepalived may move the DNS-serving VIP
based on service health, but must not by itself enable control-plane writes.
