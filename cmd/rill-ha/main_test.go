package main

import (
	"testing"
	"time"
)

func TestEvaluateRequiresMatchingFreshStandby(t *testing.T) {
	now := time.Now().UTC()
	active := status{Node: "dns-a", Role: "active", Writable: true, Healthy: true, ReplicationHealthy: true}
	active.Peer.Reachable = true
	active.Zones.LastSuccess = now
	active.Zones.Zones = []zone{{Name: "example.test.", Serial: 10}}
	standby := status{Node: "dns-b", Role: "standby", Healthy: true, ReplicationHealthy: true}
	standby.Peer.Reachable = true
	standby.Zones.LastSuccess = now
	standby.Zones.Zones = []zone{{Name: "example.test", Serial: 10}}
	if got := evaluate(active, standby, nil, nil, time.Hour, now); !got.Ready {
		t.Fatalf("expected ready: %+v", got)
	}
	standby.Zones.Zones[0].Serial = 9
	if got := evaluate(active, standby, nil, nil, time.Hour, now); got.Ready || len(got.Reasons) == 0 {
		t.Fatalf("expected serial mismatch: %+v", got)
	}
}
