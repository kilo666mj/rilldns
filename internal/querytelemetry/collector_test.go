package querytelemetry

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func TestConsumeFrameCountsOnlyClientQueriesAndDiscardsNames(t *testing.T) {
	collector := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	blocked := map[string]struct{}{"ads.example.test": {}}
	collector.blocked.Store(&blocked)

	collector.ConsumeFrame(frame(t, dnstap.Message_CLIENT_QUERY, "ads.example.test."))
	collector.ConsumeFrame(frame(t, dnstap.Message_CLIENT_QUERY, "allowed.example.test."))
	collector.ConsumeFrame(frame(t, dnstap.Message_CLIENT_RESPONSE, "ads.example.test."))
	total, blocks := collector.Metrics()
	if total != 2 || blocks != 1 {
		t.Fatalf("got total=%d blocked=%d, want 2/1", total, blocks)
	}
}

func TestStatisticsModeRanksDomainsClientsAndTypes(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	analytics, err := NewAnalytics(AnalyticsConfig{Mode: ModeStatistics, Retention: 24 * time.Hour, MaxDomains: 32, MaxClients: 16, RecentQueries: 10})
	if err != nil {
		t.Fatal(err)
	}
	analytics.now = func() time.Time { return now }
	collector := NewWithAnalytics(slog.New(slog.NewTextHandler(io.Discard, nil)), analytics)
	blocked := map[string]struct{}{"ads.example.test": {}}
	collector.blocked.Store(&blocked)

	collector.ConsumeFrame(clientFrame(t, "ads.example.test.", dns.TypeA, "192.0.2.10"))
	collector.ConsumeFrame(clientFrame(t, "www.example.test.", dns.TypeAAAA, "192.0.2.10"))
	collector.ConsumeFrame(clientFrame(t, "www.example.test.", dns.TypeAAAA, "192.0.2.11"))

	snapshot, err := collector.Analytics("1h", 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Enabled || snapshot.Mode != ModeStatistics || snapshot.Queries != 3 || snapshot.Blocked != 1 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if len(snapshot.TopDomains) != 2 || snapshot.TopDomains[0].Name != "www.example.test" || snapshot.TopDomains[0].Queries != 2 {
		t.Fatalf("top domains = %+v", snapshot.TopDomains)
	}
	if len(snapshot.TopBlockedDomains) != 1 || snapshot.TopBlockedDomains[0].Name != "ads.example.test" {
		t.Fatalf("top blocked domains = %+v", snapshot.TopBlockedDomains)
	}
	if len(snapshot.TopClients) != 2 || snapshot.TopClients[0].Name != "192.0.2.10" || snapshot.TopClients[0].Queries != 2 || snapshot.TopClients[0].Blocked != 1 {
		t.Fatalf("top clients = %+v", snapshot.TopClients)
	}
	if len(snapshot.Recent) != 0 {
		t.Fatalf("statistics mode retained detailed queries: %+v", snapshot.Recent)
	}
}

func TestDetailedModeRetainsOnlyBoundedRecentQueries(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	analytics, err := NewAnalytics(AnalyticsConfig{Mode: ModeDetailed, Retention: time.Hour, MaxDomains: 32, MaxClients: 16, RecentQueries: 2})
	if err != nil {
		t.Fatal(err)
	}
	analytics.now = func() time.Time { return now }
	for _, name := range []string{"one.example", "two.example", "three.example"} {
		analytics.Record(Observation{Time: now, Domain: name, Client: "192.0.2.10", Type: "A", Protocol: "UDP"})
	}
	snapshot, err := analytics.Snapshot("1h", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Recent) != 2 || snapshot.Recent[0].Domain != "three.example" || snapshot.Recent[1].Domain != "two.example" {
		t.Fatalf("recent queries = %+v", snapshot.Recent)
	}
	withoutRecent, err := analytics.Snapshot("1h", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutRecent.Recent) != 0 {
		t.Fatalf("recent=0 returned queries: %+v", withoutRecent.Recent)
	}
}

func TestAnalyticsStateRoundTripAndRetention(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	config := AnalyticsConfig{Mode: ModeStatistics, Retention: time.Hour, MaxDomains: 32, MaxClients: 16, RecentQueries: 10}
	analytics, err := NewAnalytics(config)
	if err != nil {
		t.Fatal(err)
	}
	analytics.now = func() time.Time { return now }
	analytics.Record(Observation{Time: now.Add(-30 * time.Minute), Domain: "current.example", Client: "192.0.2.10", Type: "A"})
	analytics.Record(Observation{Time: now.Add(-2 * time.Hour), Domain: "expired.example", Client: "192.0.2.11", Type: "A"})
	path := filepath.Join(t.TempDir(), "analytics.json")
	if err := analytics.Save(path); err != nil {
		t.Fatal(err)
	}

	restored, err := NewAnalytics(config)
	if err != nil {
		t.Fatal(err)
	}
	restored.now = func() time.Time { return now }
	if err := restored.Load(path); err != nil {
		t.Fatal(err)
	}
	snapshot, err := restored.Snapshot("1h", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Queries != 1 || len(snapshot.TopDomains) != 1 || snapshot.TopDomains[0].Name != "current.example" {
		t.Fatalf("restored snapshot = %+v", snapshot)
	}
}

func TestAnalyticsRejectsUnboundedRetentionCapacity(t *testing.T) {
	_, err := NewAnalytics(AnalyticsConfig{
		Mode: ModeStatistics, Retention: 31 * 24 * time.Hour,
		MaxDomains: 10000, MaxClients: 4096, RecentQueries: 1000,
	})
	if err == nil {
		t.Fatal("unbounded analytics capacity was accepted")
	}
}

func frame(t *testing.T, kind dnstap.Message_Type, name string) []byte {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(name, dns.TypeA)
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	tapType := dnstap.Dnstap_MESSAGE
	tap := &dnstap.Dnstap{Type: &tapType, Message: &dnstap.Message{Type: &kind, QueryMessage: wire}}
	result, err := proto.Marshal(tap)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func clientFrame(t *testing.T, name string, queryType uint16, client string) []byte {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(name, queryType)
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	tapType := dnstap.Dnstap_MESSAGE
	kind := dnstap.Message_CLIENT_QUERY
	family := dnstap.SocketFamily_INET
	protocol := dnstap.SocketProtocol_UDP
	tap := &dnstap.Dnstap{Type: &tapType, Message: &dnstap.Message{
		Type: &kind, QueryMessage: wire, QueryAddress: net.ParseIP(client).To4(),
		SocketFamily: &family, SocketProtocol: &protocol,
	}}
	result, err := proto.Marshal(tap)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
