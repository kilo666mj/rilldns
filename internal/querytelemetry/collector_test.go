package querytelemetry

import (
	"io"
	"log/slog"
	"testing"

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
