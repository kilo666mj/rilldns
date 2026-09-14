package querytelemetry

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// Collector consumes client-query dnstap frames. Aggregate mode retains only
// global counters; explicitly configured analytics modes receive bounded
// observations without changing the dnstap ingestion path.
type Collector struct {
	logger    *slog.Logger
	blocked   atomic.Pointer[map[string]struct{}]
	total     atomic.Uint64
	blocks    atomic.Uint64
	analytics *Analytics
}

func New(logger *slog.Logger) *Collector {
	return NewWithAnalytics(logger, nil)
}

func NewWithAnalytics(logger *slog.Logger, analytics *Analytics) *Collector {
	c := &Collector{logger: logger, analytics: analytics}
	empty := map[string]struct{}{}
	c.blocked.Store(&empty)
	return c
}

func (c *Collector) LoadBlocklist(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	// Read-only: nothing was written, so a close failure changes nothing.
	defer func() { _ = file.Close() }()

	domains := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		for _, name := range fields[1:] {
			name = strings.TrimSuffix(strings.ToLower(name), ".")
			if name != "" && !strings.HasPrefix(name, "#") {
				domains[name] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("refusing empty blocklist")
	}
	c.blocked.Store(&domains)
	return nil
}

func (c *Collector) Reload(ctx context.Context, path string, interval time.Duration) {
	var lastMod time.Time
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		info, err := os.Stat(path)
		if err == nil && info.ModTime() != lastMod {
			if err := c.LoadBlocklist(path); err != nil {
				c.logger.Error("reload blocklist for telemetry", "error", err)
			} else {
				lastMod = info.ModTime()
				c.logger.Info("loaded blocklist for telemetry", "domains", len(*c.blocked.Load()))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Collector) Serve(ctx context.Context, listener net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go c.consume(conn)
	}
}

func (c *Collector) consume(conn net.Conn) {
	// Nothing to return the error to on a consumed stream, and a dnstap peer
	// that already went away is the normal case.
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.logger.Warn("close dnstap connection", "error", err)
		}
	}()
	input, err := dnstap.NewFrameStreamInput(conn, true)
	if err != nil {
		c.logger.Warn("accept dnstap stream", "error", err)
		return
	}
	frames := make(chan []byte, 64)
	go input.ReadInto(frames)
	for frame := range frames {
		c.ConsumeFrame(frame)
	}
}

func (c *Collector) ConsumeFrame(frame []byte) {
	var tap dnstap.Dnstap
	if proto.Unmarshal(frame, &tap) != nil || tap.Message == nil || tap.Message.GetType() != dnstap.Message_CLIENT_QUERY {
		return
	}
	var message dns.Msg
	if message.Unpack(tap.Message.QueryMessage) != nil || len(message.Question) == 0 {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(message.Question[0].Name), ".")
	c.total.Add(1)
	_, blocked := (*c.blocked.Load())[name]
	if blocked {
		c.blocks.Add(1)
	}
	if c.analytics != nil {
		client := net.IP(tap.Message.GetQueryAddress()).String()
		if client == "<nil>" {
			client = "unknown"
		}
		queryType := dns.TypeToString[message.Question[0].Qtype]
		if queryType == "" {
			queryType = fmt.Sprintf("TYPE%d", message.Question[0].Qtype)
		}
		observedAt := time.Time{}
		if tap.Message.GetQueryTimeSec() != 0 {
			observedAt = time.Unix(int64(tap.Message.GetQueryTimeSec()), int64(tap.Message.GetQueryTimeNsec())).UTC()
		}
		c.analytics.Record(Observation{
			Time: observedAt, Domain: name, Client: client, Type: queryType,
			Protocol: tap.Message.GetSocketProtocol().String(), Blocked: blocked,
		})
	}
}

func (c *Collector) Metrics() (total, blocked uint64) {
	return c.total.Load(), c.blocks.Load()
}

func (c *Collector) Analytics(rangeName string, limit, recentLimit int) (Snapshot, error) {
	if c.analytics == nil {
		return Snapshot{Mode: ModeAggregate, Range: defaultRange(rangeName)}, nil
	}
	return c.analytics.Snapshot(rangeName, limit, recentLimit)
}

func (c *Collector) SaveAnalytics(path string) error {
	if c.analytics == nil {
		return nil
	}
	return c.analytics.Save(path)
}
