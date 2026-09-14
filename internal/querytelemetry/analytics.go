package querytelemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kilo666mj/rilldns/internal/statusfile"
)

const (
	ModeAggregate  = "aggregate"
	ModeStatistics = "statistics"
	ModeDetailed   = "detailed"

	analyticsVersion = 1
	bucketWidth      = 5 * time.Minute
	maxStateBytes    = 64 << 20
	maxDomainSlots   = 2_000_000
	maxClientSlots   = 500_000
)

type AnalyticsConfig struct {
	Mode          string
	Retention     time.Duration
	MaxDomains    int
	MaxClients    int
	RecentQueries int
}

type Observation struct {
	Time     time.Time
	Domain   string
	Client   string
	Type     string
	Protocol string
	Blocked  bool
}

type QueryEvent struct {
	Time     time.Time `json:"time"`
	Domain   string    `json:"domain"`
	Client   string    `json:"client"`
	Type     string    `json:"type"`
	Protocol string    `json:"protocol"`
	Blocked  bool      `json:"blocked"`
}

type RankedItem struct {
	Name    string  `json:"name"`
	Queries uint64  `json:"queries"`
	Blocked uint64  `json:"blocked,omitempty"`
	Percent float64 `json:"percent"`
}

type Snapshot struct {
	Enabled           bool         `json:"enabled"`
	Mode              string       `json:"mode"`
	Range             string       `json:"range"`
	Start             time.Time    `json:"start"`
	End               time.Time    `json:"end"`
	RetentionHours    int          `json:"retention_hours"`
	Queries           uint64       `json:"queries"`
	Blocked           uint64       `json:"blocked"`
	BlockedPercent    float64      `json:"blocked_percent"`
	TrackedDomains    int          `json:"tracked_domains"`
	TrackedClients    int          `json:"tracked_clients"`
	Truncated         bool         `json:"truncated"`
	TopDomains        []RankedItem `json:"top_domains"`
	TopBlockedDomains []RankedItem `json:"top_blocked_domains"`
	TopClients        []RankedItem `json:"top_clients"`
	QueryTypes        []RankedItem `json:"query_types"`
	Recent            []QueryEvent `json:"recent_queries,omitempty"`
}

type analyticsBucket struct {
	Start            time.Time         `json:"start"`
	Queries          uint64            `json:"queries"`
	Blocked          uint64            `json:"blocked"`
	Domains          map[string]uint64 `json:"domains"`
	BlockedDomains   map[string]uint64 `json:"blocked_domains"`
	Clients          map[string]uint64 `json:"clients"`
	BlockedClients   map[string]uint64 `json:"blocked_clients"`
	Types            map[string]uint64 `json:"types"`
	DomainsTruncated bool              `json:"domains_truncated,omitempty"`
	ClientsTruncated bool              `json:"clients_truncated,omitempty"`
	TypesTruncated   bool              `json:"types_truncated,omitempty"`
}

type persistedAnalytics struct {
	Version int                `json:"version"`
	Buckets []*analyticsBucket `json:"buckets"`
	Recent  []QueryEvent       `json:"recent_queries,omitempty"`
}

type Analytics struct {
	mu         sync.Mutex
	config     AnalyticsConfig
	buckets    map[int64]*analyticsBucket
	recent     []QueryEvent
	recentNext int
	now        func() time.Time
}

func NewAnalytics(config AnalyticsConfig) (*Analytics, error) {
	config.Mode = strings.ToLower(strings.TrimSpace(config.Mode))
	if config.Mode == "" {
		config.Mode = ModeAggregate
	}
	if config.Mode != ModeAggregate && config.Mode != ModeStatistics && config.Mode != ModeDetailed {
		return nil, fmt.Errorf("analytics mode must be %q, %q, or %q", ModeAggregate, ModeStatistics, ModeDetailed)
	}
	if config.Retention == 0 {
		config.Retention = 7 * 24 * time.Hour
	}
	if config.Retention < time.Hour || config.Retention > 31*24*time.Hour {
		return nil, errors.New("analytics retention must be between 1h and 31d")
	}
	if config.MaxDomains == 0 {
		config.MaxDomains = 512
	}
	if config.MaxClients == 0 {
		config.MaxClients = 128
	}
	if config.RecentQueries == 0 {
		config.RecentQueries = 1000
	}
	if config.MaxDomains < 16 || config.MaxDomains > 10000 {
		return nil, errors.New("analytics max domains must be between 16 and 10000")
	}
	if config.MaxClients < 8 || config.MaxClients > 4096 {
		return nil, errors.New("analytics max clients must be between 8 and 4096")
	}
	if config.RecentQueries < 1 || config.RecentQueries > 10000 {
		return nil, errors.New("analytics recent query limit must be between 1 and 10000")
	}
	buckets := int(config.Retention/bucketWidth) + 1
	if config.MaxDomains*buckets > maxDomainSlots {
		return nil, fmt.Errorf("analytics domain capacity exceeds the %d-slot safety limit", maxDomainSlots)
	}
	if config.MaxClients*buckets > maxClientSlots {
		return nil, fmt.Errorf("analytics client capacity exceeds the %d-slot safety limit", maxClientSlots)
	}
	return &Analytics{config: config, buckets: map[int64]*analyticsBucket{}, now: time.Now}, nil
}

func (a *Analytics) Enabled() bool {
	return a != nil && a.config.Mode != ModeAggregate
}

func (a *Analytics) Record(observation Observation) {
	if !a.Enabled() {
		return
	}
	now := a.now().UTC()
	if observation.Time.IsZero() {
		observation.Time = now
	} else {
		observation.Time = observation.Time.UTC()
	}
	if !observation.Time.Add(bucketWidth).After(now.Add(-a.config.Retention)) || observation.Time.After(now.Add(bucketWidth)) {
		return
	}
	observation.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(observation.Domain), "."))
	if observation.Domain == "" {
		return
	}
	observation.Client = strings.TrimSpace(observation.Client)
	if observation.Client == "" {
		observation.Client = "unknown"
	}
	observation.Type = strings.TrimSpace(observation.Type)
	if observation.Type == "" {
		observation.Type = "OTHER"
	}
	observation.Protocol = strings.TrimSpace(observation.Protocol)
	if observation.Protocol == "" {
		observation.Protocol = "UNKNOWN"
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now)
	start := observation.Time.Truncate(bucketWidth)
	key := start.Unix()
	bucket := a.buckets[key]
	if bucket == nil {
		bucket = &analyticsBucket{
			Start: start, Domains: map[string]uint64{}, BlockedDomains: map[string]uint64{},
			Clients: map[string]uint64{}, BlockedClients: map[string]uint64{}, Types: map[string]uint64{},
		}
		a.buckets[key] = bucket
	}
	bucket.Queries++
	bucket.DomainsTruncated = incrementBounded(bucket.Domains, observation.Domain, a.config.MaxDomains) || bucket.DomainsTruncated
	bucket.ClientsTruncated = incrementBounded(bucket.Clients, observation.Client, a.config.MaxClients) || bucket.ClientsTruncated
	bucket.TypesTruncated = incrementBounded(bucket.Types, observation.Type, 64) || bucket.TypesTruncated
	if observation.Blocked {
		bucket.Blocked++
		bucket.DomainsTruncated = incrementBounded(bucket.BlockedDomains, observation.Domain, a.config.MaxDomains) || bucket.DomainsTruncated
		bucket.ClientsTruncated = incrementBounded(bucket.BlockedClients, observation.Client, a.config.MaxClients) || bucket.ClientsTruncated
	}
	if a.config.Mode == ModeDetailed {
		a.addRecentLocked(QueryEvent(observation))
	}
}

func (a *Analytics) Snapshot(rangeName string, limit, recentLimit int) (Snapshot, error) {
	if a == nil {
		return Snapshot{Mode: ModeAggregate, Range: defaultRange(rangeName)}, nil
	}
	duration, normalizedRange, ok := analyticsRange(rangeName)
	if !ok {
		return Snapshot{}, errors.New("range must be one of 1h, 6h, 24h, or 7d")
	}
	if limit == 0 {
		limit = 10
	}
	if limit < 1 || limit > 100 {
		return Snapshot{}, errors.New("limit must be between 1 and 100")
	}
	if recentLimit < 0 || recentLimit > 1000 {
		return Snapshot{}, errors.New("recent limit must be between 0 and 1000")
	}

	now := a.now().UTC()
	start := now.Add(-duration)
	snapshot := Snapshot{
		Enabled: a.Enabled(), Mode: a.config.Mode, Range: normalizedRange,
		Start: start, End: now, RetentionHours: int(a.config.Retention.Hours()),
		TopDomains: []RankedItem{}, TopBlockedDomains: []RankedItem{},
		TopClients: []RankedItem{}, QueryTypes: []RankedItem{},
	}
	if !a.Enabled() {
		return snapshot, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(now)
	domains := map[string]uint64{}
	blockedDomains := map[string]uint64{}
	clients := map[string]uint64{}
	blockedClients := map[string]uint64{}
	types := map[string]uint64{}
	for _, bucket := range a.buckets {
		if !bucket.Start.Add(bucketWidth).After(start) || bucket.Start.After(now) {
			continue
		}
		snapshot.Queries += bucket.Queries
		snapshot.Blocked += bucket.Blocked
		mergeCounts(domains, bucket.Domains)
		mergeCounts(blockedDomains, bucket.BlockedDomains)
		mergeCounts(clients, bucket.Clients)
		mergeCounts(blockedClients, bucket.BlockedClients)
		mergeCounts(types, bucket.Types)
		snapshot.Truncated = snapshot.Truncated || bucket.DomainsTruncated || bucket.ClientsTruncated || bucket.TypesTruncated
	}
	if snapshot.Queries > 0 {
		snapshot.BlockedPercent = float64(snapshot.Blocked) * 100 / float64(snapshot.Queries)
	}
	snapshot.TrackedDomains = len(domains)
	snapshot.TrackedClients = len(clients)
	snapshot.TopDomains = rank(domains, blockedDomains, snapshot.Queries, limit)
	snapshot.TopBlockedDomains = rank(blockedDomains, blockedDomains, snapshot.Blocked, limit)
	snapshot.TopClients = rank(clients, blockedClients, snapshot.Queries, limit)
	snapshot.QueryTypes = rank(types, nil, snapshot.Queries, limit)
	if a.config.Mode == ModeDetailed && recentLimit > 0 {
		recent := a.orderedRecentLocked()
		for index := len(recent) - 1; index >= 0 && len(snapshot.Recent) < recentLimit; index-- {
			if recent[index].Time.After(start) && !recent[index].Time.After(now) {
				snapshot.Recent = append(snapshot.Recent, recent[index])
			}
		}
	}
	return snapshot, nil
}

func (a *Analytics) Save(path string) error {
	if !a.Enabled() || strings.TrimSpace(path) == "" {
		return nil
	}
	a.mu.Lock()
	a.pruneLocked(a.now().UTC())
	state := persistedAnalytics{Version: analyticsVersion, Recent: append([]QueryEvent(nil), a.orderedRecentLocked()...)}
	keys := make([]int64, 0, len(a.buckets))
	for key := range a.buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		state.Buckets = append(state.Buckets, cloneBucket(a.buckets[key]))
	}
	a.mu.Unlock()
	return statusfile.WriteJSON(path, state, 0600)
}

func (a *Analytics) Load(path string) error {
	if !a.Enabled() || strings.TrimSpace(path) == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxStateBytes {
		return fmt.Errorf("analytics state exceeds %d bytes", maxStateBytes)
	}
	var state persistedAnalytics
	decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes))
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("decode analytics state: %w", err)
	}
	if state.Version != analyticsVersion {
		return fmt.Errorf("unsupported analytics state version %d", state.Version)
	}
	now := a.now().UTC()
	buckets := map[int64]*analyticsBucket{}
	for _, bucket := range state.Buckets {
		if bucket == nil || bucket.Start.IsZero() || bucket.Start.After(now.Add(bucketWidth)) || !bucket.Start.Add(bucketWidth).After(now.Add(-a.config.Retention)) {
			continue
		}
		bucket.Start = bucket.Start.UTC().Truncate(bucketWidth)
		bucket.Domains = trimCounts(bucket.Domains, a.config.MaxDomains)
		bucket.BlockedDomains = trimCounts(bucket.BlockedDomains, a.config.MaxDomains)
		bucket.Clients = trimCounts(bucket.Clients, a.config.MaxClients)
		bucket.BlockedClients = trimCounts(bucket.BlockedClients, a.config.MaxClients)
		bucket.Types = trimCounts(bucket.Types, 256)
		buckets[bucket.Start.Unix()] = bucket
	}
	a.mu.Lock()
	a.buckets = buckets
	a.recent = nil
	a.recentNext = 0
	if a.config.Mode == ModeDetailed {
		first := 0
		if len(state.Recent) > a.config.RecentQueries {
			first = len(state.Recent) - a.config.RecentQueries
		}
		for _, event := range state.Recent[first:] {
			if event.Time.After(now.Add(-a.config.Retention)) && !event.Time.After(now) {
				a.addRecentLocked(event)
			}
		}
	}
	a.mu.Unlock()
	return nil
}

func analyticsRange(value string) (time.Duration, string, bool) {
	switch value {
	case "1h":
		return time.Hour, "1h", true
	case "", "6h":
		return 6 * time.Hour, "6h", true
	case "24h":
		return 24 * time.Hour, "24h", true
	case "7d":
		return 7 * 24 * time.Hour, "7d", true
	default:
		return 0, "", false
	}
}

func defaultRange(value string) string {
	_, normalized, ok := analyticsRange(value)
	if !ok {
		return value
	}
	return normalized
}

func incrementBounded(values map[string]uint64, key string, limit int) bool {
	if _, found := values[key]; found {
		values[key]++
		return false
	}
	if len(values) < limit {
		values[key] = 1
		return false
	}
	for existing, count := range values {
		if count <= 1 {
			delete(values, existing)
		} else {
			values[existing] = count - 1
		}
	}
	return true
}

func mergeCounts(target, source map[string]uint64) {
	for name, count := range source {
		target[name] += count
	}
}

func rank(values, blocked map[string]uint64, total uint64, limit int) []RankedItem {
	items := make([]RankedItem, 0, len(values))
	for name, queries := range values {
		item := RankedItem{Name: name, Queries: queries}
		if blocked != nil {
			item.Blocked = blocked[name]
		}
		if total > 0 {
			item.Percent = float64(queries) * 100 / float64(total)
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Queries == items[j].Queries {
			return items[i].Name < items[j].Name
		}
		return items[i].Queries > items[j].Queries
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func trimCounts(values map[string]uint64, limit int) map[string]uint64 {
	if values == nil {
		return map[string]uint64{}
	}
	if len(values) <= limit {
		return values
	}
	items := rank(values, nil, 0, limit)
	trimmed := make(map[string]uint64, len(items))
	for _, item := range items {
		trimmed[item.Name] = item.Queries
	}
	return trimmed
}

func cloneBucket(source *analyticsBucket) *analyticsBucket {
	clone := *source
	clone.Domains = cloneCounts(source.Domains)
	clone.BlockedDomains = cloneCounts(source.BlockedDomains)
	clone.Clients = cloneCounts(source.Clients)
	clone.BlockedClients = cloneCounts(source.BlockedClients)
	clone.Types = cloneCounts(source.Types)
	return &clone
}

func cloneCounts(source map[string]uint64) map[string]uint64 {
	clone := make(map[string]uint64, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func (a *Analytics) addRecentLocked(event QueryEvent) {
	if len(a.recent) < a.config.RecentQueries {
		a.recent = append(a.recent, event)
		return
	}
	a.recent[a.recentNext] = event
	a.recentNext = (a.recentNext + 1) % len(a.recent)
}

func (a *Analytics) orderedRecentLocked() []QueryEvent {
	if len(a.recent) < a.config.RecentQueries || a.recentNext == 0 {
		return append([]QueryEvent(nil), a.recent...)
	}
	ordered := make([]QueryEvent, 0, len(a.recent))
	ordered = append(ordered, a.recent[a.recentNext:]...)
	ordered = append(ordered, a.recent[:a.recentNext]...)
	return ordered
}

func (a *Analytics) pruneLocked(now time.Time) {
	cutoff := now.Add(-a.config.Retention)
	for key, bucket := range a.buckets {
		if !bucket.Start.Add(bucketWidth).After(cutoff) {
			delete(a.buckets, key)
		}
	}
}
