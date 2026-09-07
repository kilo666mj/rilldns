package secondary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var errZoneGone = errors.New("zone no longer exists on primary")

type Config struct {
	Primary       string
	ProbePrimary  string
	Listen        string
	Zones         []string
	OutputDir     string
	StatusFile    string
	Refresh       time.Duration
	Timeout       time.Duration
	NotifyFrom    net.IP
	TSIGName      string
	TSIGSecret    string
	Now           func() time.Time
	DiscoverZones bool
	MaxZones      int
}

type Status struct {
	Kind                string       `json:"kind"`
	Success             bool         `json:"success"`
	LastAttempt         time.Time    `json:"last_attempt"`
	LastSuccess         time.Time    `json:"last_success,omitempty"`
	Source              string       `json:"source"`
	Zones               []ZoneStatus `json:"zones"`
	EarliestRRSIGExpiry string       `json:"earliest_rrsig_expiry,omitempty"`
	Error               string       `json:"error,omitempty"`
}

type ZoneStatus struct {
	Name    string `json:"name"`
	Serial  uint32 `json:"serial"`
	Records int    `json:"records"`
}

type Service struct {
	config     Config
	trigger    chan string
	mu         sync.Mutex
	status     Status
	metadata   map[string]ZoneStatus
	zoneErrors map[string]string
	zonesMu    sync.RWMutex
}

func New(config Config) (*Service, error) {
	if config.Primary == "" || config.Listen == "" || len(config.Zones) == 0 || config.OutputDir == "" || config.StatusFile == "" {
		return nil, errors.New("primary, listen, zones, output directory, and status file are required")
	}
	if config.Refresh <= 0 {
		config.Refresh = time.Hour
	}
	if config.ProbePrimary == "" {
		config.ProbePrimary = config.Primary
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxZones <= 0 {
		config.MaxZones = 1000
	}
	if len(config.Zones) > config.MaxZones {
		return nil, fmt.Errorf("configured zones exceed maximum of %d", config.MaxZones)
	}
	config.TSIGName = strings.ToLower(dns.Fqdn(config.TSIGName))
	if config.TSIGName == "." || config.TSIGSecret == "" {
		return nil, errors.New("TSIG name and secret are required")
	}
	seen := map[string]struct{}{}
	for index, zone := range config.Zones {
		zone = strings.ToLower(dns.Fqdn(strings.TrimSpace(zone)))
		if zone == "." {
			return nil, errors.New("root zone is not supported")
		}
		if _, exists := seen[zone]; exists {
			return nil, fmt.Errorf("duplicate zone %s", zone)
		}
		seen[zone] = struct{}{}
		config.Zones[index] = zone
	}
	return &Service{
		config:     config,
		trigger:    make(chan string, len(config.Zones)*2),
		status:     Status{Kind: "zones", Source: config.Primary, Zones: []ZoneStatus{}},
		metadata:   map[string]ZoneStatus{},
		zoneErrors: map[string]string{},
	}, nil
}

func (s *Service) Run(ctx context.Context) (err error) {
	if err := os.MkdirAll(s.config.OutputDir, 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.config.StatusFile), 0750); err != nil {
		return err
	}
	if s.config.DiscoverZones {
		if err := s.discoverZones(); err != nil {
			return err
		}
	}
	tsigSecrets := map[string]string{s.config.TSIGName: s.config.TSIGSecret}
	serverUDP := &dns.Server{Addr: s.config.Listen, Net: "udp", Handler: dns.HandlerFunc(s.handleNotify), TsigSecret: tsigSecrets}
	serverTCP := &dns.Server{Addr: s.config.Listen, Net: "tcp", Handler: dns.HandlerFunc(s.handleNotify), TsigSecret: tsigSecrets}
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- serverUDP.ListenAndServe() }()
	go func() { errorsChannel <- serverTCP.ListenAndServe() }()
	// A listener that fails to shut down leaves the port held, which the next
	// start would then fail on, so report it rather than exiting quietly.
	defer closeWithError(&err, "shutdown UDP notify listener", serverUDP.Shutdown)
	defer closeWithError(&err, "shutdown TCP notify listener", serverTCP.Shutdown)

	for _, zone := range s.zones() {
		s.queue(zone)
	}
	ticker := time.NewTicker(s.config.Refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errorsChannel:
			return err
		case zone := <-s.trigger:
			s.syncZone(zone)
		case <-ticker.C:
			for _, zone := range s.zones() {
				s.queue(zone)
			}
		}
	}
}

func (s *Service) handleNotify(writer dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	if request.Opcode != dns.OpcodeNotify || len(request.Question) != 1 || request.Question[0].Qtype != dns.TypeSOA {
		response.Rcode = dns.RcodeNotImplemented
		_ = writer.WriteMsg(response)
		return
	}
	remoteIP := remoteAddressIP(writer.RemoteAddr())
	zone := strings.ToLower(dns.Fqdn(request.Question[0].Name))
	tsig := request.IsTsig()
	if tsig == nil || strings.ToLower(tsig.Hdr.Name) != s.config.TSIGName || writer.TsigStatus() != nil || s.config.NotifyFrom == nil || !s.config.NotifyFrom.Equal(remoteIP) || (!s.config.DiscoverZones && !s.hasZone(zone)) {
		response.Rcode = dns.RcodeRefused
		_ = writer.WriteMsg(response)
		return
	}
	if s.config.DiscoverZones && !s.hasZone(zone) {
		if !s.addZone(zone) {
			response.Rcode = dns.RcodeRefused
			_ = writer.WriteMsg(response)
			return
		}
	}
	_ = writer.WriteMsg(response)
	s.queueNotify(zone)
}

func (s *Service) discoverZones() error {
	entries, err := os.ReadDir(s.config.OutputDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".zone") {
			continue
		}
		zone := strings.TrimSuffix(entry.Name(), ".zone") + "."
		if _, ok := dns.IsDomainName(zone); ok && !s.hasZone(zone) {
			if !s.addZone(strings.ToLower(zone)) {
				return fmt.Errorf("discovered zones exceed maximum of %d", s.config.MaxZones)
			}
		}
	}
	return nil
}

func (s *Service) queueNotify(zone string) {
	s.queue(zone)
}

func (s *Service) queue(zone string) {
	select {
	case s.trigger <- zone:
	default:
	}
}

func (s *Service) hasZone(zone string) bool {
	s.zonesMu.RLock()
	defer s.zonesMu.RUnlock()
	for _, configured := range s.config.Zones {
		if configured == zone {
			return true
		}
	}
	return false
}

func (s *Service) addZone(zone string) bool {
	s.zonesMu.Lock()
	defer s.zonesMu.Unlock()
	for _, configured := range s.config.Zones {
		if configured == zone {
			return true
		}
	}
	if len(s.config.Zones) >= s.config.MaxZones {
		return false
	}
	s.config.Zones = append(s.config.Zones, zone)
	sort.Strings(s.config.Zones)
	return true
}

func (s *Service) zones() []string {
	s.zonesMu.RLock()
	defer s.zonesMu.RUnlock()
	return append([]string(nil), s.config.Zones...)
}

func (s *Service) syncZone(zone string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.config.Now().UTC()
	s.status.LastAttempt = now
	current, _ := readSerial(filepath.Join(s.config.OutputDir, zoneFileName(zone)))
	serial, err := s.remoteSerial(zone)
	gone := errors.Is(err, errZoneGone) && s.config.DiscoverZones
	if gone {
		path := filepath.Join(s.config.OutputDir, zoneFileName(zone))
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = removeErr
		} else {
			delete(s.metadata, zone)
			s.status.Zones = sortedMetadata(s.metadata)
			s.status.EarliestRRSIGExpiry = earliestExpiry(s.config.OutputDir, s.zones())
			err = nil
		}
	}
	if err == nil && !gone && serial != current {
		// The auto plugin has no IXFR journal. Its IXFR-to-AXFR fallback can
		// inherit the cache plugin's minimum TTL, corrupting snapshot TTLs.
		// Fetch a fresh, independently TSIG-authenticated AXFR for every update.
		var records []dns.RR
		records, err = s.transfer(zone, 0, false)
		if err == nil {
			err = s.publish(zone, records)
		}
	}
	if err == nil && !gone {
		var metadata ZoneStatus
		metadata, _, err = inspectZone(filepath.Join(s.config.OutputDir, zoneFileName(zone)), zone)
		if err == nil {
			s.metadata[zone] = metadata
			s.status.Zones = sortedMetadata(s.metadata)
			s.status.EarliestRRSIGExpiry = earliestExpiry(s.config.OutputDir, s.zones())
		}
	}
	if err == nil {
		delete(s.zoneErrors, zone)
	} else {
		s.zoneErrors[zone] = err.Error()
	}
	s.status.Success = len(s.zoneErrors) == 0
	s.status.Error = joinedErrors(s.zoneErrors)
	if s.status.Success {
		s.status.LastSuccess = now
	}
	if statusErr := writeJSONAtomic(s.config.StatusFile, s.status); statusErr != nil {
		fmt.Fprintf(os.Stderr, "write secondary status: %v\n", statusErr)
	}
}

func (s *Service) remoteSerial(zone string) (uint32, error) {
	message := new(dns.Msg)
	message.SetQuestion(zone, dns.TypeSOA)
	message.SetTsig(s.config.TSIGName, dns.HmacSHA256, 300, s.config.Now().Unix())
	client := &dns.Client{Net: "tcp", Timeout: s.config.Timeout, TsigSecret: map[string]string{s.config.TSIGName: s.config.TSIGSecret}}
	response, _, err := client.Exchange(message, s.config.ProbePrimary)
	if err != nil {
		return 0, fmt.Errorf("SOA %s: %w", zone, err)
	}
	if response.Rcode != dns.RcodeSuccess {
		if response.Rcode == dns.RcodeNameError && response.Authoritative {
			return 0, errZoneGone
		}
		return 0, fmt.Errorf("SOA %s: %s", zone, dns.RcodeToString[response.Rcode])
	}
	for _, record := range response.Answer {
		if soa, ok := record.(*dns.SOA); ok {
			return soa.Serial, nil
		}
	}
	return 0, fmt.Errorf("SOA %s: response contained no SOA", zone)
}

func (s *Service) transfer(zone string, serial uint32, incremental bool) ([]dns.RR, error) {
	message := new(dns.Msg)
	if incremental && serial != 0 {
		message.SetIxfr(zone, serial, "", "")
	} else {
		message.SetAxfr(zone)
	}
	message.SetTsig(s.config.TSIGName, dns.HmacSHA256, 300, s.config.Now().Unix())
	transfer := &dns.Transfer{
		DialTimeout: s.config.Timeout, ReadTimeout: s.config.Timeout, WriteTimeout: s.config.Timeout,
		TsigSecret: map[string]string{s.config.TSIGName: s.config.TSIGSecret},
	}
	channel, err := transfer.In(message, s.config.Primary)
	if err != nil {
		return nil, err
	}
	var records []dns.RR
	for envelope := range channel {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		records = append(records, envelope.RR...)
	}
	return records, nil
}

func (s *Service) publish(zone string, records []dns.RR) error {
	if !fullSnapshot(records) {
		return fmt.Errorf("%s transfer did not return a complete AXFR snapshot", zone)
	}
	soa, ok := records[0].(*dns.SOA)
	if !ok || !strings.EqualFold(soa.Hdr.Name, zone) {
		return fmt.Errorf("%s transfer has invalid apex SOA", zone)
	}
	hasNS := false
	for _, record := range records[1 : len(records)-1] {
		if record.Header().Rrtype == dns.TypeSOA {
			return fmt.Errorf("%s transfer contains an unexpected SOA", zone)
		}
		if record.Header().Rrtype == dns.TypeNS && strings.EqualFold(record.Header().Name, zone) {
			hasNS = true
		}
	}
	if !hasNS {
		return fmt.Errorf("%s transfer has no apex NS", zone)
	}
	var builder strings.Builder
	for _, record := range records[:len(records)-1] {
		builder.WriteString(record.String())
		builder.WriteByte('\n')
	}
	path := filepath.Join(s.config.OutputDir, zoneFileName(zone))
	return writeFileAtomic(path, []byte(builder.String()), 0440)
}

func fullSnapshot(records []dns.RR) bool {
	if len(records) < 3 {
		return false
	}
	first, firstOK := records[0].(*dns.SOA)
	last, lastOK := records[len(records)-1].(*dns.SOA)
	return firstOK && lastOK && first.Serial == last.Serial && strings.EqualFold(first.Hdr.Name, last.Hdr.Name)
}

func readSerial(path string) (uint32, error) {
	metadata, _, err := inspectZone(path, "")
	return metadata.Serial, err
}

func inspectZone(path, zone string) (ZoneStatus, time.Time, error) {
	file, err := os.Open(path)
	if err != nil {
		return ZoneStatus{}, time.Time{}, err
	}
	// Read-only: nothing was written, so a close failure changes nothing.
	defer func() { _ = file.Close() }()
	parser := dns.NewZoneParser(file, "", path)
	metadata := ZoneStatus{Name: strings.TrimSuffix(zone, ".")}
	var expiry time.Time
	for record, ok := parser.Next(); ok; record, ok = parser.Next() {
		metadata.Records++
		if soa, isSOA := record.(*dns.SOA); isSOA {
			metadata.Serial = soa.Serial
		}
		if signature, isSignature := record.(*dns.RRSIG); isSignature {
			candidate := time.Unix(int64(signature.Expiration), 0).UTC()
			if expiry.IsZero() || candidate.Before(expiry) {
				expiry = candidate
			}
		}
	}
	if err := parser.Err(); err != nil {
		return ZoneStatus{}, time.Time{}, err
	}
	if metadata.Serial == 0 {
		return ZoneStatus{}, time.Time{}, errors.New("zone contains no SOA")
	}
	return metadata, expiry, nil
}

func sortedMetadata(values map[string]ZoneStatus) []ZoneStatus {
	result := make([]ZoneStatus, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func joinedErrors(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	zones := make([]string, 0, len(values))
	for zone := range values {
		zones = append(zones, zone)
	}
	sort.Strings(zones)
	parts := make([]string, 0, len(zones))
	for _, zone := range zones {
		parts = append(parts, zone+": "+values[zone])
	}
	return strings.Join(parts, "; ")
}

func earliestExpiry(directory string, zones []string) string {
	var earliest time.Time
	for _, zone := range zones {
		_, expiry, err := inspectZone(filepath.Join(directory, zoneFileName(zone)), zone)
		if err == nil && !expiry.IsZero() && (earliest.IsZero() || expiry.Before(earliest)) {
			earliest = expiry
		}
	}
	if earliest.IsZero() {
		return ""
	}
	return earliest.UTC().Format("20060102150405")
}

func zoneFileName(zone string) string { return strings.TrimSuffix(zone, ".") + ".zone" }

func remoteAddressIP(address net.Addr) net.IP {
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".rill-secondary-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	// Best effort: on the success path the rename has already consumed
	// this name, so the remove is expected to fail with ENOENT.
	defer func() { _ = os.Remove(temporaryName) }()
	if _, err = temporary.Write(data); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(temporaryName, mode)
	}
	if err == nil {
		err = os.Rename(temporaryName, path)
	}
	return err
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data, 0440)
}
