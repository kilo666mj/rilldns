package zones

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNotFound         = errors.New("zone not found")
	ErrAlreadyExists    = errors.New("zone already exists")
	ErrRevisionMismatch = errors.New("zone revision mismatch")
	ErrInvalidChange    = errors.New("invalid zone change")
	ErrReadOnlyZone     = errors.New("zone is read-only")
)

type Verifier interface {
	WaitForSerial(ctx context.Context, zone string, serial uint32) error
	WaitForAbsence(ctx context.Context, zone string) error
	WaitForReplicaSerial(ctx context.Context, zone string, serial uint32) error
	WaitForReplicaAbsence(ctx context.Context, zone string) error
	Notify(ctx context.Context, zone string) error
}

const replicaVerificationTimeout = 15 * time.Second

type Store struct {
	dir      string
	history  string
	audit    string
	verifier Verifier
	now      func() time.Time
	mu       sync.Mutex
}

type Zone struct {
	Name     string  `json:"name"`
	Role     string  `json:"role"`
	Serial   uint32  `json:"serial"`
	Revision string  `json:"revision"`
	RRsets   []RRset `json:"rrsets,omitempty"`
	rrs      []dns.RR
	content  []byte
}

type LifecycleRequest struct {
	Role             string `json:"role,omitempty"`
	ZoneText         string `json:"zone_text,omitempty"`
	ExpectedRevision string `json:"expected_revision,omitempty"`
	DryRun           bool   `json:"dry_run"`
}

type LifecycleResult struct {
	Action    string `json:"action"`
	Zone      string `json:"zone"`
	Role      string `json:"role"`
	Revision  string `json:"revision,omitempty"`
	Serial    uint32 `json:"serial,omitempty"`
	DryRun    bool   `json:"dry_run"`
	Published bool   `json:"published"`
	RequestID string `json:"request_id"`
	Warning   string `json:"warning,omitempty"`
}

type roleManifest struct {
	Roles map[string]string `json:"roles"`
}

type RRset struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     uint32   `json:"ttl"`
	Records []string `json:"records"`
}

type Change struct {
	Action  string   `json:"action"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     uint32   `json:"ttl,omitempty"`
	Records []string `json:"records,omitempty"`
}

type ChangeRequest struct {
	ExpectedRevision string   `json:"expected_revision"`
	DryRun           bool     `json:"dry_run"`
	Changes          []Change `json:"changes"`
}

type ChangeResult struct {
	Zone             string   `json:"zone"`
	DryRun           bool     `json:"dry_run"`
	PreviousRevision string   `json:"previous_revision"`
	Revision         string   `json:"revision"`
	PreviousSerial   uint32   `json:"previous_serial"`
	Serial           uint32   `json:"serial"`
	Changes          []Change `json:"changes"`
	Published        bool     `json:"published"`
	RequestID        string   `json:"request_id"`
	Warning          string   `json:"warning,omitempty"`
}

type auditEvent struct {
	Timestamp        time.Time `json:"timestamp"`
	Actor            string    `json:"actor"`
	RequestID        string    `json:"request_id"`
	Zone             string    `json:"zone"`
	PreviousRevision string    `json:"previous_revision"`
	Revision         string    `json:"revision"`
	PreviousSerial   uint32    `json:"previous_serial"`
	Serial           uint32    `json:"serial"`
	Changes          []Change  `json:"changes"`
}

func NewStore(dir, auditPath string, verifier Verifier) *Store {
	return &Store{
		dir:      dir,
		history:  filepath.Join(filepath.Dir(dir), "history"),
		audit:    auditPath,
		verifier: verifier,
		now:      time.Now,
	}
}

func (s *Store) List() ([]Zone, error) {
	roles, err := s.loadRoles()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read zone directory: %w", err)
	}
	zones := make([]Zone, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".zone") {
			continue
		}
		zone, err := s.loadPath(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		zone.RRsets = nil
		zone.Role = roleFor(roles, zone.Name)
		zone.rrs = nil
		zone.content = nil
		zones = append(zones, zone)
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	return zones, nil
}

func (s *Store) Get(name string) (Zone, error) {
	path, canonical, err := s.pathFor(name)
	if err != nil {
		return Zone{}, err
	}
	zone, err := s.loadPath(path)
	if errors.Is(err, os.ErrNotExist) {
		return Zone{}, ErrNotFound
	}
	if err != nil {
		return Zone{}, err
	}
	if zone.Name != canonical {
		return Zone{}, fmt.Errorf("%w: file origin %s does not match requested zone %s", ErrInvalidChange, zone.Name, canonical)
	}
	roles, err := s.loadRoles()
	if err != nil {
		return Zone{}, err
	}
	zone.Role = roleFor(roles, zone.Name)
	return zone, nil
}

func (s *Store) Apply(ctx context.Context, name string, request ChangeRequest, actor, requestID string) (ChangeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.Get(name)
	if err != nil {
		return ChangeResult{}, err
	}
	if current.Role != "primary" {
		return ChangeResult{}, ErrReadOnlyZone
	}
	if request.ExpectedRevision == "" || request.ExpectedRevision != current.Revision {
		return ChangeResult{}, ErrRevisionMismatch
	}
	if len(request.Changes) == 0 {
		return ChangeResult{}, fmt.Errorf("%w: at least one change is required", ErrInvalidChange)
	}

	rrs := cloneRRs(current.rrs)
	for i, change := range request.Changes {
		rrs, err = applyChange(rrs, current.Name, change)
		if err != nil {
			return ChangeResult{}, fmt.Errorf("change %d: %w", i, err)
		}
	}
	if err := validate(current.Name, rrs); err != nil {
		return ChangeResult{}, err
	}

	serial, err := nextSerial(current.Serial, s.now().UTC())
	if err != nil {
		return ChangeResult{}, err
	}
	setSOASerial(rrs, serial)
	content := render(current.Name, rrs)
	revision := revision(content)
	result := ChangeResult{
		Zone:             current.Name,
		DryRun:           request.DryRun,
		PreviousRevision: current.Revision,
		Revision:         revision,
		PreviousSerial:   current.Serial,
		Serial:           serial,
		Changes:          request.Changes,
		RequestID:        requestID,
	}
	if request.DryRun {
		return result, nil
	}

	path, _, _ := s.pathFor(current.Name)
	if err := s.saveHistory(current); err != nil {
		return ChangeResult{}, err
	}
	if err := writeAtomic(path, content, 0o640); err != nil {
		return ChangeResult{}, err
	}
	if s.verifier != nil {
		verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		err = s.verifier.WaitForSerial(verifyCtx, current.Name, serial)
		cancel()
		if err != nil {
			rollbackErr := writeAtomic(path, current.content, 0o640)
			if rollbackErr != nil {
				return ChangeResult{}, fmt.Errorf("CoreDNS did not publish serial %d: %v; rollback failed: %w", serial, err, rollbackErr)
			}
			return ChangeResult{}, fmt.Errorf("CoreDNS did not publish serial %d; prior zone restored: %w", serial, err)
		}
	}
	result.Published = true
	if s.verifier != nil {
		if notifyErr := s.verifier.Notify(context.WithoutCancel(ctx), current.Name); notifyErr != nil {
			result.Warning = fmt.Sprintf("secondary NOTIFY failed: %v", notifyErr)
		} else {
			verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), replicaVerificationTimeout)
			replicaErr := s.verifier.WaitForReplicaSerial(verifyCtx, current.Name, serial)
			cancel()
			if replicaErr != nil {
				result.Warning = fmt.Sprintf("secondary publication was not confirmed: %v", replicaErr)
			}
		}
	}
	if err := s.appendAudit(auditEvent{
		Timestamp:        s.now().UTC(),
		Actor:            actor,
		RequestID:        requestID,
		Zone:             current.Name,
		PreviousRevision: current.Revision,
		Revision:         revision,
		PreviousSerial:   current.Serial,
		Serial:           serial,
		Changes:          request.Changes,
	}); err != nil {
		return result, fmt.Errorf("zone published but audit append failed: %w", err)
	}
	return result, nil
}

func (s *Store) Create(ctx context.Context, name string, request LifecycleRequest, actor, requestID string) (LifecycleResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, canonical, err := s.pathFor(name)
	if err != nil {
		return LifecycleResult{}, err
	}
	if _, err := os.Stat(path); err == nil {
		return LifecycleResult{}, ErrAlreadyExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return LifecycleResult{}, err
	}
	role, err := validRole(request.Role)
	if err != nil {
		return LifecycleResult{}, err
	}
	if strings.TrimSpace(request.ZoneText) == "" {
		return LifecycleResult{}, fmt.Errorf("%w: zone_text is required", ErrInvalidChange)
	}
	zone, content, err := parseZoneText(request.ZoneText, canonical, path)
	if err != nil {
		return LifecycleResult{}, err
	}
	result := LifecycleResult{Action: "create", Zone: canonical, Role: role, Revision: revision(content), Serial: zone.Serial, DryRun: request.DryRun, RequestID: requestID}
	if request.DryRun {
		return result, nil
	}
	roles, err := s.loadRoles()
	if err != nil {
		return LifecycleResult{}, err
	}
	if err := writeAtomic(path, content, 0o640); err != nil {
		return LifecycleResult{}, err
	}
	roles[canonical] = role
	if err := s.saveRoles(roles); err != nil {
		_ = os.Remove(path)
		return LifecycleResult{}, err
	}
	if s.verifier != nil {
		verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		err = s.verifier.WaitForSerial(verifyCtx, canonical, zone.Serial)
		cancel()
		if err != nil {
			_ = os.Remove(path)
			delete(roles, canonical)
			_ = s.saveRoles(roles)
			return LifecycleResult{}, fmt.Errorf("CoreDNS did not publish imported zone; files restored: %w", err)
		}
	}
	result.Published = true
	if s.verifier != nil {
		if notifyErr := s.verifier.Notify(context.WithoutCancel(ctx), canonical); notifyErr != nil {
			result.Warning = fmt.Sprintf("secondary NOTIFY failed: %v", notifyErr)
		} else {
			verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), replicaVerificationTimeout)
			replicaErr := s.verifier.WaitForReplicaSerial(verifyCtx, canonical, zone.Serial)
			cancel()
			if replicaErr != nil {
				result.Warning = fmt.Sprintf("secondary publication was not confirmed: %v", replicaErr)
			}
		}
	}
	_ = s.appendAudit(auditEvent{Timestamp: s.now().UTC(), Actor: actor, RequestID: requestID, Zone: canonical, Revision: result.Revision, Serial: result.Serial})
	return result, nil
}

func (s *Store) Delete(ctx context.Context, name string, request LifecycleRequest, actor, requestID string) (LifecycleResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.Get(name)
	if err != nil {
		return LifecycleResult{}, err
	}
	if request.ExpectedRevision == "" || request.ExpectedRevision != current.Revision {
		return LifecycleResult{}, ErrRevisionMismatch
	}
	result := LifecycleResult{Action: "delete", Zone: current.Name, Role: current.Role, Revision: current.Revision, Serial: current.Serial, DryRun: request.DryRun, RequestID: requestID}
	if request.DryRun {
		return result, nil
	}
	if err := s.saveHistory(current); err != nil {
		return LifecycleResult{}, err
	}
	path, _, _ := s.pathFor(current.Name)
	if err := os.Remove(path); err != nil {
		return LifecycleResult{}, err
	}
	roles, err := s.loadRoles()
	if err != nil {
		return LifecycleResult{}, err
	}
	delete(roles, current.Name)
	if err := s.saveRoles(roles); err != nil {
		_ = writeAtomic(path, current.content, 0o640)
		return LifecycleResult{}, err
	}
	if s.verifier != nil {
		verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		err = s.verifier.WaitForAbsence(verifyCtx, current.Name)
		cancel()
		if err != nil {
			_ = writeAtomic(path, current.content, 0o640)
			roles[current.Name] = current.Role
			_ = s.saveRoles(roles)
			return LifecycleResult{}, fmt.Errorf("CoreDNS did not remove zone; files restored: %w", err)
		}
	}
	result.Published = true
	if s.verifier != nil {
		if notifyErr := s.verifier.Notify(context.WithoutCancel(ctx), current.Name); notifyErr != nil {
			result.Warning = fmt.Sprintf("secondary NOTIFY failed: %v", notifyErr)
		} else {
			verifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), replicaVerificationTimeout)
			replicaErr := s.verifier.WaitForReplicaAbsence(verifyCtx, current.Name)
			cancel()
			if replicaErr != nil {
				result.Warning = fmt.Sprintf("secondary removal was not confirmed: %v", replicaErr)
			}
		}
	}
	_ = s.appendAudit(auditEvent{Timestamp: s.now().UTC(), Actor: actor, RequestID: requestID, Zone: current.Name, PreviousRevision: current.Revision, PreviousSerial: current.Serial})
	return result, nil
}

func parseZoneText(input, expected, path string) (Zone, []byte, error) {
	parser := dns.NewZoneParser(strings.NewReader(input), expected, path)
	var records []dns.RR
	for record, ok := parser.Next(); ok; record, ok = parser.Next() {
		records = append(records, record)
	}
	if err := parser.Err(); err != nil {
		return Zone{}, nil, fmt.Errorf("%w: parse zone: %v", ErrInvalidChange, err)
	}
	if err := validate(expected, records); err != nil {
		return Zone{}, nil, err
	}
	var serial uint32
	for _, record := range records {
		if soa, ok := record.(*dns.SOA); ok {
			serial = soa.Serial
		}
	}
	content := render(expected, records)
	return Zone{Name: expected, Serial: serial, Revision: revision(content), rrs: records, content: content}, content, nil
}

func validRole(role string) (string, error) {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		role = "primary"
	}
	if role != "primary" && role != "secondary" {
		return "", fmt.Errorf("%w: role must be primary or secondary", ErrInvalidChange)
	}
	return role, nil
}

func roleFor(roles map[string]string, zone string) string {
	if role := roles[zone]; role != "" {
		return role
	}
	// Existing zone files that have not been explicitly classified must never
	// become writable merely because the role manifest is absent or incomplete.
	return "secondary"
}

func (s *Store) loadRoles() (map[string]string, error) {
	content, err := os.ReadFile(filepath.Join(s.dir, ".roles.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var manifest roleManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return nil, fmt.Errorf("parse zone role manifest: %w", err)
	}
	if manifest.Roles == nil {
		manifest.Roles = map[string]string{}
	}
	return manifest.Roles, nil
}

func (s *Store) saveRoles(roles map[string]string) error {
	content, err := json.MarshalIndent(roleManifest{Roles: roles}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, ".roles.json"), append(content, '\n'), 0o640)
}

func (s *Store) loadPath(path string) (Zone, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Zone{}, err
	}
	parser := dns.NewZoneParser(strings.NewReader(string(content)), "", path)
	rrs := make([]dns.RR, 0)
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		rrs = append(rrs, rr)
	}
	if err := parser.Err(); err != nil {
		return Zone{}, fmt.Errorf("parse %s: %w", path, err)
	}
	var origin string
	var serial uint32
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			if origin != "" {
				return Zone{}, fmt.Errorf("%w: multiple SOA records", ErrInvalidChange)
			}
			origin = canonicalName(soa.Hdr.Name)
			serial = soa.Serial
		}
	}
	if origin == "" {
		return Zone{}, fmt.Errorf("%w: missing SOA", ErrInvalidChange)
	}
	if err := validate(origin, rrs); err != nil {
		return Zone{}, err
	}
	return Zone{
		Name:     origin,
		Serial:   serial,
		Revision: revision(content),
		RRsets:   groupRRsets(rrs),
		rrs:      rrs,
		content:  content,
	}, nil
}

func (s *Store) pathFor(name string) (string, string, error) {
	canonical := canonicalName(name)
	trimmed := strings.TrimSuffix(canonical, ".")
	if trimmed == "" || strings.ContainsAny(trimmed, `/\\`) {
		return "", "", fmt.Errorf("%w: invalid zone name", ErrInvalidChange)
	}
	if _, ok := dns.IsDomainName(canonical); !ok {
		return "", "", fmt.Errorf("%w: invalid zone name", ErrInvalidChange)
	}
	return filepath.Join(s.dir, trimmed+".zone"), canonical, nil
}

func (s *Store) saveHistory(zone Zone) error {
	directory := filepath.Join(s.history, strings.TrimSuffix(zone.Name, "."))
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return fmt.Errorf("create zone history: %w", err)
	}
	path := filepath.Join(directory, zone.Revision+".zone")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomic(path, zone.content, 0o640)
}

func (s *Store) appendAudit(event auditEvent) error {
	if s.audit == "" {
		return nil
	}
	file, err := os.OpenFile(s.audit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	return encoder.Encode(event)
}

func applyChange(rrs []dns.RR, zone string, change Change) ([]dns.RR, error) {
	action := strings.ToLower(change.Action)
	if action != "upsert" && action != "delete" {
		return nil, fmt.Errorf("%w: action must be upsert or delete", ErrInvalidChange)
	}
	typeName := strings.ToUpper(strings.TrimSpace(change.Type))
	typeCode, ok := dns.StringToType[typeName]
	if !ok || typeCode == dns.TypeNone || typeCode == dns.TypeANY || typeCode == dns.TypeAXFR || typeCode == dns.TypeIXFR {
		return nil, fmt.Errorf("%w: unsupported record type %q", ErrInvalidChange, change.Type)
	}
	if typeCode == dns.TypeSOA {
		return nil, fmt.Errorf("%w: SOA is managed automatically", ErrInvalidChange)
	}
	name, err := ownerName(zone, change.Name)
	if err != nil {
		return nil, err
	}

	filtered := rrs[:0]
	for _, rr := range rrs {
		if canonicalName(rr.Header().Name) == name && rr.Header().Rrtype == typeCode {
			continue
		}
		filtered = append(filtered, rr)
	}
	if action == "delete" {
		if len(change.Records) != 0 {
			return nil, fmt.Errorf("%w: delete does not accept records", ErrInvalidChange)
		}
		return filtered, nil
	}
	if len(change.Records) == 0 {
		return nil, fmt.Errorf("%w: upsert requires records", ErrInvalidChange)
	}
	for _, value := range change.Records {
		presentation := fmt.Sprintf("%s %d IN %s %s", name, change.TTL, typeName, strings.TrimSpace(value))
		rr, err := dns.NewRR(presentation)
		if err != nil {
			return nil, fmt.Errorf("%w: parse %s record: %v", ErrInvalidChange, typeName, err)
		}
		filtered = append(filtered, rr)
	}
	return filtered, nil
}

func validate(zone string, rrs []dns.RR) error {
	soaCount := 0
	apexNS := 0
	typesByName := make(map[string]map[uint16]struct{})
	seen := make(map[string]struct{})
	for _, rr := range rrs {
		header := rr.Header()
		name := canonicalName(header.Name)
		if header.Class != dns.ClassINET {
			return fmt.Errorf("%w: only IN class is supported", ErrInvalidChange)
		}
		if !dns.IsSubDomain(zone, name) {
			return fmt.Errorf("%w: owner %s is outside %s", ErrInvalidChange, name, zone)
		}
		key := strings.ToLower(rr.String())
		if _, ok := seen[key]; ok {
			return fmt.Errorf("%w: duplicate record %s", ErrInvalidChange, rr.String())
		}
		seen[key] = struct{}{}
		if _, ok := typesByName[name]; !ok {
			typesByName[name] = make(map[uint16]struct{})
		}
		typesByName[name][header.Rrtype] = struct{}{}
		if header.Rrtype == dns.TypeSOA {
			soaCount++
			if name != zone {
				return fmt.Errorf("%w: SOA must be at zone apex", ErrInvalidChange)
			}
		}
		if header.Rrtype == dns.TypeNS && name == zone {
			apexNS++
		}
	}
	if soaCount != 1 {
		return fmt.Errorf("%w: zone must contain exactly one SOA", ErrInvalidChange)
	}
	if apexNS == 0 {
		return fmt.Errorf("%w: zone must contain an apex NS record", ErrInvalidChange)
	}
	for name, types := range typesByName {
		if _, hasCNAME := types[dns.TypeCNAME]; hasCNAME {
			for recordType := range types {
				if recordType != dns.TypeCNAME && recordType != dns.TypeRRSIG && recordType != dns.TypeNSEC && recordType != dns.TypeNSEC3 {
					return fmt.Errorf("%w: CNAME at %s cannot coexist with other record types", ErrInvalidChange, name)
				}
			}
		}
	}
	return nil
}

func groupRRsets(rrs []dns.RR) []RRset {
	type key struct {
		name     string
		typeCode uint16
	}
	sets := make(map[key]*RRset)
	for _, rr := range rrs {
		header := rr.Header()
		k := key{canonicalName(header.Name), header.Rrtype}
		set, ok := sets[k]
		if !ok {
			set = &RRset{Name: k.name, Type: dns.TypeToString[k.typeCode], TTL: header.Ttl}
			sets[k] = set
		}
		set.Records = append(set.Records, rdata(rr))
	}
	result := make([]RRset, 0, len(sets))
	for _, set := range sets {
		sort.Strings(set.Records)
		result = append(result, *set)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Name == result[j].Name {
			return result[i].Type < result[j].Type
		}
		return result[i].Name < result[j].Name
	})
	return result
}

func render(zone string, rrs []dns.RR) []byte {
	ordered := cloneRRs(rrs)
	sort.SliceStable(ordered, func(i, j int) bool {
		return rrSortKey(zone, ordered[i]) < rrSortKey(zone, ordered[j])
	})
	var builder strings.Builder
	fmt.Fprintf(&builder, "$ORIGIN %s\n$TTL 300\n\n", zone)
	for _, rr := range ordered {
		builder.WriteString(rr.String())
		builder.WriteByte('\n')
	}
	return []byte(builder.String())
}

func rrSortKey(zone string, rr dns.RR) string {
	header := rr.Header()
	priority := "2"
	if header.Rrtype == dns.TypeSOA {
		priority = "0"
	} else if canonicalName(header.Name) == zone && header.Rrtype == dns.TypeNS {
		priority = "1"
	}
	return priority + canonicalName(header.Name) + fmt.Sprintf("%05d", header.Rrtype) + rr.String()
}

func setSOASerial(rrs []dns.RR, serial uint32) {
	for _, rr := range rrs {
		if soa, ok := rr.(*dns.SOA); ok {
			soa.Serial = serial
			return
		}
	}
}

func nextSerial(current uint32, now time.Time) (uint32, error) {
	if current == math.MaxUint32 {
		return 0, fmt.Errorf("%w: SOA serial has reached uint32 maximum", ErrInvalidChange)
	}
	dateSerial, _ := strconv.ParseUint(now.Format("20060102")+"00", 10, 32)
	next := current + 1
	if uint32(dateSerial) > next {
		return uint32(dateSerial), nil
	}
	return next, nil
}

func ownerName(zone, owner string) (string, error) {
	owner = strings.TrimSpace(owner)
	var name string
	if owner == "" || owner == "@" {
		name = zone
	} else if dns.IsFqdn(owner) {
		name = canonicalName(owner)
	} else {
		name = canonicalName(owner + "." + zone)
	}
	if _, ok := dns.IsDomainName(name); !ok || !dns.IsSubDomain(zone, name) {
		return "", fmt.Errorf("%w: owner %q is outside zone %s", ErrInvalidChange, owner, zone)
	}
	return name, nil
}

func canonicalName(name string) string { return strings.ToLower(dns.Fqdn(strings.TrimSpace(name))) }

func cloneRRs(rrs []dns.RR) []dns.RR {
	result := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		result[i] = dns.Copy(rr)
	}
	return result
}

func revision(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func rdata(rr dns.RR) string {
	parts := strings.SplitN(rr.String(), "\t", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	fields := strings.Fields(rr.String())
	if len(fields) <= 4 {
		return ""
	}
	return strings.Join(fields[4:], " ")
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".rilldns-*")
	if err != nil {
		return fmt.Errorf("create temporary zone: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	writer := bufio.NewWriter(temporary)
	if _, err := writer.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish zone: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open zone directory for sync: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync zone directory: %w", err)
	}
	return nil
}
