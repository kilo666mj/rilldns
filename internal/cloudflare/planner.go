package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

var (
	ErrRevisionMismatch = errors.New("revision mismatch for the Cloudflare zone")
	ErrInvalidChange    = errors.New("invalid Cloudflare DNS change")
)

type ProviderOptions struct {
	Proxied *bool     `json:"proxied,omitempty"`
	Comment *string   `json:"comment,omitempty"`
	Tags    *[]string `json:"tags,omitempty"`
}

type Change struct {
	Action   string          `json:"action"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	TTL      uint32          `json:"ttl,omitempty"`
	Records  []string        `json:"records,omitempty"`
	Provider ProviderOptions `json:"provider,omitempty"`
}

type PlanRequest struct {
	ExpectedRevision string   `json:"expected_revision"`
	Changes          []Change `json:"changes"`
}

type DeleteOperation struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

type CreateOperation struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Content  string         `json:"content,omitempty"`
	TTL      uint32         `json:"ttl"`
	Proxied  *bool          `json:"proxied,omitempty"`
	Priority *uint16        `json:"priority,omitempty"`
	Comment  string         `json:"comment,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type PatchOperation struct {
	ID string `json:"id"`
	CreateOperation
}

type Plan struct {
	Zone             string            `json:"zone"`
	DryRun           bool              `json:"dry_run"`
	PreviousRevision string            `json:"previous_revision"`
	Changes          []Change          `json:"changes"`
	Deletes          []DeleteOperation `json:"deletes"`
	Patches          []PatchOperation  `json:"patches"`
	Creates          []CreateOperation `json:"creates"`
	Expected         []CreateOperation `json:"expected"`
}

func (c *Client) PlanChanges(ctx context.Context, zone string, request PlanRequest) (Plan, error) {
	current, err := c.ListRecords(ctx, zone)
	if err != nil {
		return Plan{}, err
	}
	return planChanges(current, request)
}

func planChanges(current ZoneRecords, request PlanRequest) (Plan, error) {
	if strings.TrimSpace(request.ExpectedRevision) == "" || request.ExpectedRevision != current.Revision {
		return Plan{}, ErrRevisionMismatch
	}
	if len(request.Changes) == 0 {
		return Plan{}, fmt.Errorf("%w: at least one change is required", ErrInvalidChange)
	}
	if len(request.Changes) > 100 {
		return Plan{}, fmt.Errorf("%w: a batch is limited to 100 RRset changes", ErrInvalidChange)
	}

	type key struct{ name, recordType string }
	existing := make(map[key][]Record)
	finalTypes := make(map[string]map[string]bool)
	initialTypes := make(map[string]map[string]bool)
	for _, record := range current.Records {
		k := key{record.Name, record.Type}
		existing[k] = append(existing[k], record)
		if finalTypes[record.Name] == nil {
			finalTypes[record.Name] = make(map[string]bool)
		}
		finalTypes[record.Name][record.Type] = true
		if initialTypes[record.Name] == nil {
			initialTypes[record.Name] = make(map[string]bool)
		}
		initialTypes[record.Name][record.Type] = true
	}

	plan := Plan{Zone: current.Zone, DryRun: true, PreviousRevision: current.Revision, Changes: request.Changes}
	seen := make(map[key]bool)
	for i, change := range request.Changes {
		owner, err := changeOwner(current.Zone, change.Name)
		if err != nil {
			return Plan{}, fmt.Errorf("change %d: %w", i, err)
		}
		recordType := strings.ToUpper(strings.TrimSpace(change.Type))
		if _, ok := supportedTypes[recordType]; !ok {
			return Plan{}, fmt.Errorf("change %d: %w: unsupported record type %q", i, ErrInvalidChange, change.Type)
		}
		k := key{owner, recordType}
		if seen[k] {
			return Plan{}, fmt.Errorf("change %d: %w: RRset %s %s appears more than once", i, ErrInvalidChange, owner, recordType)
		}
		seen[k] = true

		switch strings.ToLower(strings.TrimSpace(change.Action)) {
		case "delete":
			if len(change.Records) != 0 || change.TTL != 0 {
				return Plan{}, fmt.Errorf("change %d: %w: delete must not include ttl or records", i, ErrInvalidChange)
			}
			if len(existing[k]) == 0 {
				return Plan{}, fmt.Errorf("change %d: %w: RRset %s %s does not exist", i, ErrInvalidChange, owner, recordType)
			}
			for _, record := range existing[k] {
				plan.Deletes = append(plan.Deletes, deleteOperation(record))
			}
			delete(finalTypes[owner], recordType)
		case "upsert":
			if err := validateTTL(change.TTL); err != nil {
				return Plan{}, fmt.Errorf("change %d: %w", i, err)
			}
			if len(change.Records) == 0 {
				return Plan{}, fmt.Errorf("change %d: %w: upsert requires at least one record", i, ErrInvalidChange)
			}
			provider := inheritedProvider(existing[k], change.Provider)
			values := make(map[string]bool)
			var desired []CreateOperation
			for _, value := range change.Records {
				operation, normalized, err := createOperation(owner, recordType, change.TTL, value, provider)
				if err != nil {
					return Plan{}, fmt.Errorf("change %d: %w", i, err)
				}
				if values[normalized] {
					return Plan{}, fmt.Errorf("change %d: %w: duplicate record %q", i, ErrInvalidChange, value)
				}
				values[normalized] = true
				desired = append(desired, operation)
			}
			deletes, patches, creates, err := reconcileRRset(existing[k], desired)
			if err != nil {
				return Plan{}, fmt.Errorf("change %d: %w", i, err)
			}
			plan.Deletes = append(plan.Deletes, deletes...)
			plan.Patches = append(plan.Patches, patches...)
			plan.Creates = append(plan.Creates, creates...)
			plan.Expected = append(plan.Expected, desired...)
			if finalTypes[owner] == nil {
				finalTypes[owner] = make(map[string]bool)
			}
			finalTypes[owner][recordType] = true
		default:
			return Plan{}, fmt.Errorf("change %d: %w: action must be upsert or delete", i, ErrInvalidChange)
		}
	}
	for owner, types := range finalTypes {
		if types["CNAME"] && len(types) > 1 && !sameTypeSet(types, initialTypes[owner]) {
			return Plan{}, fmt.Errorf("%w: CNAME at %s cannot coexist with other record types", ErrInvalidChange, owner)
		}
	}
	sort.Slice(plan.Deletes, func(i, j int) bool { return plan.Deletes[i].ID < plan.Deletes[j].ID })
	sort.Slice(plan.Patches, func(i, j int) bool { return plan.Patches[i].ID < plan.Patches[j].ID })
	sort.Slice(plan.Creates, func(i, j int) bool {
		a, b := plan.Creates[i], plan.Creates[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Content < b.Content
	})
	return plan, nil
}

func deleteOperation(record Record) DeleteOperation {
	return DeleteOperation{ID: record.ID, Name: record.Name, Type: record.Type, Content: record.Content}
}

func reconcileRRset(existing []Record, desired []CreateOperation) ([]DeleteOperation, []PatchOperation, []CreateOperation, error) {
	remaining := append([]Record(nil), existing...)
	var patches []PatchOperation
	var creates []CreateOperation
	for _, wanted := range desired {
		match := -1
		for i, record := range remaining {
			if sameRecordValue(record, wanted) {
				match = i
				break
			}
		}
		if match < 0 {
			creates = append(creates, wanted)
			continue
		}
		record := remaining[match]
		remaining = append(remaining[:match], remaining[match+1:]...)
		if strings.TrimSpace(record.ID) == "" {
			return nil, nil, nil, fmt.Errorf("%w: existing record has no Cloudflare ID", ErrInvalidChange)
		}
		if record.TTL != wanted.TTL || !equalBool(record.Proxied, wanted.Proxied) || record.Comment != wanted.Comment || !reflect.DeepEqual(record.Tags, wanted.Tags) {
			patches = append(patches, PatchOperation{ID: record.ID, CreateOperation: wanted})
		}
	}
	deletes := make([]DeleteOperation, 0, len(remaining))
	for _, record := range remaining {
		if strings.TrimSpace(record.ID) == "" {
			return nil, nil, nil, fmt.Errorf("%w: existing record has no Cloudflare ID", ErrInvalidChange)
		}
		deletes = append(deletes, deleteOperation(record))
	}
	return deletes, patches, creates, nil
}

func sameRecordValue(record Record, wanted CreateOperation) bool {
	if record.Name != wanted.Name || record.Type != wanted.Type {
		return false
	}
	if record.Type == "MX" {
		return record.Content == wanted.Content && equalUint16(record.Priority, wanted.Priority)
	}
	return strings.TrimSpace(record.Content) == strings.TrimSpace(wanted.Content)
}

func equalBool(left, right *bool) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}
func equalUint16(left, right *uint16) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func sameTypeSet(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if !right[value] {
			return false
		}
	}
	return true
}

var supportedTypes = map[string]bool{"A": true, "AAAA": true, "CAA": true, "CNAME": true, "MX": true, "NS": true, "SRV": true, "TXT": true}

func changeOwner(zone, name string) (string, error) {
	name = canonicalName(name)
	if name == "@" {
		return zone, nil
	}
	if name == "" {
		return "", fmt.Errorf("%w: record name is required", ErrInvalidChange)
	}
	if !inZone(name, zone) {
		name += "." + zone
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(name)); !ok || !inZone(name, zone) {
		return "", fmt.Errorf("%w: invalid or out-of-zone record name %q", ErrInvalidChange, name)
	}
	return name, nil
}

func validateTTL(ttl uint32) error {
	if ttl != 1 && (ttl < 60 || ttl > 86400) {
		return fmt.Errorf("%w: TTL must be automatic (1) or between 60 and 86400", ErrInvalidChange)
	}
	return nil
}

func inheritedProvider(records []Record, requested ProviderOptions) ProviderOptions {
	result := requested
	if len(records) == 0 {
		return result
	}
	if result.Proxied == nil {
		value := records[0].Proxied
		uniform := value != nil
		for _, record := range records[1:] {
			if record.Proxied == nil || value == nil || *record.Proxied != *value {
				uniform = false
			}
		}
		if uniform {
			copy := *value
			result.Proxied = &copy
		}
	}
	if result.Comment == nil {
		value, uniform := records[0].Comment, true
		for _, record := range records[1:] {
			if record.Comment != value {
				uniform = false
			}
		}
		if uniform {
			result.Comment = &value
		}
	}
	if result.Tags == nil {
		value, uniform := append([]string(nil), records[0].Tags...), true
		for _, record := range records[1:] {
			if strings.Join(record.Tags, "\x00") != strings.Join(value, "\x00") {
				uniform = false
			}
		}
		if uniform {
			result.Tags = &value
		}
	}
	return result
}

func createOperation(owner, recordType string, ttl uint32, value string, provider ProviderOptions) (CreateOperation, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return CreateOperation{}, "", fmt.Errorf("%w: record value is empty", ErrInvalidChange)
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", dns.Fqdn(owner), ttl, recordType, value))
	if err != nil {
		return CreateOperation{}, "", fmt.Errorf("%w: invalid %s record %q: %v", ErrInvalidChange, recordType, value, err)
	}
	op := CreateOperation{Name: owner, Type: recordType, TTL: ttl, Proxied: provider.Proxied}
	if provider.Comment != nil {
		op.Comment = *provider.Comment
	}
	if provider.Tags != nil {
		op.Tags = append([]string(nil), (*provider.Tags)...)
		sort.Strings(op.Tags)
	}
	switch typed := rr.(type) {
	case *dns.A:
		op.Content = typed.A.String()
	case *dns.AAAA:
		op.Content = typed.AAAA.String()
	case *dns.CNAME:
		op.Content = canonicalName(typed.Target)
	case *dns.NS:
		op.Content = canonicalName(typed.Ns)
	case *dns.MX:
		op.Content = canonicalName(typed.Mx)
		priority := typed.Preference
		op.Priority = &priority
	case *dns.TXT:
		if len(typed.Txt) != 1 {
			return CreateOperation{}, "", fmt.Errorf("%w: split TXT strings are not supported", ErrInvalidChange)
		}
		op.Content = typed.Txt[0]
	case *dns.CAA:
		op.Content = fmt.Sprintf("%d %s %s", typed.Flag, typed.Tag, typed.Value)
		op.Data = map[string]any{"flags": typed.Flag, "tag": typed.Tag, "value": typed.Value}
	case *dns.SRV:
		op.Content = fmt.Sprintf("%d %d %d %s", typed.Priority, typed.Weight, typed.Port, canonicalName(typed.Target))
		op.Data = map[string]any{"priority": typed.Priority, "weight": typed.Weight, "port": typed.Port, "target": canonicalName(typed.Target)}
	default:
		return CreateOperation{}, "", fmt.Errorf("%w: unsupported parsed record type %s", ErrInvalidChange, recordType)
	}
	encoded, _ := json.Marshal(op)
	return op, string(encoded), nil
}
