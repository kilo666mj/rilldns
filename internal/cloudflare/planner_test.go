package cloudflare

import (
	"errors"
	"testing"
)

func boolPointer(value bool) *bool { return &value }

func TestPlanChangesReplacesCompleteRRsetAndPreservesProviderOptions(t *testing.T) {
	current := ZoneRecords{Zone: "example.com", Revision: "current", Records: []Record{
		{ID: "b", Name: "www.example.com", Type: "A", Content: "192.0.2.2", TTL: 300, Proxied: boolPointer(true), Comment: "web", Tags: []string{"prod"}},
		{ID: "a", Name: "www.example.com", Type: "A", Content: "192.0.2.1", TTL: 300, Proxied: boolPointer(true), Comment: "web", Tags: []string{"prod"}},
	}}
	plan, err := planChanges(current, PlanRequest{ExpectedRevision: "current", Changes: []Change{{Action: "upsert", Name: "www", Type: "a", TTL: 600, Records: []string{"192.0.2.10"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DryRun || len(plan.Deletes) != 2 || plan.Deletes[0].ID != "a" || len(plan.Creates) != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	create := plan.Creates[0]
	if create.Name != "www.example.com" || create.Type != "A" || create.Content != "192.0.2.10" || create.Proxied == nil || !*create.Proxied || create.Comment != "web" || len(create.Tags) != 1 {
		t.Fatalf("unexpected create: %+v", create)
	}
}

func TestPlanChangesParsesStructuredRecords(t *testing.T) {
	current := ZoneRecords{Zone: "example.com", Revision: "current"}
	plan, err := planChanges(current, PlanRequest{ExpectedRevision: "current", Changes: []Change{
		{Action: "upsert", Name: "@", Type: "MX", TTL: 300, Records: []string{"10 mail.example.com."}},
		{Action: "upsert", Name: "_sip._tcp", Type: "SRV", TTL: 300, Records: []string{"10 20 5060 sip.example.com."}},
		{Action: "upsert", Name: "@", Type: "CAA", TTL: 300, Records: []string{`0 issue "letsencrypt.org"`}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Creates) != 3 {
		t.Fatalf("creates = %+v", plan.Creates)
	}
	var sawMX, sawSRV, sawCAA bool
	for _, create := range plan.Creates {
		switch create.Type {
		case "MX":
			sawMX = create.Priority != nil && *create.Priority == 10 && create.Content == "mail.example.com"
		case "SRV":
			sawSRV = create.Data["port"] == uint16(5060)
		case "CAA":
			sawCAA = create.Data["tag"] == "issue"
		}
	}
	if !sawMX || !sawSRV || !sawCAA {
		t.Fatalf("structured creates = %+v", plan.Creates)
	}
}

func TestPlanChangesRejectsStaleInvalidAndConflictingChanges(t *testing.T) {
	current := ZoneRecords{Zone: "example.com", Revision: "current", Records: []Record{{ID: "a", Name: "www.example.com", Type: "A", Content: "192.0.2.1", TTL: 300}}}
	_, err := planChanges(current, PlanRequest{ExpectedRevision: "stale", Changes: []Change{{Action: "delete", Name: "www", Type: "A"}}})
	if !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("stale error = %v", err)
	}
	_, err = planChanges(current, PlanRequest{ExpectedRevision: "current", Changes: []Change{{Action: "upsert", Name: "www", Type: "CNAME", TTL: 300, Records: []string{"target.example.com."}}}})
	if !errors.Is(err, ErrInvalidChange) {
		t.Fatalf("CNAME error = %v", err)
	}
	_, err = planChanges(current, PlanRequest{ExpectedRevision: "current", Changes: []Change{{Action: "upsert", Name: "www", Type: "A", TTL: 30, Records: []string{"192.0.2.1"}}}})
	if !errors.Is(err, ErrInvalidChange) {
		t.Fatalf("TTL error = %v", err)
	}
}

func TestPlanChangesToleratesUnchangedExistingCloudflareCNAMEConflict(t *testing.T) {
	current := ZoneRecords{Zone: "example.com", Revision: "current", Records: []Record{
		{ID: "cname", Name: "example.com", Type: "CNAME", Content: "target.example.net", TTL: 1},
		{ID: "txt", Name: "example.com", Type: "TXT", Content: "verification", TTL: 300},
	}}
	plan, err := planChanges(current, PlanRequest{ExpectedRevision: "current", Changes: []Change{{Action: "upsert", Name: "www", Type: "A", TTL: 300, Records: []string{"192.0.2.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Creates) != 1 || plan.Creates[0].Name != "www.example.com" {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestPlanChangesUsesMinimalOperations(t *testing.T) {
	current := ZoneRecords{Zone: "example.com", Revision: "current", Records: []Record{{ID: "keep", Name: "www.example.com", Type: "A", Content: "192.0.2.1", TTL: 300}, {ID: "remove", Name: "www.example.com", Type: "A", Content: "192.0.2.2", TTL: 300}}}
	plan, err := planChanges(current, PlanRequest{ExpectedRevision: "current", Changes: []Change{{Action: "upsert", Name: "www", Type: "A", TTL: 600, Records: []string{"192.0.2.1", "192.0.2.3"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Deletes) != 1 || plan.Deletes[0].ID != "remove" || len(plan.Patches) != 1 || plan.Patches[0].ID != "keep" || len(plan.Creates) != 1 || plan.Creates[0].Content != "192.0.2.3" {
		t.Fatalf("non-minimal plan: %+v", plan)
	}
}
