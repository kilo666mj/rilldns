package mcpserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kilo666mj/mcpkit"
	"github.com/kilo666mj/rilldns/internal/blocking"
	"github.com/kilo666mj/rilldns/internal/cloudflare"
	"github.com/kilo666mj/rilldns/internal/controlclient"
	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"github.com/kilo666mj/rilldns/internal/zones"
	"github.com/miekg/dns"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Hosted exposes the same API-backed tool catalogue over authenticated,
// stateless Streamable HTTP. The API remains authoritative for validation,
// revisions, auditing, verification, and rollback.
func Hosted(api *controlclient.Client, dnsAddress, token string) (http.Handler, error) {
	handler, err := mcpkit.StatelessHTTP(func(*http.Request) *mcp.Server {
		return New(api, dnsAddress)
	}, mcpkit.HTTPOptions{DisableLocalhostProtection: true})
	if err != nil {
		return nil, err
	}
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := []byte(r.Header.Get("Authorization"))
		if len(expected) == len("Bearer ") || len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}), nil
}

type Server struct {
	api        *controlclient.Client
	dnsAddress string
}

type EmptyInput struct{}

type BlocklistConfigOutput struct {
	Config blocking.Config `json:"config"`
}

type BlocklistUpdateInput struct {
	Sources          []string `json:"sources" jsonschema:"Complete desired list of HTTPS blocklist source URLs"`
	Allow            []string `json:"allow" jsonschema:"Complete desired list of explicitly allowed domains"`
	Deny             []string `json:"deny" jsonschema:"Complete desired list of explicitly blocked domains"`
	ExpectedRevision string   `json:"expected_revision" jsonschema:"Exact revision returned by dns_get_blocklist_config"`
	Confirm          bool     `json:"confirm" jsonschema:"Must be true to publish; false validates a dry run"`
}

type BlocklistUpdateOutput struct {
	Result blocking.UpdateResult `json:"result"`
}

type ListZonesOutput struct {
	Zones []zones.Zone `json:"zones"`
}

type ListCloudflareZonesOutput struct {
	Zones []controlclient.CloudflareZone `json:"zones"`
}
type CloudflareRecordsOutput struct {
	Zone cloudflare.ZoneRecords `json:"zone"`
}
type CloudflarePlanInput struct {
	Zone             string              `json:"zone" jsonschema:"Configured Cloudflare DNS zone to change"`
	ExpectedRevision string              `json:"expected_revision" jsonschema:"Exact revision returned by dns_cloudflare_list_records"`
	Changes          []cloudflare.Change `json:"changes" jsonschema:"Complete Cloudflare RRset upsert/delete operations"`
}
type CloudflarePlanOutput struct {
	Plan cloudflare.Plan `json:"plan"`
}
type CloudflareApplyInput struct {
	Zone             string              `json:"zone" jsonschema:"Configured Cloudflare DNS zone to change"`
	ExpectedRevision string              `json:"expected_revision" jsonschema:"Exact revision returned by dns_cloudflare_list_records or dns_cloudflare_plan_changes"`
	Changes          []cloudflare.Change `json:"changes" jsonschema:"Complete Cloudflare RRset upsert/delete operations"`
	Confirm          bool                `json:"confirm" jsonschema:"Must be true to write to Cloudflare"`
}
type CloudflareApplyOutput struct {
	Result cloudflare.ApplyResult `json:"result"`
}

type RefreshStatusOutput struct {
	Status refreshstatus.Report `json:"status"`
}

type ZoneInput struct {
	Zone string `json:"zone" jsonschema:"Canonical DNS zone name, for example example.test"`
}

type ZoneOutput struct {
	Zone zones.Zone `json:"zone"`
}

type ChangeInput struct {
	Zone             string         `json:"zone" jsonschema:"Existing primary DNS zone to change"`
	ExpectedRevision string         `json:"expected_revision" jsonschema:"Exact revision returned by dns_list_records; prevents stale writes"`
	Changes          []zones.Change `json:"changes" jsonschema:"Atomic RRset upsert/delete operations"`
}

type ApplyInput struct {
	Zone             string         `json:"zone" jsonschema:"Existing primary DNS zone to change"`
	ExpectedRevision string         `json:"expected_revision" jsonschema:"Exact revision returned by dns_list_records or dns_plan_changes"`
	Changes          []zones.Change `json:"changes" jsonschema:"Atomic RRset upsert/delete operations"`
	Confirm          bool           `json:"confirm" jsonschema:"Must be true to commit the mutation"`
}

type ChangeOutput struct {
	Result zones.ChangeResult `json:"result"`
}

type CreateZoneInput struct {
	Zone     string `json:"zone" jsonschema:"Canonical DNS zone name"`
	Role     string `json:"role" jsonschema:"Zone role: primary or secondary"`
	ZoneText string `json:"zone_text" jsonschema:"Complete RFC 1035 zone text containing one apex SOA and at least one apex NS"`
	Confirm  bool   `json:"confirm" jsonschema:"Must be true to publish; false performs a dry-run validation"`
}

type DeleteZoneInput struct {
	Zone             string `json:"zone" jsonschema:"Existing managed zone name"`
	ExpectedRevision string `json:"expected_revision" jsonschema:"Exact current zone revision"`
	Confirm          bool   `json:"confirm" jsonschema:"Must be true to delete; false performs a dry-run validation"`
}

type LifecycleOutput struct {
	Result zones.LifecycleResult `json:"result"`
}

type ResolveInput struct {
	Name string `json:"name" jsonschema:"DNS name to query"`
	Type string `json:"type,omitempty" jsonschema:"DNS record type such as A, AAAA, MX, TXT, SOA; defaults to A"`
}

type ResolveOutput struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Server  string   `json:"server"`
	Rcode   string   `json:"rcode"`
	Answers []string `json:"answers"`
}

func New(api *controlclient.Client, dnsAddress string) *mcp.Server {
	service := &Server{api: api, dnsAddress: dnsAddress}
	server := mcp.NewServer(&mcp.Implementation{Name: "rilldns", Version: "0.1.0"}, nil)

	readOnly := true
	closedWorld := false
	destructive := true
	mcp.AddTool(server, &mcp.Tool{
		Name: "dns_get_blocklist_config", Title: "Get DNS blocklist configuration",
		Description: "Read blocklist sources and explicit allow/deny domains with their optimistic-concurrency revision.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.getBlocklistConfig)
	mcp.AddTool(server, &mcp.Tool{
		Name: "dns_update_blocklist_config", Title: "Update DNS blocklist configuration",
		Description: "Replace blocklist sources and allow/deny domains. Requires the current revision; confirm=false validates a dry run.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, service.updateBlocklistConfig)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_create_zone",
		Title:       "Create or import DNS zone",
		Description: "Validate and optionally publish a complete RFC 1035 zone as an explicitly primary or read-only secondary zone. confirm=false is a dry run.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, service.createZone)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_delete_zone",
		Title:       "Delete DNS zone",
		Description: "Validate and optionally delete a managed zone. Requires its exact revision; confirm=false is a dry run and confirm=true commits.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, service.deleteZone)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_list_zones",
		Title:       "List DNS zones",
		Description: "List zones managed by this RillDNS instance, including current SOA serial and revision.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.listZones)
	mcp.AddTool(server, &mcp.Tool{
		Name: "dns_cloudflare_list_zones", Title: "List configured Cloudflare DNS zones",
		Description: "List the external Cloudflare zones explicitly allowed in this RillDNS instance.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.listCloudflareZones)
	mcp.AddTool(server, &mcp.Tool{
		Name: "dns_cloudflare_list_records", Title: "List Cloudflare DNS records",
		Description: "Read and normalize all records in one configured Cloudflare zone, including a synthetic optimistic-concurrency revision.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.listCloudflareRecords)
	mcp.AddTool(server, &mcp.Tool{
		Name: "dns_cloudflare_plan_changes", Title: "Preview Cloudflare DNS changes",
		Description: "Validate Cloudflare RRset changes against the current revision and show the exact proposed deletes and creates without writing to Cloudflare.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.planCloudflareChanges)
	mcp.AddTool(server, &mcp.Tool{
		Name: "dns_cloudflare_apply_changes", Title: "Apply Cloudflare DNS changes",
		Description: "Apply a reviewed Cloudflare RRset batch with the exact current revision and confirm=true; verifies, audits, and rolls back on failure.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, service.applyCloudflareChanges)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_refresh_status",
		Title:       "Show DNS refresh health",
		Description: "Show zone-transfer, DNSSEC-signature, and blocklist refresh health, timestamps, counts, and errors.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.refreshStatus)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_list_records",
		Title:       "List zone records",
		Description: "Read all RRsets in one managed zone. Use the returned revision for planning or committing changes.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.listRecords)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_plan_changes",
		Title:       "Preview DNS changes",
		Description: "Validate an atomic RRset change batch and show the proposed revision and SOA serial without modifying DNS.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly, OpenWorldHint: &closedWorld},
	}, service.planChanges)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_apply_changes",
		Title:       "Apply DNS changes",
		Description: "Commit a previously reviewed atomic RRset change batch. Requires the current revision and confirm=true. RillDNS validates, publishes, verifies, audits, and rolls back on failure.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive, IdempotentHint: false, OpenWorldHint: &closedWorld},
	}, service.applyChanges)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "dns_test_resolution",
		Title:       "Test DNS resolution",
		Description: "Send a read-only DNS query to the local RillDNS listener and return its response code and answers.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: &closedWorld},
	}, service.testResolution)
	return server
}

func (s *Server) getBlocklistConfig(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, BlocklistConfigOutput, error) {
	config, err := s.api.GetBlocklistConfig(ctx)
	return nil, BlocklistConfigOutput{Config: config}, err
}

func (s *Server) updateBlocklistConfig(ctx context.Context, _ *mcp.CallToolRequest, input BlocklistUpdateInput) (*mcp.CallToolResult, BlocklistUpdateOutput, error) {
	if strings.TrimSpace(input.ExpectedRevision) == "" {
		return nil, BlocklistUpdateOutput{}, errors.New("expected_revision is required")
	}
	result, err := s.api.UpdateBlocklistConfig(ctx, blocking.UpdateRequest{
		Sources: input.Sources, Allow: input.Allow, Deny: input.Deny,
		ExpectedRevision: input.ExpectedRevision, DryRun: !input.Confirm,
	}, "mcp:blocklist-config")
	return nil, BlocklistUpdateOutput{Result: result}, err
}

func (s *Server) createZone(ctx context.Context, _ *mcp.CallToolRequest, input CreateZoneInput) (*mcp.CallToolResult, LifecycleOutput, error) {
	if strings.TrimSpace(input.Zone) == "" || strings.TrimSpace(input.ZoneText) == "" {
		return nil, LifecycleOutput{}, errors.New("zone and zone_text are required")
	}
	result, err := s.api.CreateZone(ctx, input.Zone, zones.LifecycleRequest{Role: input.Role, ZoneText: input.ZoneText, DryRun: !input.Confirm}, "mcp:create-zone")
	return nil, LifecycleOutput{Result: result}, err
}

func (s *Server) deleteZone(ctx context.Context, _ *mcp.CallToolRequest, input DeleteZoneInput) (*mcp.CallToolResult, LifecycleOutput, error) {
	if strings.TrimSpace(input.Zone) == "" || strings.TrimSpace(input.ExpectedRevision) == "" {
		return nil, LifecycleOutput{}, errors.New("zone and expected_revision are required")
	}
	result, err := s.api.DeleteZone(ctx, input.Zone, zones.LifecycleRequest{ExpectedRevision: input.ExpectedRevision, DryRun: !input.Confirm}, "mcp:delete-zone")
	return nil, LifecycleOutput{Result: result}, err
}

func (s *Server) refreshStatus(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, RefreshStatusOutput, error) {
	result, err := s.api.RefreshStatus(ctx)
	return nil, RefreshStatusOutput{Status: result}, err
}

func (s *Server) listZones(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, ListZonesOutput, error) {
	result, err := s.api.ListZones(ctx)
	return nil, ListZonesOutput{Zones: result}, err
}

func (s *Server) listCloudflareZones(ctx context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, ListCloudflareZonesOutput, error) {
	result, err := s.api.ListCloudflareZones(ctx)
	return nil, ListCloudflareZonesOutput{Zones: result}, err
}

func (s *Server) listCloudflareRecords(ctx context.Context, _ *mcp.CallToolRequest, input ZoneInput) (*mcp.CallToolResult, CloudflareRecordsOutput, error) {
	if strings.TrimSpace(input.Zone) == "" {
		return nil, CloudflareRecordsOutput{}, errors.New("zone is required")
	}
	result, err := s.api.GetCloudflareRecords(ctx, input.Zone)
	return nil, CloudflareRecordsOutput{Zone: result}, err
}

func (s *Server) planCloudflareChanges(ctx context.Context, _ *mcp.CallToolRequest, input CloudflarePlanInput) (*mcp.CallToolResult, CloudflarePlanOutput, error) {
	if strings.TrimSpace(input.Zone) == "" {
		return nil, CloudflarePlanOutput{}, errors.New("zone is required")
	}
	if strings.TrimSpace(input.ExpectedRevision) == "" {
		return nil, CloudflarePlanOutput{}, errors.New("expected_revision is required")
	}
	if len(input.Changes) == 0 {
		return nil, CloudflarePlanOutput{}, errors.New("at least one change is required")
	}
	if len(input.Changes) > 100 {
		return nil, CloudflarePlanOutput{}, errors.New("a single MCP call is limited to 100 RRset changes")
	}
	result, err := s.api.PlanCloudflareChanges(ctx, input.Zone, cloudflare.PlanRequest{ExpectedRevision: input.ExpectedRevision, Changes: input.Changes})
	return nil, CloudflarePlanOutput{Plan: result}, err
}

func (s *Server) applyCloudflareChanges(ctx context.Context, _ *mcp.CallToolRequest, input CloudflareApplyInput) (*mcp.CallToolResult, CloudflareApplyOutput, error) {
	if !input.Confirm {
		return nil, CloudflareApplyOutput{}, errors.New("confirm must be true to commit Cloudflare DNS changes; use dns_cloudflare_plan_changes first")
	}
	if strings.TrimSpace(input.Zone) == "" || strings.TrimSpace(input.ExpectedRevision) == "" {
		return nil, CloudflareApplyOutput{}, errors.New("zone and expected_revision are required")
	}
	if len(input.Changes) == 0 || len(input.Changes) > 100 {
		return nil, CloudflareApplyOutput{}, errors.New("between 1 and 100 RRset changes are required")
	}
	result, err := s.api.ApplyCloudflareChanges(ctx, input.Zone, cloudflare.ApplyRequest{ExpectedRevision: input.ExpectedRevision, Changes: input.Changes, Confirm: true}, "mcp:cloudflare-apply")
	return nil, CloudflareApplyOutput{Result: result}, err
}

func (s *Server) listRecords(ctx context.Context, _ *mcp.CallToolRequest, input ZoneInput) (*mcp.CallToolResult, ZoneOutput, error) {
	if strings.TrimSpace(input.Zone) == "" {
		return nil, ZoneOutput{}, errors.New("zone is required")
	}
	result, err := s.api.GetZone(ctx, input.Zone)
	return nil, ZoneOutput{Zone: result}, err
}

func (s *Server) planChanges(ctx context.Context, _ *mcp.CallToolRequest, input ChangeInput) (*mcp.CallToolResult, ChangeOutput, error) {
	if err := validateChangeInput(input.Zone, input.ExpectedRevision, input.Changes); err != nil {
		return nil, ChangeOutput{}, err
	}
	result, err := s.api.Apply(ctx, input.Zone, zones.ChangeRequest{
		ExpectedRevision: input.ExpectedRevision,
		DryRun:           true,
		Changes:          input.Changes,
	}, "mcp:plan")
	return nil, ChangeOutput{Result: result}, err
}

func (s *Server) applyChanges(ctx context.Context, _ *mcp.CallToolRequest, input ApplyInput) (*mcp.CallToolResult, ChangeOutput, error) {
	if !input.Confirm {
		return nil, ChangeOutput{}, errors.New("confirm must be true to commit DNS changes; use dns_plan_changes first")
	}
	if err := validateChangeInput(input.Zone, input.ExpectedRevision, input.Changes); err != nil {
		return nil, ChangeOutput{}, err
	}
	result, err := s.api.Apply(ctx, input.Zone, zones.ChangeRequest{
		ExpectedRevision: input.ExpectedRevision,
		Changes:          input.Changes,
	}, "mcp:apply")
	return nil, ChangeOutput{Result: result}, err
}

func (s *Server) testResolution(ctx context.Context, _ *mcp.CallToolRequest, input ResolveInput) (*mcp.CallToolResult, ResolveOutput, error) {
	name := dns.Fqdn(strings.TrimSpace(input.Name))
	if _, ok := dns.IsDomainName(name); !ok {
		return nil, ResolveOutput{}, fmt.Errorf("invalid DNS name %q", input.Name)
	}
	typeName := strings.ToUpper(strings.TrimSpace(input.Type))
	if typeName == "" {
		typeName = "A"
	}
	typeCode, ok := dns.StringToType[typeName]
	if !ok || typeCode == dns.TypeAXFR || typeCode == dns.TypeIXFR || typeCode == dns.TypeANY {
		return nil, ResolveOutput{}, fmt.Errorf("unsupported query type %q", typeName)
	}
	message := new(dns.Msg)
	message.SetQuestion(name, typeCode)
	client := &dns.Client{Timeout: 3 * time.Second}
	response, _, err := client.ExchangeContext(ctx, message, s.dnsAddress)
	if err != nil {
		return nil, ResolveOutput{}, err
	}
	answers := make([]string, len(response.Answer))
	for i, answer := range response.Answer {
		answers[i] = answer.String()
	}
	return nil, ResolveOutput{
		Name: name, Type: typeName, Server: s.dnsAddress,
		Rcode: dns.RcodeToString[response.Rcode], Answers: answers,
	}, nil
}

func validateChangeInput(zone, revision string, changes []zones.Change) error {
	if strings.TrimSpace(zone) == "" {
		return errors.New("zone is required")
	}
	if strings.TrimSpace(revision) == "" {
		return errors.New("expected_revision is required")
	}
	if len(changes) == 0 {
		return errors.New("at least one change is required")
	}
	if len(changes) > 100 {
		return errors.New("a single MCP call is limited to 100 RRset changes")
	}
	return nil
}
