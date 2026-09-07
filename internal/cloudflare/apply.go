package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ErrConfirmationRequired = errors.New("confirmation is required for this Cloudflare change")

type ApplyRequest struct {
	ExpectedRevision string   `json:"expected_revision"`
	Changes          []Change `json:"changes"`
	Confirm          bool     `json:"confirm"`
	Actor            string   `json:"-"`
	RequestID        string   `json:"-"`
}

type ApplyResult struct {
	Zone             string   `json:"zone"`
	PreviousRevision string   `json:"previous_revision"`
	Revision         string   `json:"revision"`
	Changes          []Change `json:"changes"`
	Accepted         bool     `json:"accepted"`
	APIVerified      bool     `json:"api_verified"`
	DNSVerified      bool     `json:"dns_verified"`
	RolledBack       bool     `json:"rolled_back"`
	RequestID        string   `json:"request_id"`
	Warning          string   `json:"warning,omitempty"`
}

type batchRequest struct {
	Deletes []struct {
		ID string `json:"id"`
	} `json:"deletes,omitempty"`
	Patches []PatchOperation  `json:"patches,omitempty"`
	Posts   []CreateOperation `json:"posts,omitempty"`
}

func (c *Client) ApplyChanges(ctx context.Context, zone string, request ApplyRequest) (ApplyResult, error) {
	if !request.Confirm {
		return ApplyResult{}, ErrConfirmationRequired
	}
	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	current, err := c.ListRecords(ctx, zone)
	if err != nil {
		return ApplyResult{}, err
	}
	plan, err := planChanges(current, PlanRequest{ExpectedRevision: request.ExpectedRevision, Changes: request.Changes})
	if err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{Zone: current.Zone, PreviousRevision: current.Revision, Changes: request.Changes, RequestID: request.RequestID}
	if len(plan.Deletes) == 0 && len(plan.Patches) == 0 && len(plan.Creates) == 0 {
		result.Accepted, result.APIVerified, result.DNSVerified, result.Revision = true, true, true, current.Revision
		_ = c.appendAudit(request, result, "no-op", "")
		return result, nil
	}
	if err := c.ensureAuditWritable(); err != nil {
		return result, fmt.Errorf("audit log for Cloudflare changes is not writable: %w", err)
	}
	if err := c.sendBatch(ctx, current.ZoneID, plan); err != nil {
		_ = c.appendAudit(request, result, "failed", err.Error())
		return result, err
	}
	result.Accepted = true
	verified, err := c.waitForAPI(ctx, current.Zone, plan, 15*time.Second)
	if err == nil {
		result.APIVerified = true
		result.Revision = verified.Revision
		if dnsErr := c.dnsVerifier(ctx, current.Zone, plan, 30*time.Second); dnsErr == nil {
			result.DNSVerified = true
			_ = c.appendAudit(request, result, "applied", "")
			return result, nil
		} else {
			result.Warning = "DNS propagation is still pending: " + dnsErr.Error()
			_ = c.appendAudit(request, result, "applied_dns_pending", result.Warning)
			return result, nil
		}
	}
	rollbackErr := c.rollback(ctx, current, request.Changes)
	result.RolledBack = rollbackErr == nil
	message := err.Error()
	if rollbackErr != nil {
		message += "; rollback failed: " + rollbackErr.Error()
	}
	_ = c.appendAudit(request, result, "verification_failed", message)
	return result, fmt.Errorf("verification of the Cloudflare change failed: %s", message)
}

func (c *Client) waitForDNS(ctx context.Context, zone string, plan Plan, timeout time.Duration) error {
	c.mu.RLock()
	nameservers := append([]string(nil), c.zoneNS[zone]...)
	c.mu.RUnlock()
	if len(nameservers) == 0 {
		return errors.New("no authoritative nameservers returned by Cloudflare")
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		allVerified := true
		for _, nameserver := range nameservers {
			if err := verifyNameserver(ctx, nameserver, plan); err != nil {
				lastErr = fmt.Errorf("%s: %w", nameserver, err)
				allVerified = false
				break
			}
		}
		if allVerified {
			return nil
		}
		if err := c.verifyDoH(ctx, plan); err == nil {
			return nil
		} else {
			lastErr = fmt.Errorf("direct DNS unavailable (%v); Cloudflare DoH: %w", lastErr, err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for authoritative nameservers: %w", lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func verifyNameserver(ctx context.Context, nameserver string, plan Plan) error {
	for _, change := range plan.Changes {
		owner, _ := changeOwner(plan.Zone, change.Name)
		kind := strings.ToUpper(strings.TrimSpace(change.Type))
		typeCode := dns.StringToType[kind]
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(owner), typeCode)
		response, _, err := (&dns.Client{Timeout: 3 * time.Second}).ExchangeContext(ctx, message, net.JoinHostPort(nameserver, "53"))
		if err != nil {
			return err
		}
		if err := verifyDNSResponse(response, change, plan); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) verifyDoH(ctx context.Context, plan Plan) (err error) {
	for _, change := range plan.Changes {
		owner, _ := changeOwner(plan.Zone, change.Name)
		kind := strings.ToUpper(strings.TrimSpace(change.Type))
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(owner), dns.StringToType[kind])
		wire, err := message.Pack()
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://cloudflare-dns.com/dns-query", bytes.NewReader(wire))
		if err != nil {
			return err
		}
		request.Header.Set("Accept", "application/dns-message")
		request.Header.Set("Content-Type", "application/dns-message")
		response, err := c.http.Do(request)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 65536))
		_ = response.Body.Close()
		if readErr != nil {
			return readErr
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("DoH returned %s", response.Status)
		}
		answer := new(dns.Msg)
		if err := answer.Unpack(data); err != nil {
			return err
		}
		if err := verifyDNSResponse(answer, change, plan); err != nil {
			return err
		}
	}
	return nil
}

func verifyDNSResponse(response *dns.Msg, change Change, plan Plan) error {
	owner, _ := changeOwner(plan.Zone, change.Name)
	kind := strings.ToUpper(strings.TrimSpace(change.Type))
	typeCode := dns.StringToType[kind]
	var answers []dns.RR
	for _, answer := range response.Answer {
		if answer.Header().Rrtype == typeCode {
			answers = append(answers, answer)
		}
	}
	if strings.EqualFold(change.Action, "delete") {
		if len(answers) != 0 {
			return errors.New("deleted RRset is still present")
		}
		return nil
	}
	proxied := false
	for _, expected := range plan.Expected {
		if expected.Name == owner && expected.Type == kind && expected.Proxied != nil && *expected.Proxied {
			proxied = true
		}
	}
	if proxied {
		if response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
			return errors.New("proxied RRset is not yet answering")
		}
		return nil
	}
	if len(answers) != len(change.Records) {
		return errors.New("authoritative RRset value count differs")
	}
	actual := make(map[string]bool)
	for _, answer := range answers {
		actual[canonicalRData(answer)] = true
	}
	for _, value := range change.Records {
		rr, parseErr := dns.NewRR(fmt.Sprintf("%s 300 IN %s %s", dns.Fqdn(owner), kind, value))
		if parseErr != nil || !actual[canonicalRData(rr)] {
			return errors.New("authoritative RRset values differ")
		}
	}
	return nil
}

func canonicalRData(rr dns.RR) string {
	parts := strings.Fields(rr.String())
	if len(parts) < 5 {
		return strings.ToLower(rr.String())
	}
	return strings.ToLower(strings.Join(parts[4:], " "))
}

func (c *Client) sendBatch(ctx context.Context, zoneID string, plan Plan) error {
	body := batchRequest{Patches: plan.Patches, Posts: plan.Creates}
	for _, operation := range plan.Deletes {
		body.Deletes = append(body.Deletes, struct {
			ID string `json:"id"`
		}{ID: operation.ID})
	}
	var response struct {
		Success bool       `json:"success"`
		Errors  []apiError `json:"errors"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records/batch", body, &response); err != nil {
		return err
	}
	if !response.Success {
		return apiFailure(response.Errors, "unsuccessful batch response")
	}
	return nil
}

func (c *Client) waitForAPI(ctx context.Context, zone string, plan Plan, timeout time.Duration) (ZoneRecords, error) {
	deadline := time.Now().Add(timeout)
	for {
		current, err := c.ListRecords(ctx, zone)
		if err == nil && planMatches(current, plan) {
			return current, nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return ZoneRecords{}, err
			}
			return ZoneRecords{}, errors.New("timed out waiting for intended records")
		}
		select {
		case <-ctx.Done():
			return ZoneRecords{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func planMatches(current ZoneRecords, plan Plan) bool {
	type key struct{ name, kind string }
	wanted := make(map[key][]CreateOperation)
	for _, operation := range plan.Expected {
		wanted[key{operation.Name, operation.Type}] = append(wanted[key{operation.Name, operation.Type}], operation)
	}
	for _, change := range plan.Changes {
		owner, _ := changeOwner(plan.Zone, change.Name)
		kind := strings.ToUpper(strings.TrimSpace(change.Type))
		var actual []Record
		for _, record := range current.Records {
			if record.Name == owner && record.Type == kind {
				actual = append(actual, record)
			}
		}
		expected := wanted[key{owner, kind}]
		if len(actual) != len(expected) {
			return false
		}
		used := make([]bool, len(actual))
		for _, value := range expected {
			found := false
			for i, record := range actual {
				if !used[i] && sameRecordValue(record, value) && record.TTL == value.TTL {
					used[i], found = true, true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func (c *Client) rollback(ctx context.Context, original ZoneRecords, changes []Change) error {
	latest, err := c.ListRecords(ctx, original.Zone)
	if err != nil {
		return err
	}
	affected := make(map[string]bool)
	for _, change := range changes {
		owner, _ := changeOwner(original.Zone, change.Name)
		affected[owner+"\x00"+strings.ToUpper(change.Type)] = true
	}
	plan := Plan{Zone: original.Zone}
	for _, record := range latest.Records {
		if affected[record.Name+"\x00"+record.Type] {
			plan.Deletes = append(plan.Deletes, deleteOperation(record))
		}
	}
	for _, record := range original.Records {
		if !affected[record.Name+"\x00"+record.Type] {
			continue
		}
		plan.Creates = append(plan.Creates, CreateOperation{Name: record.Name, Type: record.Type, Content: record.Content, TTL: record.TTL, Proxied: record.Proxied, Priority: record.Priority, Comment: record.Comment, Tags: record.Tags})
	}
	if err := c.sendBatch(ctx, original.ZoneID, plan); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		current, readErr := c.ListRecords(ctx, original.Zone)
		if readErr == nil && affectedRecordsMatch(current, original, affected) {
			return nil
		}
		if time.Now().After(deadline) {
			if readErr != nil {
				return readErr
			}
			return errors.New("timed out verifying rollback")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func affectedRecordsMatch(left, right ZoneRecords, affected map[string]bool) bool {
	selectRecords := func(zone ZoneRecords) map[string][]Record {
		result := make(map[string][]Record)
		for _, record := range zone.Records {
			key := record.Name + "\x00" + record.Type
			if affected[key] {
				result[key] = append(result[key], record)
			}
		}
		return result
	}
	a, b := selectRecords(left), selectRecords(right)
	if len(a) != len(b) {
		return false
	}
	for key, expected := range b {
		actual := a[key]
		if len(actual) != len(expected) {
			return false
		}
		used := make([]bool, len(actual))
		for _, wanted := range expected {
			found := false
			for i, got := range actual {
				if !used[i] && got.Content == wanted.Content && got.TTL == wanted.TTL && equalBool(got.Proxied, wanted.Proxied) && equalUint16(got.Priority, wanted.Priority) {
					used[i], found = true, true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func (c *Client) ensureAuditWritable() error {
	if c.auditPath == "" {
		return nil
	}
	file, err := os.OpenFile(c.auditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	return file.Close()
}

func (c *Client) appendAudit(request ApplyRequest, result ApplyResult, outcome, detail string) (err error) {
	if c.auditPath == "" {
		return nil
	}
	event := map[string]any{"timestamp": time.Now().UTC(), "actor": request.Actor, "request_id": request.RequestID, "provider": "cloudflare", "zone": result.Zone, "previous_revision": result.PreviousRevision, "revision": result.Revision, "changes": result.Changes, "outcome": outcome, "accepted": result.Accepted, "api_verified": result.APIVerified, "dns_verified": result.DNSVerified, "rolled_back": result.RolledBack}
	if detail != "" {
		event["detail"] = detail
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(c.auditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	// The close matters here: an audit record that fails to flush is lost, and
	// reporting success would hide that.
	defer closeWithError(&err, "close cloudflare audit log", file.Close)
	_, err = file.Write(data)
	return err
}

func (c *Client) doJSON(ctx context.Context, method, path string, input, output any) (err error) {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("request to the Cloudflare API failed: %w", err)
	}
	defer closeWithError(&err, "close response body", response.Body.Close)
	return decodeResponse(response, output)
}
