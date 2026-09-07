package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL = "https://api.cloudflare.com/client/v4"
	maxBodyBytes   = 8 << 20
)

type Client struct {
	baseURL     string
	token       string
	http        *http.Client
	mu          sync.RWMutex
	applyMu     sync.Mutex
	zoneIDs     map[string]string
	zoneNS      map[string][]string
	auditPath   string
	dnsVerifier func(context.Context, string, Plan, time.Duration) error
}

func (c *Client) SetAuditPath(path string) { c.auditPath = strings.TrimSpace(path) }

type Record struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Content  string   `json:"content"`
	TTL      uint32   `json:"ttl"`
	Proxied  *bool    `json:"proxied,omitempty"`
	Priority *uint16  `json:"priority,omitempty"`
	Comment  string   `json:"comment,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type ZoneRecords struct {
	ZoneID   string   `json:"-"`
	Zone     string   `json:"zone"`
	Revision string   `json:"revision"`
	Records  []Record `json:"records"`
}

type apiResponse struct {
	Success    bool            `json:"success"`
	Errors     []apiError      `json:"errors"`
	Result     []Record        `json:"result"`
	ResultInfo json.RawMessage `json:"result_info"`
}

type zone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameServers []string `json:"name_servers"`
}

type zoneResponse struct {
	Success bool       `json:"success"`
	Errors  []apiError `json:"errors"`
	Result  []zone     `json:"result"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

func New(token string) (*Client, error) {
	return newClient(defaultBaseURL, token, nil)
}

func newClient(baseURL, token string, httpClient *http.Client) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Cloudflare API URL %q", baseURL)
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("an API token for Cloudflare is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	}
	client := &Client{baseURL: parsed.String(), token: strings.TrimSpace(token), http: httpClient, zoneIDs: make(map[string]string), zoneNS: make(map[string][]string)}
	client.dnsVerifier = client.waitForDNS
	return client, nil
}

func (c *Client) ListRecords(ctx context.Context, zone string) (ZoneRecords, error) {
	zone = canonicalName(zone)
	if zone == "" {
		return ZoneRecords{}, errors.New("a zone name for Cloudflare is required")
	}
	zoneID, err := c.resolveZoneID(ctx, zone)
	if err != nil {
		return ZoneRecords{}, err
	}

	var records []Record
	for page := 1; ; page++ {
		path := "/zones/" + url.PathEscape(zoneID) + "/dns_records?per_page=5000000&page=" + strconv.Itoa(page)
		var response apiResponse
		if err := c.get(ctx, path, &response); err != nil {
			return ZoneRecords{}, err
		}
		for i := range response.Result {
			record := &response.Result[i]
			record.Name = canonicalName(record.Name)
			record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
			record.Content = strings.TrimSpace(record.Content)
			sort.Strings(record.Tags)
			if !inZone(record.Name, zone) {
				return ZoneRecords{}, fmt.Errorf("record %q returned by Cloudflare is outside configured zone %q", record.Name, zone)
			}
		}
		records = append(records, response.Result...)

		var info resultInfo
		if len(response.ResultInfo) == 0 || json.Unmarshal(response.ResultInfo, &info) != nil || info.TotalPages <= page {
			break
		}
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Content != b.Content {
			return a.Content < b.Content
		}
		return a.ID < b.ID
	})
	encoded, err := json.Marshal(records)
	if err != nil {
		return ZoneRecords{}, fmt.Errorf("encode normalized Cloudflare records: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return ZoneRecords{ZoneID: zoneID, Zone: zone, Revision: hex.EncodeToString(sum[:]), Records: records}, nil
}

func (c *Client) resolveZoneID(ctx context.Context, name string) (string, error) {
	c.mu.RLock()
	id := c.zoneIDs[name]
	c.mu.RUnlock()
	if id != "" {
		return id, nil
	}

	query := url.Values{"name": {name}, "status": {"active"}, "per_page": {"50"}}
	var response zoneResponse
	if err := c.getJSON(ctx, "/zones?"+query.Encode(), &response); err != nil {
		return "", err
	}
	if !response.Success {
		return "", apiFailure(response.Errors, "unsuccessful response")
	}
	var matches []zone
	for _, candidate := range response.Result {
		if canonicalName(candidate.Name) == name && strings.TrimSpace(candidate.ID) != "" {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("zone %q was not found in Cloudflare or is not accessible", name)
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("got %d exact matches from Cloudflare for zone %q", len(matches), name)
	}
	c.mu.Lock()
	c.zoneIDs[name] = matches[0].ID
	c.zoneNS[name] = append([]string(nil), matches[0].NameServers...)
	c.mu.Unlock()
	return matches[0].ID, nil
}

func (c *Client) get(ctx context.Context, path string, output *apiResponse) error {
	if err := c.getJSON(ctx, path, output); err != nil {
		return err
	}
	if !output.Success {
		return apiFailure(output.Errors, "unsuccessful response")
	}
	return nil
}

func (c *Client) getJSON(ctx context.Context, path string, output any) (err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("request to the Cloudflare API failed: %w", err)
	}
	defer closeWithError(&err, "close response body", response.Body.Close)
	return decodeResponse(response, output)
}

func decodeResponse(response *http.Response, output any) error {
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read Cloudflare API response: %w", err)
	}
	if len(data) > maxBodyBytes {
		return fmt.Errorf("response from the Cloudflare API exceeds %d bytes", maxBodyBytes)
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode Cloudflare API response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var failure struct {
			Errors []apiError `json:"errors"`
		}
		if json.Unmarshal(data, &failure) == nil && len(failure.Errors) > 0 {
			return apiFailure(failure.Errors, response.Status)
		}
		return fmt.Errorf("the Cloudflare API returned %s", response.Status)
	}
	return nil
}

func apiFailure(apiErrors []apiError, fallback string) error {
	if len(apiErrors) > 0 {
		return fmt.Errorf("the Cloudflare API returned error %d: %s", apiErrors[0].Code, apiErrors[0].Message)
	}
	return fmt.Errorf("the Cloudflare API returned %s", fallback)
}

func canonicalName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func inZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}
