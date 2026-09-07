package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kilo666mj/rilldns/internal/blocking"
	"github.com/kilo666mj/rilldns/internal/refreshstatus"
	"github.com/kilo666mj/rilldns/internal/zones"
)

const maxResponseBytes = 8 << 20

type Client struct {
	baseURL string
	http    *http.Client
}

func (c *Client) GetBlocklistConfig(ctx context.Context) (blocking.Config, error) {
	var response blocking.Config
	if err := c.request(ctx, http.MethodGet, "/v1/blocklists/config", nil, &response); err != nil {
		return blocking.Config{}, err
	}
	return response, nil
}

func (c *Client) UpdateBlocklistConfig(ctx context.Context, request blocking.UpdateRequest, actor string) (blocking.UpdateResult, error) {
	var response blocking.UpdateResult
	headers := make(http.Header)
	headers.Set("X-RillDNS-Actor", actor)
	if err := c.requestWithHeaders(ctx, http.MethodPut, "/v1/blocklists/config", request, headers, &response); err != nil {
		return blocking.UpdateResult{}, err
	}
	return response, nil
}

func (c *Client) RefreshStatus(ctx context.Context) (refreshstatus.Report, error) {
	var response refreshstatus.Report
	if err := c.request(ctx, http.MethodGet, "/v1/status/refresh", nil, &response); err != nil {
		return refreshstatus.Report{}, err
	}
	return response, nil
}

func New(baseURL string) (*Client, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid API URL %q", baseURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported API URL scheme %q", parsed.Scheme)
	}
	return &Client{
		baseURL: parsed.String(),
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) ListZones(ctx context.Context) ([]zones.Zone, error) {
	var response struct {
		Zones []zones.Zone `json:"zones"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/zones", nil, &response); err != nil {
		return nil, err
	}
	return response.Zones, nil
}

func (c *Client) GetZone(ctx context.Context, zone string) (zones.Zone, error) {
	var response zones.Zone
	path := "/v1/zones/" + url.PathEscape(strings.TrimSuffix(zone, ".")) + "/rrsets"
	if err := c.request(ctx, http.MethodGet, path, nil, &response); err != nil {
		return zones.Zone{}, err
	}
	return response, nil
}

func (c *Client) Apply(ctx context.Context, zone string, request zones.ChangeRequest, actor string) (zones.ChangeResult, error) {
	var response zones.ChangeResult
	path := "/v1/zones/" + url.PathEscape(strings.TrimSuffix(zone, ".")) + "/changes"
	headers := make(http.Header)
	headers.Set("X-RillDNS-Actor", actor)
	if err := c.requestWithHeaders(ctx, http.MethodPost, path, request, headers, &response); err != nil {
		return zones.ChangeResult{}, err
	}
	return response, nil
}

func (c *Client) CreateZone(ctx context.Context, zone string, request zones.LifecycleRequest, actor string) (zones.LifecycleResult, error) {
	var response zones.LifecycleResult
	path := "/v1/zones/" + url.PathEscape(strings.TrimSuffix(zone, "."))
	headers := make(http.Header)
	headers.Set("X-RillDNS-Actor", actor)
	if err := c.requestWithHeaders(ctx, http.MethodPut, path, request, headers, &response); err != nil {
		return zones.LifecycleResult{}, err
	}
	return response, nil
}

func (c *Client) DeleteZone(ctx context.Context, zone string, request zones.LifecycleRequest, actor string) (zones.LifecycleResult, error) {
	var response zones.LifecycleResult
	path := "/v1/zones/" + url.PathEscape(strings.TrimSuffix(zone, "."))
	headers := make(http.Header)
	headers.Set("X-RillDNS-Actor", actor)
	if err := c.requestWithHeaders(ctx, http.MethodDelete, path, request, headers, &response); err != nil {
		return zones.LifecycleResult{}, err
	}
	return response, nil
}

func (c *Client) request(ctx context.Context, method, path string, input, output any) error {
	return c.requestWithHeaders(ctx, method, path, input, nil, output)
}

func (c *Client) requestWithHeaders(ctx context.Context, method, path string, input any, headers http.Header, output any) (err error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("RillDNS API request failed: %w", err)
	}
	defer closeWithError(&err, "close response body", response.Body.Close)
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("RillDNS API response exceeds %d bytes", maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var apiError struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		message := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &apiError) == nil && apiError.Error.Message != "" {
			message = apiError.Error.Message
		}
		return fmt.Errorf("RillDNS API returned %s: %s", response.Status, message)
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			return fmt.Errorf("decode RillDNS API response: %w", err)
		}
	}
	return nil
}
