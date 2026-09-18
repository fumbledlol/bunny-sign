package bunnysign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultPurgeEndpoint = "https://api.bunny.net/purge"
	defaultPullZoneFmt   = "https://api.bunny.net/pullzone/%s/purgeCache"
	defaultClientTimeout = 10 * time.Second
)

// PurgeClient interacts with the Bunny.net purge API.
type PurgeClient struct {
	apiKey     string
	pullZoneID string
	httpClient *http.Client
	purgeURL   string
}

// ClientOption configures a PurgeClient.
type ClientOption func(*PurgeClient)

// WithHTTPClient overrides the HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *PurgeClient) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithPullZoneID sets the default pull zone ID.
func WithPullZoneID(id string) ClientOption {
	return func(c *PurgeClient) {
		c.pullZoneID = strings.TrimSpace(id)
	}
}

// NewPurgeClient creates a client for the Bunny.net cache purge API.
func NewPurgeClient(apiKey string, opts ...ClientOption) *PurgeClient {
	c := &PurgeClient{
		apiKey:   strings.TrimSpace(apiKey),
		purgeURL: defaultPurgeEndpoint,
		httpClient: &http.Client{
			Timeout: defaultClientTimeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// PurgeURL invalidates specific cached URLs across Bunny.net edge nodes.
func (c *PurgeClient) PurgeURL(ctx context.Context, urls ...string) error {
	if c.apiKey == "" {
		return errors.New("bunnysign: API key not configured")
	}

	var errs []string
	for _, rawURL := range urls {
		target := strings.TrimSpace(rawURL)
		if target == "" {
			continue
		}

		reqURL := fmt.Sprintf("%s?url=%s&async=true", c.purgeURL, url.QueryEscape(target))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, nil)
		if err != nil {
			errs = append(errs, fmt.Sprintf("build request %s: %v", target, err))
			continue
		}

		req.Header.Set("AccessKey", c.apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			errs = append(errs, fmt.Sprintf("post %s: %v", target, err))
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errs = append(errs, fmt.Sprintf("purge %s returned HTTP %d", target, resp.StatusCode))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("bunnysign: %s", strings.Join(errs, "; "))
	}
	return nil
}

// PurgeCacheTag invalidates cached items matching one or more Edge Cache Tags.
func (c *PurgeClient) PurgeCacheTag(ctx context.Context, pullZoneID string, tags ...string) error {
	pz := pullZoneID
	if pz == "" {
		pz = c.pullZoneID
	}
	if pz == "" {
		return errors.New("bunnysign: pull zone ID required")
	}
	if c.apiKey == "" {
		return errors.New("bunnysign: API key not configured")
	}

	targetURL := fmt.Sprintf(defaultPullZoneFmt, pz)
	var errs []string

	for _, tag := range tags {
		cleanTag := strings.TrimSpace(tag)
		if cleanTag == "" {
			continue
		}

		bodyBytes, _ := json.Marshal(map[string]string{"CacheTag": cleanTag})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
		if err != nil {
			errs = append(errs, fmt.Sprintf("build request for tag %s: %v", cleanTag, err))
			continue
		}
		req.Header.Set("AccessKey", c.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			errs = append(errs, fmt.Sprintf("tag %s: %v", cleanTag, err))
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errs = append(errs, fmt.Sprintf("tag %s returned HTTP %d", cleanTag, resp.StatusCode))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("bunnysign: %s", strings.Join(errs, "; "))
	}
	return nil
}

// PurgePullZone invalidates the entire cache for a pull zone.
func (c *PurgeClient) PurgePullZone(ctx context.Context, pullZoneID string) error {
	pz := pullZoneID
	if pz == "" {
		pz = c.pullZoneID
	}
	if pz == "" {
		return errors.New("bunnysign: pull zone ID required")
	}
	if c.apiKey == "" {
		return errors.New("bunnysign: API key not configured")
	}

	targetURL := fmt.Sprintf(defaultPullZoneFmt, pz)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("AccessKey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bunnysign: purge pull zone returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
