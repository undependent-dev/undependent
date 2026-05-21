// Package osv queries the OSV API for known vulnerabilities.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Vulnerability represents a single OSV vulnerability.
type Vulnerability struct {
	ID       string
	Summary  string
	Severity string // "low", "medium", "high", "critical"
	URL      string
}

// QueryResult holds results for one package query.
type QueryResult struct {
	Package string
	Version string
	Vulns   []Vulnerability
}

// BatchQuery is a single entry in a batch request.
type BatchQuery struct {
	Package   string
	Version   string
	Ecosystem string
}

// Client wraps the OSV API.
type Client struct {
	HTTP *http.Client
}

// NewClient creates an OSV client with a 30s timeout.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

// osvQuery is the single-package request body.
type osvQuery struct {
	Package *osvPackage `json:"package"`
	Version string      `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvResponse is the API response for a single query.
type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID      string       `json:"id"`
	Summary string       `json:"summary"`
	Severity []osvSev    `json:"severity"`
	Links   []osvLink    `json:"links"`
}

type osvSev struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvLink struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Query checks a single package version against OSV.
func (c *Client) Query(ctx context.Context, ecosystem, pkg, version string) (*QueryResult, error) {
	q := osvQuery{
		Package: &osvPackage{Name: pkg, Ecosystem: ecosystem},
		Version: version,
	}

	body, err := json.Marshal(q)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned %d", resp.StatusCode)
	}

	var osvResp osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	result := &QueryResult{
		Package: pkg,
		Version: version,
		Vulns:   make([]Vulnerability, 0, len(osvResp.Vulns)),
	}

	for _, v := range osvResp.Vulns {
		vuln := Vulnerability{
			ID:      v.ID,
			Summary: v.Summary,
		}
		vuln.Severity = extractSeverity(v.Severity)
		if len(v.Links) > 0 {
			vuln.URL = v.Links[0].URL
		}
		result.Vulns = append(result.Vulns, vuln)
	}

	return result, nil
}

// QueryBatch checks multiple packages in a single API call.
func (c *Client) QueryBatch(ctx context.Context, queries []BatchQuery) ([]QueryResult, error) {
	batchReq := map[string][]osvQuery{"queries": make([]osvQuery, 0, len(queries))}
	for _, q := range queries {
		batchReq["queries"] = append(batchReq["queries"], osvQuery{
			Package: &osvPackage{Name: q.Package, Ecosystem: q.Ecosystem},
			Version: q.Version,
		})
	}

	body, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("marshal batch query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/query/batch", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned %d", resp.StatusCode)
	}

	type batchResponse struct {
		Results []osvResponse `json:"results"`
	}
	var batchResp batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	results := make([]QueryResult, 0, len(queries))
	for i, resp := range batchResp.Results {
		if i >= len(queries) {
			break
		}
		q := queries[i]
		result := QueryResult{
			Package: q.Package,
			Version: q.Version,
			Vulns:   make([]Vulnerability, 0, len(resp.Vulns)),
		}
		for _, v := range resp.Vulns {
			vuln := Vulnerability{
				ID:      v.ID,
				Summary: v.Summary,
				Severity: extractSeverity(v.Severity),
			}
			if len(v.Links) > 0 {
				vuln.URL = v.Links[0].URL
			}
			result.Vulns = append(result.Vulns, vuln)
		}
		results = append(results, result)
	}

	return results, nil
}

// EcosystemForLang maps language names to OSV ecosystem strings.
func EcosystemForLang(lang string) string {
	switch strings.ToLower(lang) {
	case "go":
		return "Go"
	case "python":
		return "PyPI"
	case "javascript", "typescript":
		return "npm"
	case "rust":
		return "crates.io"
	default:
		return ""
	}
}

func extractSeverity(sevs []osvSev) string {
	for _, s := range sevs {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V4" {
			score := 0.0
			fmt.Sscanf(s.Score, "%f", &score)
			if score >= 9.0 {
				return "critical"
			} else if score >= 7.0 {
				return "high"
			} else if score >= 4.0 {
				return "medium"
			} else if score > 0 {
				return "low"
			}
		}
	}
	return "unknown"
}