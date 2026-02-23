package nvd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	nvdAPIBase     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	requestTimeout = 15 * time.Second
)

type cvssData struct {
	VectorString string `json:"vectorString"`
}

type cvssMetricEntry struct {
	Type     string   `json:"type"`
	CVSSData cvssData `json:"cvssData"`
}

type nvdMetrics struct {
	CVSSMetricV31 []cvssMetricEntry `json:"cvssMetricV31"`
	CVSSMetricV30 []cvssMetricEntry `json:"cvssMetricV30"`
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			Metrics nvdMetrics `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// Client fetches CVE data from NVD. Optional APIKey enables higher rate limits.
type Client struct {
	HTTPClient *http.Client
	APIKey     string
}

// NewClient returns a client. apiKey is optional.
func NewClient(apiKey string) *Client {
	return &Client{
		HTTPClient: &http.Client{Timeout: requestTimeout},
		APIKey:     apiKey,
	}
}

// FetchCVSSV3Vector returns the CVSS v3.1 or v3.0 vector string for the given CVE ID.
func (c *Client) FetchCVSSV3Vector(cveID string) (string, error) {
	params := url.Values{}
	params.Set("cveId", cveID)
	req, err := http.NewRequest(http.MethodGet, nvdAPIBase+"?"+params.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("nvd request: %w", err)
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("nvd request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", fmt.Errorf("nvd rate limit (429)")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("nvd api: status %s", resp.Status)
	}
	var body nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("nvd decode: %w", err)
	}
	if len(body.Vulnerabilities) == 0 {
		return "", nil
	}
	metrics := body.Vulnerabilities[0].CVE.Metrics
	// Try v3.1 first, fall back to v3.0.
	for _, entries := range [][]cvssMetricEntry{metrics.CVSSMetricV31, metrics.CVSSMetricV30} {
		if v := pickVector(entries); v != "" {
			// The NVD API occasionally returns JSON-escaped forward slashes (\/),
			// which is valid JSON but invalid in CVSS vector strings.
			return strings.ReplaceAll(v, `\/`, "/"), nil
		}
	}
	return "", nil
}

// pickVector returns the Primary vector from entries, falling back to the first
// non-empty vector if no Primary entry exists.
func pickVector(entries []cvssMetricEntry) string {
	var first string
	for _, e := range entries {
		if e.CVSSData.VectorString == "" {
			continue
		}
		if strings.EqualFold(e.Type, "Primary") {
			return e.CVSSData.VectorString
		}
		if first == "" {
			first = e.CVSSData.VectorString
		}
	}
	return first
}
