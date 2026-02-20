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

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			Metrics struct {
				CVSSMetricV31 []struct {
					Type     string `json:"type"`
					CVSSData struct {
						VectorString string `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					Type     string `json:"type"`
					CVSSData struct {
						VectorString string `json:"vectorString"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
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
	req, err := http.NewRequest(http.MethodGet, nvdAPIBase+"?cveId="+url.QueryEscape(cveID), nil)
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
	if v := pickVector(metrics.CVSSMetricV31); v != "" {
		return strings.ReplaceAll(v, `\/`, "/"), nil
	}
	if v := pickVectorV30(metrics.CVSSMetricV30); v != "" {
		return strings.ReplaceAll(v, `\/`, "/"), nil
	}
	return "", nil
}

func pickVector(entries []struct {
	Type     string `json:"type"`
	CVSSData struct {
		VectorString string `json:"vectorString"`
	} `json:"cvssData"`
}) string {
	var primary, first string
	for _, e := range entries {
		if e.CVSSData.VectorString == "" {
			continue
		}
		if first == "" {
			first = e.CVSSData.VectorString
		}
		if strings.EqualFold(e.Type, "Primary") {
			primary = e.CVSSData.VectorString
			break
		}
	}
	if primary != "" {
		return primary
	}
	return first
}

func pickVectorV30(entries []struct {
	Type     string `json:"type"`
	CVSSData struct {
		VectorString string `json:"vectorString"`
	} `json:"cvssData"`
}) string {
	var primary, first string
	for _, e := range entries {
		if e.CVSSData.VectorString == "" {
			continue
		}
		if first == "" {
			first = e.CVSSData.VectorString
		}
		if strings.EqualFold(e.Type, "Primary") {
			primary = e.CVSSData.VectorString
			break
		}
	}
	if primary != "" {
		return primary
	}
	return first
}
