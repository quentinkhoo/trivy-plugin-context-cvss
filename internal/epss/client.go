package epss

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	apiBaseURL        = "https://api.first.org/data/v1/epss"
	maxCVEsPerRequest = 80
	requestTimeout    = 15 * time.Second
)

type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Date       string `json:"date"`
		Percentile string `json:"percentile"`
	} `json:"data"`
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// Data holds EPSS score, percentile, and date for a CVE.
type Data struct {
	Score      float64
	Percentile float64
	Date       string
}

// Client fetches EPSS scores from the FIRST API.
type Client struct {
	HTTPClient *http.Client
}

// NewClient returns a client with default timeout.
func NewClient() *Client {
	return &Client{HTTPClient: &http.Client{Timeout: requestTimeout}}
}

// FetchScores returns a map of CVE ID -> EPSS data for the given CVE IDs.
func (c *Client) FetchScores(cveIDs []string) (map[string]Data, error) {
	if len(cveIDs) == 0 {
		return map[string]Data{}, nil
	}
	result := make(map[string]Data)
	for i := 0; i < len(cveIDs); i += maxCVEsPerRequest {
		end := i + maxCVEsPerRequest
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		got, err := c.fetchBatch(cveIDs[i:end])
		if err != nil {
			return result, err
		}
		for k, v := range got {
			result[k] = v
		}
	}
	return result, nil
}

func (c *Client) fetchBatch(cveIDs []string) (map[string]Data, error) {
	params := url.Values{}
	params.Set("cve", joinCVEs(cveIDs))
	req, err := http.NewRequest(http.MethodGet, apiBaseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("epss request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss api: status %s", resp.Status)
	}
	var body epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("epss decode: %w", err)
	}
	out := make(map[string]Data)
	for _, d := range body.Data {
		score, err := strconv.ParseFloat(d.EPSS, 64)
		if err != nil {
			continue
		}
		percentile, _ := strconv.ParseFloat(d.Percentile, 64)
		out[d.CVE] = Data{Score: score, Percentile: percentile, Date: d.Date}
	}
	return out, nil
}

func joinCVEs(cveIDs []string) string {
	if len(cveIDs) == 0 {
		return ""
	}
	b := []byte(cveIDs[0])
	for i := 1; i < len(cveIDs); i++ {
		b = append(b, ',')
		b = append(b, cveIDs[i]...)
	}
	return string(b)
}
