package epss

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
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
	result := make(map[string]Data)
	for batch := range slices.Chunk(cveIDs, maxCVEsPerRequest) {
		got, err := c.fetchBatch(batch)
		if err != nil {
			return result, err
		}
		maps.Copy(result, got)
	}
	return result, nil
}

// fetchBatch fetches EPSS scores for a slice of CVE IDs in a single batch,
// paginating through results until all records have been collected.
func (c *Client) fetchBatch(cveIDs []string) (map[string]Data, error) {
	out := make(map[string]Data)
	cveParam := strings.Join(cveIDs, ",")
	offset := 0

	for {
		page, err := c.fetchPage(cveParam, offset)
		if err != nil {
			return nil, err
		}
		for _, d := range page.Data {
			score, err := strconv.ParseFloat(d.EPSS, 64)
			if err != nil {
				continue
			}
			percentile, _ := strconv.ParseFloat(d.Percentile, 64)
			out[d.CVE] = Data{Score: score, Percentile: percentile, Date: d.Date}
		}
		offset += len(page.Data)
		// Stop when we've collected all records, or if the API returned an empty
		// page unexpectedly (guards against an infinite loop).
		if offset >= page.Total || len(page.Data) == 0 {
			break
		}
	}
	return out, nil
}

// fetchPage makes a single HTTP request to the EPSS API for the given CVE param
// and page offset, returning the decoded response. For example:
//
//	GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228%2CCVE-2022-0001&offset=0
func (c *Client) fetchPage(cveParam string, offset int) (*epssResponse, error) {
	params := url.Values{}
	params.Set("cve", cveParam)
	params.Set("offset", strconv.Itoa(offset))
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
	return &body, nil
}
