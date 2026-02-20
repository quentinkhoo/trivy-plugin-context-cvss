package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"trivy-plugin-context-cvss/internal/epss"
	"trivy-plugin-context-cvss/internal/flags"
	"trivy-plugin-context-cvss/internal/nvd"
	"trivy-plugin-context-cvss/internal/report"
)

func main() {
	ro := flags.Parse()
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Errorf("failed to read from stdin: %w", err))
	}
	var reportData map[string]any
	if err := json.Unmarshal(inputData, &reportData); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	processReport(reportData, ro)
	output, _ := json.MarshalIndent(reportData, "", "  ")
	fmt.Println(string(output))
}

func processReport(reportData map[string]any, ro flags.RunOptions) {
	results, _ := reportData["Results"].([]any)
	if results == nil {
		return
	}
	nvdVectors := map[string]string{}
	if ro.FetchCVSS {
		nvdVectors = fetchNVDVectors(report.CollectCVEsWithoutCVSS(results), ro.NvdAPIKey)
	}
	epssData := map[string]epss.Data{}
	if ro.UseEPSS {
		epssData = fetchEPSSData(report.CollectAllCVEIDs(results))
	}
	for _, r := range results {
		resa, _ := r.(map[string]any)
		if resa == nil {
			continue
		}
		vulns, _ := resa["Vulnerabilities"].([]any)
		for _, v := range vulns {
			vuln, _ := v.(map[string]any)
			if vuln != nil {
				report.ProcessVuln(vuln, nvdVectors, epssData, ro)
			}
		}
	}
}

func fetchNVDVectors(cveIDs []string, apiKey string) map[string]string {
	out := make(map[string]string)
	client := nvd.NewClient(apiKey)
	throttle := 6 * time.Second
	if apiKey != "" {
		throttle = time.Second
	}
	for i, cveID := range cveIDs {
		if i > 0 {
			time.Sleep(throttle)
		}
		vec, err := client.FetchCVSSV3Vector(cveID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "NVD fetch %s: %v\n", cveID, err)
			continue
		}
		if vec != "" {
			out[cveID] = vec
		}
	}
	return out
}

func fetchEPSSData(cveIDs []string) map[string]epss.Data {
	data, err := epss.NewClient().FetchScores(cveIDs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "EPSS fetch: %v (using -e or X for E)\n", err)
		return map[string]epss.Data{}
	}
	return data
}
