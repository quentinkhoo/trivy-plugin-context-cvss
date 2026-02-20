package report

import (
	"fmt"
	"os"

	"trivy-plugin-context-cvss/internal/cvss"
	"trivy-plugin-context-cvss/internal/epss"
	"trivy-plugin-context-cvss/internal/flags"
)

// contextualMetrics holds the contextual CVSS metrics (temporal, environmental) and EPSS data, stored under Custom.ContextualMetrics.
type contextualMetrics struct {
	Vector              string   `json:"Vector,omitempty"`
	TemporalScore       float64  `json:"TemporalScore"`
	TemporalRating      string   `json:"TemporalRating,omitempty"`
	EnvironmentalScore  float64  `json:"EnvironmentalScore"`
	EnvironmentalRating string   `json:"EnvironmentalRating,omitempty"`
	EpssScore           *float64 `json:"EpssScore,omitempty"`
	EpssPercentile      *float64 `json:"EpssPercentile,omitempty"`
	EpssDate            *string  `json:"EpssDate,omitempty"`
}

var defaultCVSSSources = []string{
	"redhat", "ghsa", "bitnami", "ubuntu", "alpine", "amazon", "oracle", "nvd",
}

func chooseCVSSSource(vuln map[string]any) string {
	cvssMap, _ := vuln["CVSS"].(map[string]any)
	if len(cvssMap) == 0 {
		return ""
	}
	severitySource, _ := vuln["SeveritySource"].(string)
	if severitySource != "" {
		if data, ok := cvssMap[severitySource].(map[string]any); ok {
			if v, _ := data["V3Vector"].(string); v != "" {
				return severitySource
			}
		}
	}
	for _, source := range defaultCVSSSources {
		if data, ok := cvssMap[source].(map[string]any); ok {
			if v, _ := data["V3Vector"].(string); v != "" {
				return source
			}
		}
	}
	for source, val := range cvssMap {
		if data, ok := val.(map[string]any); ok {
			if v, _ := data["V3Vector"].(string); v != "" {
				return source
			}
		}
	}
	return ""
}

func getCVSSVectorFromVuln(vuln map[string]any) string {
	source := chooseCVSSSource(vuln)
	if source == "" {
		return ""
	}
	cvssMap, _ := vuln["CVSS"].(map[string]any)
	data, _ := cvssMap[source].(map[string]any)
	v, _ := data["V3Vector"].(string)
	return v
}

func setContextualMetrics(vuln map[string]any, metrics contextualMetrics) {
	if vuln["Custom"] == nil {
		vuln["Custom"] = make(map[string]any)
	}
	if custom, ok := vuln["Custom"].(map[string]any); ok {
		custom["ContextualMetrics"] = metrics
	}
}

// CollectCVEsWithoutCVSS returns CVE IDs that have no CVSS source in the report.
func CollectCVEsWithoutCVSS(results []any) []string {
	var out []string
	seen := make(map[string]bool)
	for _, r := range results {
		resa, _ := r.(map[string]any)
		if resa == nil {
			continue
		}
		vulns, _ := resa["Vulnerabilities"].([]any)
		for _, v := range vulns {
			vuln, _ := v.(map[string]any)
			if vuln == nil || chooseCVSSSource(vuln) != "" {
				continue
			}
			id, _ := vuln["VulnerabilityID"].(string)
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// CollectAllCVEIDs returns deduplicated CVE IDs from all vulnerabilities in results.
func CollectAllCVEIDs(results []any) []string {
	var out []string
	seen := make(map[string]bool)
	for _, r := range results {
		resa, _ := r.(map[string]any)
		if resa == nil {
			continue
		}
		vulns, _ := resa["Vulnerabilities"].([]any)
		for _, v := range vulns {
			vuln, _ := v.(map[string]any)
			if vuln == nil {
				continue
			}
			id, _ := vuln["VulnerabilityID"].(string)
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// ProcessVuln resolves the CVSS vector, applies contextual metrics, and writes result to vuln.Custom.ContextualMetrics.
func ProcessVuln(vuln map[string]any, nvdVectors map[string]string, epssData map[string]epss.Data, ro flags.RunOptions) {
	vulnID, _ := vuln["VulnerabilityID"].(string)
	severity, _ := vuln["Severity"].(string)
	vectorStr := getCVSSVectorFromVuln(vuln)
	if vectorStr == "" && ro.FetchCVSS {
		vectorStr = nvdVectors[vulnID]
	}
	if vectorStr == "" {
		if ro.ForceCtxRating {
			setContextualMetrics(vuln, contextualMetrics{
				TemporalRating:      severity,
				EnvironmentalRating: severity,
			})
		}
		return
	}
	eVal := ro.Opts.E
	if ro.UseEPSS {
		if data, ok := epssData[vulnID]; ok {
			eVal = epss.EPSSToExploitMaturity(data.Score)
		} else if eVal == "" {
			eVal = "X"
		}
	}
	if eVal == "" {
		eVal = "X"
	}
	opts := ro.Opts
	opts.E = eVal
	newVectorStr, err := cvss.ApplyMetrics(vectorStr, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error applying environmental metrics for %s: %v\n", vulnID, err)
		return
	}
	_, tempScore, envScore, err := cvss.CalculateScores(newVectorStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calculating scores for %s: %v\n", vulnID, err)
		return
	}
	metrics := contextualMetrics{
		Vector:              newVectorStr,
		TemporalScore:       tempScore,
		TemporalRating:      cvss.CalculateSeverityRating(tempScore),
		EnvironmentalScore:  envScore,
		EnvironmentalRating: cvss.CalculateSeverityRating(envScore),
	}
	if ro.UseEPSS {
		if data, ok := epssData[vulnID]; ok {
			metrics.EpssScore = &data.Score
			metrics.EpssPercentile = &data.Percentile
			if data.Date != "" {
				metrics.EpssDate = &data.Date
			}
		}
	}
	setContextualMetrics(vuln, metrics)
}
