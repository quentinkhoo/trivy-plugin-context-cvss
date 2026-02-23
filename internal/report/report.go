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
	return collectCVEIDs(results, func(vuln map[string]any) bool {
		return chooseCVSSSource(vuln) == ""
	})
}

// CollectAllCVEIDs returns deduplicated CVE IDs from all vulnerabilities in results.
func CollectAllCVEIDs(results []any) []string {
	return collectCVEIDs(results, func(_ map[string]any) bool { return true })
}

// collectCVEIDs iterates all vulnerabilities across results and returns deduplicated
// CVE IDs for which include returns true.
func collectCVEIDs(results []any, include func(map[string]any) bool) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, r := range results {
		resultMap, _ := r.(map[string]any)
		if resultMap == nil {
			continue
		}
		vulns, _ := resultMap["Vulnerabilities"].([]any)
		for _, v := range vulns {
			vuln, _ := v.(map[string]any)
			if vuln == nil || !include(vuln) {
				continue
			}
			id, _ := vuln["VulnerabilityID"].(string)
			if _, alreadySeen := seen[id]; id != "" && !alreadySeen {
				seen[id] = struct{}{}
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

	vectorStr := resolveVector(vuln, vulnID, nvdVectors, ro.FetchMissingCVSS)
	if vectorStr == "" {
		if ro.ForceCtxRating {
			setContextualMetrics(vuln, contextualMetrics{
				TemporalRating:      severity,
				EnvironmentalRating: severity,
			})
		}
		return
	}

	epssEntry, hasEPSS := epssData[vulnID]
	opts := ro.Opts
	opts.E = resolveExploitMaturity(ro.Opts.E, ro.UseEPSS, epssEntry, hasEPSS)

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
	if ro.UseEPSS && hasEPSS {
		metrics.EpssScore = &epssEntry.Score
		metrics.EpssPercentile = &epssEntry.Percentile
		if epssEntry.Date != "" {
			metrics.EpssDate = &epssEntry.Date
		}
	}
	setContextualMetrics(vuln, metrics)
}

// resolveVector returns the CVSS vector for the vulnerability, falling back to
// the NVD-fetched vector if the report has none and fetchMissingCVSS is enabled.
func resolveVector(vuln map[string]any, vulnID string, nvdVectors map[string]string, fetchMissingCVSS bool) string {
	if v := getCVSSVectorFromVuln(vuln); v != "" {
		return v
	}
	if fetchMissingCVSS {
		return nvdVectors[vulnID]
	}
	return ""
}

// resolveExploitMaturity returns the exploit maturity value to use. If EPSS is
// enabled and data is available, it derives the value from the EPSS score.
// Otherwise it falls back to the configured value, defaulting to "X" (not defined).
func resolveExploitMaturity(configured string, useEPSS bool, epssEntry epss.Data, hasEPSS bool) string {
	if useEPSS && hasEPSS {
		return epss.EPSSToExploitMaturity(epssEntry.Score)
	}
	if configured == "" {
		return "X"
	}
	return configured
}
