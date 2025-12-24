package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"trivy-plugin-context-cvss/cvss"

	"github.com/aquasecurity/trivy/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

type ContextualMetricsResults struct {
	Vector   						string  `json:",omitempty"`
	TemporalScore       float64 `json:"TemporalScore"`
	TemporalRating 			string  `json:",omitempty"`
	EnvironmentalScore float64 `json:"EnvironmentalScore"`
	EnvironmentalRating string  `json:",omitempty"`
}

// TODO: Enhance this to support CVSS v2 and v4
func main() {
	//Temporal Metrics flags
	modExploitCodeMaturity := flag.String("e", "", "Modified Exploit Code Maturity (X, U, P, F, H)")
	modRemediationLevel := flag.String("rl", "", "Modified Remediation Level (X, O, T, W, U)")
	modReportConf := flag.String("rc", "", "Modified Report Confidence (X, U, R, C)")
	// Environmental Metrics flags
	modAttackVec := flag.String("mav", "", "Modified Attack Vector (X, N, A, L, P)")
	modAttackComp := flag.String("mac", "", "Modified Attack Complexity (X, L, H)")
	modPrivReq := flag.String("mpr", "", "Modified Privileges Required (X, N, L, H)")
	modUserInt := flag.String("mui", "", "Modified User Interaction (X, N, R)")
	modConf := flag.String("mc", "", "Modified Confidentiality (X, L, H)")
	modInteg := flag.String("mi", "", "Modified Integrity (X, L, H)")
	modAvail := flag.String("ma", "", "Modified Availability (X, L, H)")
	// General non-CVSS related flags
	smartApply := flag.Bool("smart", true, "Smartly apply environmental metrics only if the environmental score would be lowered")

	flag.Parse()

	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Errorf("failed to read from stdin: %w", err))
	}

	var report types.Report
	if err := json.Unmarshal(inputData, &report); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}

	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			vuln := &report.Results[i].Vulnerabilities[j]

			// We extract out the CVSS vector from the chosen source
			var vectorStr string
			if cvssSource := chooseCVSSSource(*vuln); cvssSource != "" {
				vectorStr = vuln.CVSS[cvssSource].V3Vector
			}

			if vectorStr == "" {
				continue
			}

			// Apply Environmental Metrics to the base vector
			newVectorStr, err := applyMetrics(vectorStr, *modExploitCodeMaturity, *modRemediationLevel, *modReportConf, *modAttackVec, *modAttackComp, *modPrivReq, *modUserInt, *modConf, *modInteg, *modAvail, *smartApply)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error applying environmental metrics for %s: %v\n", vuln.VulnerabilityID, err)
			}

			// Calculate Environmental Score and Severity based on the user-input environmental metric values
			_, tempScore, envScore, err := cvss.CalculateScores(newVectorStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error calculating scores for %s: %v\n", vuln.VulnerabilityID, err)
				continue
			}

			tempSeverityRating := cvss.CalculateSeverityRating(tempScore)
			envSeverityRating := cvss.CalculateSeverityRating(envScore)
			contextualMetricsResults := ContextualMetricsResults{
				Vector: newVectorStr,
				TemporalScore:       tempScore,
				TemporalRating:      tempSeverityRating,
				EnvironmentalScore:  envScore,
				EnvironmentalRating: envSeverityRating,
			}

			// Store the results in the Custom field of the vulnerability which trivy conveniently provides as part of the Struct
			if vuln.Custom == nil {
				vuln.Custom = make(map[string]any)
			}
			if customMap, ok := vuln.Custom.(map[string]any); ok {
				customMap["ContextualMetrics"] = contextualMetricsResults
			}
		}
	}

	output, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(output))
}

// TODO: Improve the priority list
var defaultCVSSSources = []dbTypes.SourceID{
	"redhat",
	"ghsa",
	"bitnami",
	"ubuntu",
	"alpine",
	"amazon",
	"oracle",
	"nvd",
}

// A CVSS source could be something like 'nvd', 'redhat', 'ghsa', etc, which refers to the origin of the CVSS vector.
// Different sources may provide different CVSS vectors for the same vulnerability.
// We want to select the best CVSS Source based on the following priority:
// 1. The 'SeveritySource' field (if it exists and has a vector).
// 2. The defaultCVSSSources priority list.
// 3. Any available source with a vector.
func chooseCVSSSource(vuln types.DetectedVulnerability) dbTypes.SourceID {
	if len(vuln.CVSS) == 0 {
		return ""
	}

	if source := vuln.SeveritySource; source != "" {
		if cvssData, ok := vuln.CVSS[source]; ok && cvssData.V3Vector != "" {
			return source
		}
	}

	for _, source := range defaultCVSSSources {
		if cvssData, ok := vuln.CVSS[source]; ok && cvssData.V3Vector != "" {
			return source
		}
	}

	for source, cvssData := range vuln.CVSS {
		if cvssData.V3Vector != "" {
			return source
		}
	}

	return ""
}

// TODO: Add support for CVSS v2 and v4
// In CVSS 3.0/3.1, Environmental metrics like MA, MC, MI can be applied to the base vector.
// By modifying the base vector with the provided Temporal/Environmental metrics, we can compute a Temporal/Environmental Score.
// If you're not familiar with contextual metrics like Environmental Metrics 
// refer to: https://www.first.org/cvss/v3-1/specification-document#Environmental-Metrics
func applyMetrics(baseVector, e, rl, rc, mav, mac, mpr, mui, mc, mi, ma string, smart bool) (string, error) {
	var sb strings.Builder
	sb.WriteString(baseVector)

	cvssVersion, err := cvss.GetCVSSVersion(baseVector)
	if err != nil {
		return "", err
	}

	if cvssVersion == "CVSS 3.0" || cvssVersion == "CVSS 3.1" {
		temporals := []struct {
			metric string
			value  string
		}{
			{"E", e}, {"RL", rl}, {"RC", rc},
		}
		
		for _, m := range temporals {
			if m.value != "" {
				sb.WriteString(fmt.Sprintf("/%s:%s", m.metric, strings.ToUpper(m.value)))
			}
		}

		environmentals := []struct {
			metric string
			value  string
		}{
			{"MAV", mav}, {"MAC", mac}, {"MPR", mpr}, {"MUI", mui}, {"MA", ma}, {"MC", mc}, {"MI", mi},
		}

		for _, m := range environmentals {
			if m.value == "" {
				continue
			}

			upperVal := strings.ToUpper(m.value)
			shouldAppend := true

			if smart {
				improved, _ := checkIfEnvRatingImproved(sb.String(), m.metric, upperVal)
				shouldAppend = improved
			}

			if shouldAppend {
				sb.WriteString(fmt.Sprintf("/%s:%s", m.metric, upperVal))
			}
		}
  }

	return sb.String(), nil
}

func checkIfEnvRatingImproved(baseVector, metric, value string) (bool, error) {
	modifiedVectorStr := baseVector + fmt.Sprintf("/%s:%s", metric, value)
	baseScore, _, envScore, err := cvss.CalculateScores(modifiedVectorStr)
	if err != nil {
		return false, err
	}
	return envScore < baseScore, nil
}