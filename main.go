package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

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
	confReq := flag.String("cr", "", "Confidentiality Requirement (X, L, M, H)")
	integReq := flag.String("ir", "", "Integrity Requirement (X, L, M, H)")
	availReq := flag.String("ar", "", "Availability Requirement (X, L, M, H)")
	modAttackVec := flag.String("mav", "", "Modified Attack Vector (X, N, A, L, P)")
	modAttackComp := flag.String("mac", "", "Modified Attack Complexity (X, L, H)")
	modPrivReq := flag.String("mpr", "", "Modified Privileges Required (X, N, L, H)")
	modUserInt := flag.String("mui", "", "Modified User Interaction (X, N, R)")
	modConf := flag.String("mc", "", "Modified Confidentiality (X, L, H)")
	modInteg := flag.String("mi", "", "Modified Integrity (X, L, H)")
	modAvail := flag.String("ma", "", "Modified Availability (X, L, H)")
	// General non-CVSS related flags
	smartApply := flag.Bool("smart", false, "Smartly apply environmental metrics only if the environmental score would be lowered, does not affect CR/IR/AR.")
	forceCtxRating := flag.Bool("force-ctx-rating", false, "Force a contextual rating based on what Trivy gave even if CVSS doesn't exist from Trivy")

	flag.Parse()

	opts := cvss.MetricsOptions{
		E: *modExploitCodeMaturity, RL: *modRemediationLevel, RC: *modReportConf,
		CR: *confReq, IR: *integReq, AR: *availReq,
		MAV: *modAttackVec, MAC: *modAttackComp, MPR: *modPrivReq, MUI: *modUserInt,
		MC: *modConf, MI: *modInteg, MA: *modAvail,
		Smart: *smartApply,
	}

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

			// If no VectorStr found, we update the contextual ratings to match that of the original one provided by trivy
			if vectorStr == "" {
        if *forceCtxRating {
          metrics := ContextualMetricsResults{
            Vector:              "",
            TemporalScore:       0,
            TemporalRating:      vuln.Severity,
            EnvironmentalScore:  0,
            EnvironmentalRating: vuln.Severity,
          }
          updateContextualMetrics(vuln, metrics)
        }
        continue
      }

			// Apply Environmental Metrics to the base vector
			newVectorStr, err := cvss.ApplyMetrics(vectorStr, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error applying environmental metrics for %s: %v\n", vuln.VulnerabilityID, err)
			}

			// Calculate Environmental Score and Severity based on the user-input environmental metric values
			_, tempScore, envScore, err := cvss.CalculateScores(newVectorStr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error calculating scores for %s: %v\n", vuln.VulnerabilityID, err)
				continue
			}

			metrics := ContextualMetricsResults{
        Vector:              newVectorStr,
        TemporalScore:       tempScore,
        TemporalRating:      cvss.CalculateSeverityRating(tempScore),
        EnvironmentalScore:  envScore,
        EnvironmentalRating: cvss.CalculateSeverityRating(envScore),
      }
      
      updateContextualMetrics(vuln, metrics)
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

func updateContextualMetrics(vuln *types.DetectedVulnerability, results ContextualMetricsResults) {
	// Store the results in the Custom field of the vulnerability which trivy conveniently provides as part of the Struct
	if vuln.Custom == nil {
		vuln.Custom = make(map[string]any)
	}
	if customMap, ok := vuln.Custom.(map[string]any); ok {
		customMap["ContextualMetrics"] = results
	}
}