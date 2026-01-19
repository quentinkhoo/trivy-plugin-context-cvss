// TODO: Add support for CVSS v2 and v4
// In CVSS 3.0/3.1, Environmental metrics like MA, MC, MI can be applied to the base vector.
// By modifying the base vector with the provided Temporal/Environmental metrics, we can compute a Temporal/Environmental Score.
// If you're not familiar with contextual metrics like Environmental Metrics 
// refer to: https://www.first.org/cvss/v3-1/specification-document#Environmental-Metrics

package cvss

import (
	"fmt"
	"strings"
)

// MetricsOptions defines the values to apply to the vector.
type MetricsOptions struct {
	E, RL, RC                      string
	CR, IR, AR                     string
	MAV, MAC, MPR, MUI, MC, MI, MA string
	Smart                          bool
}

// severityWeights is private to this package.
// It defines the hierarchy of severity for Smart Clamping.
var severityWeights = map[string]map[string]int{
	"AV": {"N": 4, "A": 3, "L": 2, "P": 1},
	"AC": {"L": 2, "H": 1},
	"PR": {"N": 3, "L": 2, "H": 1},
	"UI": {"N": 2, "R": 1},
	"C":  {"H": 3, "L": 2, "N": 1},
	"I":  {"H": 3, "L": 2, "N": 1},
	"A":  {"H": 3, "L": 2, "N": 1},
}

var envToBaseMap = map[string]string{
	"MAV": "AV", 
	"MAC": "AC", 
	"MPR": "PR", 
	"MUI": "UI",
	"MC": "C", 
	"MI": "I", 
	"MA": "A",
}

// ApplyMetrics takes a base vector and applies the given options.
func ApplyMetrics(baseVectorStr string, opts MetricsOptions) (string, error) {
	// We can call GetCVSSVersion directly because we are in package cvss
	cvssVersion, err := GetCVSSVersion(baseVectorStr)
	if err != nil {
		return "", err
	}
	
	// Currently only supporting 3.0/3.1 for modification
	if cvssVersion != "CVSS 3.0" && cvssVersion != "CVSS 3.1" {
		return baseVectorStr, nil
	}

	var sb strings.Builder
	sb.WriteString(baseVectorStr)

	baseMetrics := parseBaseVector(baseVectorStr)

	temporals := []struct{ Key, Val string }{
		{"E", opts.E}, {"RL", opts.RL}, {"RC", opts.RC},
	}
	for _, m := range temporals {
		if m.Val != "" {
			sb.WriteString(fmt.Sprintf("/%s:%s", m.Key, strings.ToUpper(m.Val)))
		}
	}

	environmentals := []struct{ Key, Val string }{
		{"CR", opts.CR}, {"IR", opts.IR}, {"AR", opts.AR},
		{"MAV", opts.MAV}, {"MAC", opts.MAC}, {"MPR", opts.MPR}, {"MUI", opts.MUI},
		{"MC", opts.MC}, {"MI", opts.MI}, {"MA", opts.MA},
	}

	for _, m := range environmentals {
		if m.Val == "" {
			continue
		}
		
		upperVal := strings.ToUpper(m.Val)
		
		if shouldApplyMetric(m.Key, upperVal, baseMetrics, opts.Smart) {
			sb.WriteString(fmt.Sprintf("/%s:%s", m.Key, upperVal))
		}
	}

	return sb.String(), nil
}

// internal helper to check if we should apply the modified metric based on "Smart" mode
// for example, we don't want to apply a Modified Availability of "Low" if the Base Availability is "None"
func shouldApplyMetric(metricKey, metricVal string, baseMetrics map[string]string, smart bool) bool {

	// Not Defined, I mean who uses this? 
	if metricVal == "X" {
		return true
	}

	if !smart { 
		return true 
	}

	// These reflect business criticality and should never be suppressed by "Smart" mode.
	if metricKey == "CR" || metricKey == "IR" || metricKey == "AR" { 
		return true 
	}
	
	// We want to ensure that a Modified metric does not imply a higher severity 
	// than the Base metric allows (which would be illogical).
	baseKey, hasBase := envToBaseMap[metricKey]
	if !hasBase { 
		return true 
	}

	weightMap, hasWeights := severityWeights[baseKey]
	if !hasWeights {
		return true
	}

	baseVal, hasBaseVal := baseMetrics[baseKey]
	if !hasBaseVal {
		// If Base vector is malformed/missing this key, we can't compare. Default to apply.
		return true
	}

	// We check if the keys exist in our weight map to avoid panics on invalid input strings
	baseWeight, baseOk := weightMap[baseVal]
	modWeight, modOk := weightMap[metricVal]

	if baseOk && modOk {
		// If Modified Weight > Base Weight, the environment is making the vulnerability 
		// "worse" than the code allows. We skip this to clamp the score.
		if modWeight > baseWeight {
			return false
		}
	}
	return true
}

// parseBaseVector splits a CVSS Vector string "CVSS:3.1/AV:N/AC:L..." into a map {"AV":"N", "AC":"L"}
func parseBaseVector(vector string) map[string]string {
	m := make(map[string]string)

	if strings.HasPrefix(vector, "CVSS:3.1/") {
		vector = strings.TrimPrefix(vector, "CVSS:3.1/")
	} else if strings.HasPrefix(vector, "CVSS:3.0/") {
		vector = strings.TrimPrefix(vector, "CVSS:3.0/")
	}

	parts := strings.Split(vector, "/")
	for _, part := range parts {
		kv := strings.Split(part, ":")
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}