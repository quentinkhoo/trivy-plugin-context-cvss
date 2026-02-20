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
	"MAV": "AV", "MAC": "AC", "MPR": "PR", "MUI": "UI",
	"MC": "C", "MI": "I", "MA": "A",
}

// ApplyMetrics takes a base vector and applies the given options.
func ApplyMetrics(baseVectorStr string, opts MetricsOptions) (string, error) {
	cvssVersion, err := GetCVSSVersion(baseVectorStr)
	if err != nil {
		return "", err
	}
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

func shouldApplyMetric(metricKey, metricVal string, baseMetrics map[string]string, smart bool) bool {
	if metricVal == "X" {
		return true
	}
	if !smart {
		return true
	}
	if metricKey == "CR" || metricKey == "IR" || metricKey == "AR" {
		return true
	}
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
		return true
	}
	baseWeight, baseOk := weightMap[baseVal]
	modWeight, modOk := weightMap[metricVal]
	if baseOk && modOk && modWeight > baseWeight {
		return false
	}
	return true
}

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
