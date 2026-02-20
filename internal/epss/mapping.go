package epss

const (
	ThresholdUnproven    = 0.05
	ThresholdPoC        = 0.20
	ThresholdFunctional = 0.50
)

// EPSSToExploitMaturity maps an EPSS score (0-1) to CVSS v3 Exploit Code Maturity (U, P, F, H).
func EPSSToExploitMaturity(score float64) string {
	switch {
	case score < 0:
		return "X"
	case score < ThresholdUnproven:
		return "U"
	case score < ThresholdPoC:
		return "P"
	case score < ThresholdFunctional:
		return "F"
	default:
		return "H"
	}
}
