package flags

import (
	"flag"
	"os"

	"trivy-plugin-context-cvss/internal/cvss"
)

// RunOptions holds CVSS options and feature flags for a run.
type RunOptions struct {
	Opts           cvss.MetricsOptions
	ForceCtxRating bool
	UseEPSS        bool
	FetchCVSS      bool
	NvdAPIKey      string
}

// Parse parses CLI flags and returns run options.
func Parse() RunOptions {
	modExploitCodeMaturity := flag.String("e", "", "Modified Exploit Code Maturity (X, U, P, F, H)")
	modRemediationLevel := flag.String("rl", "", "Modified Remediation Level (X, O, T, W, U)")
	modReportConf := flag.String("rc", "", "Modified Report Confidence (X, U, R, C)")
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
	smartApply := flag.Bool("smart", false, "Smartly apply environmental metrics only if the environmental score would be lowered, does not affect CR/IR/AR.")
	forceCtxRating := flag.Bool("force-ctx-rating", false, "Force a contextual rating based on what Trivy gave even if CVSS doesn't exist from Trivy")
	useEPSS := flag.Bool("epss", false, "Fetch EPSS per CVE and set Exploit Code Maturity (E) from EPSS score bands")
	fetchCVSS := flag.Bool("fetch-cvss", false, "For CVEs with no CVSS source, fetch CVSS from NVD (rate limited without API key)")
	nvdAPIKey := flag.String("nvd-api-key", "", "NVD API key for higher rate limits (50/30s); or set NVD_API_KEY env")
	flag.Parse()
	apiKey := *nvdAPIKey
	if apiKey == "" {
		apiKey = os.Getenv("NVD_API_KEY")
	}
	return RunOptions{
		Opts: cvss.MetricsOptions{
			E: *modExploitCodeMaturity, RL: *modRemediationLevel, RC: *modReportConf,
			CR: *confReq, IR: *integReq, AR: *availReq,
			MAV: *modAttackVec, MAC: *modAttackComp, MPR: *modPrivReq, MUI: *modUserInt,
			MC: *modConf, MI: *modInteg, MA: *modAvail,
			Smart: *smartApply,
		},
		ForceCtxRating: *forceCtxRating,
		UseEPSS:        *useEPSS,
		FetchCVSS:      *fetchCVSS,
		NvdAPIKey:      apiKey,
	}
}
