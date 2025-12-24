package cvss

import (
	"fmt"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

//Given a Vector String, determine the CVSS Version and validate the vector.
// It could either be CVSS 2.0, 3.0, 3.1 or 4.0
func GetCVSSVersion(vector string) (string, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0"):
		_, err := gocvss40.ParseVector(vector)
		if err != nil {
			return "", fmt.Errorf("invalid CVSS 4.0 vector: %w", err)
		}
		return "CVSS 4.0", nil

	case strings.HasPrefix(vector, "CVSS:3.1"):
		_, err := gocvss31.ParseVector(vector)
		if err != nil {
			return "", fmt.Errorf("invalid CVSS 3.1 vector: %w", err)
		}
		return "CVSS 3.1", nil

	case strings.HasPrefix(vector, "CVSS:3.0"):
		_, err := gocvss30.ParseVector(vector)
		if err != nil {
			return "", fmt.Errorf("invalid CVSS 3.0 vector: %w", err)
		}
		return "CVSS 3.0", nil

	default:
		_, err := gocvss20.ParseVector(vector)
		if err != nil {
			return "", fmt.Errorf("unknown or invalid vector format: %w", err)
		}
		return "CVSS 2.0", nil
	}
}

// Given a CVSS vector string, calculate and return the Base, Temporal, and Environmental scores.
// For CVSS 4.0, unfrotunately the library only calculates a single Score()
// TODO: update the code when the library supports separate scores for CVSS 4.0/does something smarter for CVSS 4.0
func CalculateScores(vector string) (float64, float64, float64, error) {
	cvssVersion, err := GetCVSSVersion(vector)
	if err != nil {
		return 0, 0, 0, err
	}

	switch cvssVersion {
	case "CVSS 4.0":
		cvss40, _ := gocvss40.ParseVector(vector)
		return cvss40.Score(), cvss40.Score(), cvss40.Score(), nil
	case "CVSS 3.1":
		cvss31, _ := gocvss31.ParseVector(vector)
		return cvss31.BaseScore(), cvss31.TemporalScore(), cvss31.EnvironmentalScore(), nil
	case "CVSS 3.0":
		cvss30, _ := gocvss30.ParseVector(vector)
		return cvss30.BaseScore(), cvss30.TemporalScore(), cvss30.EnvironmentalScore(), nil
	case "CVSS 2.0":
		cvss20, _ := gocvss20.ParseVector(vector)
		return cvss20.BaseScore(), cvss20.TemporalScore(), cvss20.EnvironmentalScore(), nil
	default:
		return 0, 0, 0, fmt.Errorf("unsupported CVSS version: %s", cvssVersion)
	}
}

// Given a CVSS score, return the corresponding severity rating.
func CalculateSeverityRating(score float64) string {
	if score == 0.0 {
		return "NONE"
	}
	if score >= 0.1 && score <= 3.9 {
		return "LOW"
	}
	if score >= 4.0 && score <= 6.9 {
		return "MEDIUM"
	}
	if score >= 7.0 && score <= 8.9 {
		return "HIGH"
	}
	if score >= 9.0 && score <= 10.0 {
		return "CRITICAL"
	}
	return "UNKNOWN"
}