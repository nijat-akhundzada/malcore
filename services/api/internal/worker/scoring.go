package worker

import (
	"math"
	"strings"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

const maxScore = 100

func scoreAnalyzerOutput(output *analyzerOutput) int {
	if output == nil {
		return 0
	}

	score := 0
	score += scoreYARAHits(output.Results)
	score += scoreEntropy(output.Results)
	score += scoreMacros(output.Results)
	score += scoreGenericFindings(output.Results)

	return clampScore(score)
}

func scoreYARAHits(results []analyzerModuleResult) int {
	score := 0
	matchCount := 0

	for _, module := range results {
		if !sameToken(module.Analyzer, "yara") {
			continue
		}

		severities := yaraMatchSeverities(module)
		matchCount += len(severities)

		for _, severity := range severities {
			score = max(score, scoreForSeverity(severity))
		}
	}

	if matchCount > 1 {
		score += min((matchCount-1)*5, 15)
	}

	return min(score, 95)
}

func yaraMatchSeverities(module analyzerModuleResult) []string {
	matches, ok := module.Metadata["matches"].([]any)
	if ok && len(matches) > 0 {
		severities := make([]string, 0, len(matches))
		for _, item := range matches {
			match, ok := item.(map[string]any)
			if !ok {
				continue
			}

			severities = append(severities, stringValue(match["severity"]))
		}
		return severities
	}

	severities := make([]string, 0, len(module.Findings))
	for _, finding := range module.Findings {
		if sameToken(finding.Type, "yara_match") {
			severities = append(severities, finding.Severity)
		}
	}
	return severities
}

func scoreEntropy(results []analyzerModuleResult) int {
	highestEntropy, highEntropySections := entropyStats(results)

	score := 0
	switch {
	case highestEntropy >= 7.8:
		score = 70
	case highestEntropy >= 7.2:
		score = 50
	}

	if highEntropySections > 1 {
		score += 10
	}

	return min(score, 80)
}

func entropyStats(results []analyzerModuleResult) (float64, int) {
	highestEntropy := 0.0
	highEntropySections := 0

	for _, module := range results {
		moduleHasSectionMetadata := false
		sections, ok := module.Metadata["sections"].([]any)
		if ok {
			moduleHasSectionMetadata = true
			for _, item := range sections {
				section, ok := item.(map[string]any)
				if !ok {
					continue
				}

				entropy, ok := floatValue(section["entropy"])
				if !ok {
					continue
				}

				highestEntropy = math.Max(highestEntropy, entropy)
				if entropy >= 7.2 {
					highEntropySections++
				}
			}
		}

		if moduleHasSectionMetadata {
			continue
		}

		for _, finding := range module.Findings {
			if !sameToken(finding.Type, "high_entropy_section") {
				continue
			}

			if entropy, ok := floatValue(finding.Entropy); ok {
				highestEntropy = math.Max(highestEntropy, entropy)
			}
			highEntropySections++
		}
	}

	return highestEntropy, highEntropySections
}

func scoreMacros(results []analyzerModuleResult) int {
	score := 0
	suspiciousKeywords := 0

	for _, module := range results {
		hasMacros := boolValue(module.Metadata["has_macros"])
		if hasMacros {
			score = max(score, 70)
		}

		keywords, ok := module.Metadata["suspicious_keywords"].([]any)
		if ok {
			suspiciousKeywords += len(keywords)
		}

		for _, finding := range module.Findings {
			switch {
			case sameToken(finding.Type, "office_macros"):
				score = max(score, 70)
			case !ok && sameToken(finding.Type, "office_suspicious_keyword"):
				suspiciousKeywords++
			}
		}
	}

	if suspiciousKeywords > 0 {
		score += min(suspiciousKeywords*10, 20)
	}

	return min(score, 90)
}

func scoreGenericFindings(results []analyzerModuleResult) int {
	score := 0

	for _, module := range results {
		for _, finding := range module.Findings {
			if hasSpecificScoringRule(finding.Type) {
				continue
			}

			score = max(score, scoreForSeverity(finding.Severity))
		}
	}

	return score
}

func hasSpecificScoringRule(findingType string) bool {
	switch strings.ToLower(strings.TrimSpace(findingType)) {
	case "yara_match", "high_entropy_section", "office_macros", "office_suspicious_keyword":
		return true
	default:
		return false
	}
}

func scoreForSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 50
	case "low":
		return 15
	default:
		return 0
	}
}

func riskLevelForScore(score int) jobs.RiskLevel {
	switch {
	case score >= 80:
		return jobs.RiskCritical
	case score >= 60:
		return jobs.RiskHigh
	case score >= 30:
		return jobs.RiskMedium
	default:
		return jobs.RiskLow
	}
}

func finalScore(ruleScore int, aiScore int) int {
	weighted := (0.6 * float64(clampScore(ruleScore))) + (0.4 * float64(clampScore(aiScore)))
	return clampScore(int(math.Round(weighted)))
}

func floatValue(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case jsonNumber:
		number, err := v.Float64()
		return number, err == nil
	default:
		return 0, false
	}
}

type jsonNumber interface {
	Float64() (float64, error)
}

func boolValue(value any) bool {
	v, ok := value.(bool)
	return ok && v
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}

func sameToken(left string, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func clampScore(score int) int {
	return max(0, min(score, maxScore))
}
