package worker

import (
	"encoding/json"
	"math"
	"strings"
)

const (
	aiModelName       = "logistic_regression_v1"
	aiBias            = -2.25
	aiYARAWeight      = 1.35
	aiAPIWeight       = 0.38
	aiEntropyWeight   = 1.05
	aiEntropyBaseline = 6.5
)

type aiScoringResult struct {
	Score    int               `json:"score"`
	Model    string            `json:"model"`
	Features aiScoringFeatures `json:"features"`
}

type aiScoringFeatures struct {
	YARACount          int     `json:"yara_count"`
	SuspiciousAPICount int     `json:"suspicious_api_count"`
	MaxEntropy         float64 `json:"max_entropy"`
}

func scoreAIAnalyzerOutput(output *analyzerOutput) aiScoringResult {
	features := aiScoringFeatures{}
	if output != nil {
		features = aiFeaturesForResults(output.Results)
	}

	return aiScoringResult{
		Score:    aiScoreFromFeatures(features),
		Model:    aiModelName,
		Features: features,
	}
}

func aiFeaturesForResults(results []analyzerModuleResult) aiScoringFeatures {
	maxEntropy, _ := entropyStats(results)

	return aiScoringFeatures{
		YARACount:          yaraMatchCount(results),
		SuspiciousAPICount: suspiciousAPICount(results),
		MaxEntropy:         roundFloat(maxEntropy, 4),
	}
}

func aiScoreFromFeatures(features aiScoringFeatures) int {
	logit := aiBias
	logit += aiYARAWeight * math.Min(float64(features.YARACount), 5)
	logit += aiAPIWeight * math.Min(float64(features.SuspiciousAPICount), 10)

	if features.MaxEntropy > aiEntropyBaseline {
		logit += aiEntropyWeight * (features.MaxEntropy - aiEntropyBaseline)
	}

	probability := 1 / (1 + math.Exp(-logit))
	return clampScore(int(math.Round(probability * 100)))
}

func annotateAnalyzerResult(raw json.RawMessage, ruleScore int, aiResult aiScoringResult) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw
	}

	payload["scoring"] = map[string]any{
		"rule_score": ruleScore,
		"ai_score":   aiResult.Score,
		"ai_model": map[string]any{
			"name":     aiResult.Model,
			"features": aiResult.Features,
		},
	}

	annotated, err := json.Marshal(payload)
	if err != nil {
		return raw
	}

	return annotated
}

func yaraMatchCount(results []analyzerModuleResult) int {
	count := 0
	for _, module := range results {
		if sameToken(module.Analyzer, "yara") {
			count += len(yaraMatchSeverities(module))
		}
	}
	return count
}

func suspiciousAPICount(results []analyzerModuleResult) int {
	seen := map[string]struct{}{}

	for _, module := range results {
		imports, ok := module.Metadata["imports"].([]any)
		if !ok {
			continue
		}

		for _, item := range imports {
			importEntry, ok := item.(map[string]any)
			if !ok {
				continue
			}

			functions, ok := importEntry["functions"].([]any)
			if !ok {
				continue
			}

			for _, functionItem := range functions {
				function, ok := functionItem.(map[string]any)
				if !ok {
					continue
				}

				name := normalizeAPIName(stringValue(function["name"]))
				if name == "" || !isSuspiciousAPI(name) {
					continue
				}
				seen[name] = struct{}{}
			}
		}
	}

	return len(seen)
}

func normalizeAPIName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "__imp_")
	if at := strings.Index(name, "@"); at >= 0 {
		name = name[:at]
	}
	return name
}

func isSuspiciousAPI(name string) bool {
	if _, ok := suspiciousAPIs[name]; ok {
		return true
	}

	if strings.HasSuffix(name, "a") || strings.HasSuffix(name, "w") {
		_, ok := suspiciousAPIs[name[:len(name)-1]]
		return ok
	}

	return false
}

func roundFloat(value float64, places int) float64 {
	scale := math.Pow(10, float64(places))
	return math.Round(value*scale) / scale
}

var suspiciousAPIs = map[string]struct{}{
	"connect":              {},
	"createremotethread":   {},
	"getprocaddress":       {},
	"httpopenrequest":      {},
	"internetopen":         {},
	"internetopenurl":      {},
	"isdebuggerpresent":    {},
	"loadlibrary":          {},
	"ntunmapviewofsection": {},
	"openprocess":          {},
	"regsetvalue":          {},
	"shellexecute":         {},
	"urldownloadtofile":    {},
	"virtualalloc":         {},
	"virtualallocex":       {},
	"virtualprotect":       {},
	"winexec":              {},
	"writeprocessmemory":   {},
	"wsastartup":           {},
}
