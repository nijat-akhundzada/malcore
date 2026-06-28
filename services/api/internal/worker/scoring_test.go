package worker

import (
	"testing"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

func TestScoreAnalyzerOutputUsesYARAHits(t *testing.T) {
	score := scoreAnalyzerOutput(&analyzerOutput{
		Results: []analyzerModuleResult{
			{
				Analyzer: "yara",
				Metadata: map[string]any{
					"matches": []any{
						map[string]any{"rule": "SuspiciousRule", "severity": "high"},
					},
				},
			},
		},
	})

	if score != 80 {
		t.Fatalf("expected high YARA hit to score 80, got %d", score)
	}
	if riskLevelForScore(score) != jobs.RiskHigh {
		t.Fatalf("expected high risk, got %q", riskLevelForScore(score))
	}
}

func TestScoreAnalyzerOutputUsesPEEntropy(t *testing.T) {
	score := scoreAnalyzerOutput(&analyzerOutput{
		Results: []analyzerModuleResult{
			{
				Analyzer: "pe",
				Metadata: map[string]any{
					"sections": []any{
						map[string]any{"name": ".text", "entropy": 7.4},
					},
				},
			},
		},
	})

	if score != 50 {
		t.Fatalf("expected high entropy section to score 50, got %d", score)
	}
	if riskLevelForScore(score) != jobs.RiskMedium {
		t.Fatalf("expected medium risk, got %q", riskLevelForScore(score))
	}
}

func TestScoreAnalyzerOutputUsesOfficeMacros(t *testing.T) {
	score := scoreAnalyzerOutput(&analyzerOutput{
		Results: []analyzerModuleResult{
			{
				Analyzer: "office",
				Metadata: map[string]any{
					"has_macros": true,
					"suspicious_keywords": []any{
						map[string]any{"keyword": "AutoOpen"},
					},
				},
			},
		},
	})

	if score != 80 {
		t.Fatalf("expected macro with suspicious keyword to score 80, got %d", score)
	}
	if riskLevelForScore(score) != jobs.RiskHigh {
		t.Fatalf("expected high risk, got %q", riskLevelForScore(score))
	}
}

func TestScoreAnalyzerOutputCombinesRulesAndCapsAtOneHundred(t *testing.T) {
	score := scoreAnalyzerOutput(&analyzerOutput{
		Results: []analyzerModuleResult{
			{
				Analyzer: "yara",
				Metadata: map[string]any{
					"matches": []any{
						map[string]any{"rule": "CriticalRule", "severity": "critical"},
					},
				},
			},
			{
				Analyzer: "office",
				Metadata: map[string]any{
					"has_macros": true,
				},
			},
		},
	})

	if score != 100 {
		t.Fatalf("expected score cap at 100, got %d", score)
	}
	if riskLevelForScore(score) != jobs.RiskCritical {
		t.Fatalf("expected critical risk, got %q", riskLevelForScore(score))
	}
}

func TestScoreAnalyzerOutputKeepsGenericSeverityFallback(t *testing.T) {
	score := scoreAnalyzerOutput(&analyzerOutput{
		Results: []analyzerModuleResult{
			{
				Analyzer: "scripts",
				Findings: []analyzerFinding{
					{Type: "script_dynamic_execution", Severity: "medium"},
				},
			},
		},
	})

	if score != 50 {
		t.Fatalf("expected generic medium finding to score 50, got %d", score)
	}
}

func TestScoreAIAnalyzerOutputUsesLogisticFeatures(t *testing.T) {
	result := scoreAIAnalyzerOutput(&analyzerOutput{
		Results: []analyzerModuleResult{
			{
				Analyzer: "yara",
				Metadata: map[string]any{
					"matches": []any{
						map[string]any{"rule": "RuleOne", "severity": "high"},
						map[string]any{"rule": "RuleTwo", "severity": "medium"},
					},
				},
			},
			{
				Analyzer: "pe",
				Metadata: map[string]any{
					"sections": []any{
						map[string]any{"name": ".text", "entropy": 7.8},
					},
					"imports": []any{
						map[string]any{
							"dll": "kernel32.dll",
							"functions": []any{
								map[string]any{"name": "VirtualAlloc"},
								map[string]any{"name": "CreateRemoteThread"},
								map[string]any{"name": "GetProcAddress"},
							},
						},
						map[string]any{
							"dll": "urlmon.dll",
							"functions": []any{
								map[string]any{"name": "URLDownloadToFileA"},
							},
						},
					},
				},
			},
		},
	})

	if result.Model != aiModelName {
		t.Fatalf("expected model %q, got %q", aiModelName, result.Model)
	}
	if result.Features.YARACount != 2 {
		t.Fatalf("expected 2 YARA hits, got %d", result.Features.YARACount)
	}
	if result.Features.SuspiciousAPICount != 4 {
		t.Fatalf("expected 4 suspicious APIs, got %d", result.Features.SuspiciousAPICount)
	}
	if result.Features.MaxEntropy != 7.8 {
		t.Fatalf("expected max entropy 7.8, got %f", result.Features.MaxEntropy)
	}
	if result.Score != 97 {
		t.Fatalf("expected logistic AI score 97, got %d", result.Score)
	}
}

func TestScoreAIAnalyzerOutputReturnsBaselineScoreForNoFeatures(t *testing.T) {
	result := scoreAIAnalyzerOutput(&analyzerOutput{Results: []analyzerModuleResult{}})

	if result.Score != 10 {
		t.Fatalf("expected baseline AI score 10, got %d", result.Score)
	}
	if result.Features.YARACount != 0 || result.Features.SuspiciousAPICount != 0 || result.Features.MaxEntropy != 0 {
		t.Fatalf("expected empty features, got %#v", result.Features)
	}
}
