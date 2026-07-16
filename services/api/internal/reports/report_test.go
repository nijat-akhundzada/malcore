package reports

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

func TestBuildIncludesHashesScoresAndYARAHits(t *testing.T) {
	md5 := "abc"
	sha := "def"
	mime := "application/x-dosexec"
	ext := ".exe"
	size := int64(1234)
	score := 77
	ai := 65
	risk := jobs.RiskHigh
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

	job := &jobs.AnalysisJob{
		ID:                    "job-123",
		SourceType:            jobs.SourceTypeUpload,
		Status:                jobs.StatusCompleted,
		MD5Hash:               &md5,
		SHA256Hash:            &sha,
		MIMEType:              &mime,
		FileExtension:         &ext,
		SizeBytes:             &size,
		MIMEExtensionMismatch: true,
		Score:                 &score,
		AIScore:               &ai,
		RiskLevel:             &risk,
		CreatedAt:             now,
		UpdatedAt:             now,
		AnalyzerResult: json.RawMessage(`{
			"schema_version":"malcore.analyzer.v1",
			"mode":"auto",
			"analyzers":["pe","yara","ioc"],
			"iocs":{"urls":["https://c2.example"],"ips":["8.8.8.8"],"domains":["c2.example"]},
			"scoring":{"rule_score":85,"ai_score":65,"ai_model":{"name":"logistic_regression_v1","features":{"yara_count":1}}},
			"results":[
				{"analyzer":"yara","category":"signature","supported":true,"metadata":{"matches":[{"rule":"MalcoreRule","severity":"high","description":"test hit"}]},"findings":[{"type":"yara_match","severity":"high","description":"test hit"}],"iocs":{"urls":[],"ips":[],"domains":[]}},
				{"analyzer":"pe","category":"pe","supported":true,"metadata":{"sections":[{"name":".text","entropy":7.9}]},"findings":[{"type":"high_entropy_section","severity":"medium","description":"packed"}],"iocs":{"urls":[],"ips":[],"domains":[]}}
			]
		}`),
	}

	report, err := Build(job)
	if err != nil {
		t.Fatalf("build report: %v", err)
	}

	if report.Scoring.FinalScore == nil || *report.Scoring.FinalScore != 77 {
		t.Fatalf("expected final score 77, got %#v", report.Scoring.FinalScore)
	}
	if report.Scoring.RuleScore == nil || *report.Scoring.RuleScore != 85 {
		t.Fatalf("expected rule score 85, got %#v", report.Scoring.RuleScore)
	}
	if len(report.Analysis.YARAHits) != 1 || report.Analysis.YARAHits[0].Rule != "MalcoreRule" {
		t.Fatalf("expected one yara hit, got %#v", report.Analysis.YARAHits)
	}
	if len(report.Analysis.Findings) != 2 {
		t.Fatalf("expected two findings, got %#v", report.Analysis.Findings)
	}
	if report.File.Hashes.MD5 == nil || *report.File.Hashes.MD5 != "abc" {
		t.Fatalf("expected md5 hash in report, got %#v", report.File.Hashes.MD5)
	}
}

func TestRenderPDFProducesPDFDocument(t *testing.T) {
	report := &Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   "2026-07-14T12:00:00Z",
		Job: ReportJob{
			ID:         "job-123",
			SourceType: jobs.SourceTypeUpload,
			Status:     jobs.StatusCompleted,
		},
		File: ReportFile{
			Hashes:  ReportFileHashes{},
			Storage: ReportStorageDetails{},
		},
		Scoring: ReportScoring{
			Formula: "0.6*rule_score + 0.4*ai_score",
		},
		Analysis: ReportAnalysis{
			IOCs: map[string][]string{
				"urls":    []string{"https://example.test"},
				"ips":     []string{},
				"domains": []string{},
			},
			YARAHits:  []ReportYARAHit{{Rule: "MalcoreRule", Severity: "high", Description: "test"}},
			Findings:  []ReportFinding{{Analyzer: "scripts", Type: "script_dynamic_execution", Severity: "high", Description: "eval detected"}},
			Modules:   []ReportModule{{Analyzer: "scripts", Category: "script", Supported: true}},
			Analyzers: []string{"scripts"},
		},
	}

	document, err := RenderPDF(report)
	if err != nil {
		t.Fatalf("render pdf: %v", err)
	}

	if !strings.HasPrefix(string(document), "%PDF-1.4") {
		t.Fatalf("expected pdf header, got %q", string(document[:8]))
	}
	if !strings.Contains(string(document), "MALCORE Analysis Report") {
		t.Fatalf("expected title in pdf stream")
	}
}
