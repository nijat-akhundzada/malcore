package reporting

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

func TestBuildReportIncludesHashesYARAHitsIOCsAndScores(t *testing.T) {
	md5Hash := "ea902edb11c106b075e53235ce7e0821"
	sha256Hash := "4c1d8d09f5bb8f82bb0dc4904d178b264581c51853f0173310c8072d0990b723"
	mimeType := "text/plain"
	extension := ".ps1"
	sizeBytes := int64(31)
	originalKey := "original/job-123/file.bin"
	quarantineKey := "quarantine/job-123/file.bin"
	finalScore := 60
	aiScore := 29
	riskLevel := jobs.RiskMedium
	now := time.Date(2026, 7, 1, 17, 30, 0, 0, time.UTC)

	job := &jobs.AnalysisJob{
		ID:                   "job-123",
		SourceType:           jobs.SourceTypeUpload,
		Status:               jobs.StatusCompleted,
		MD5Hash:              &md5Hash,
		SHA256Hash:           &sha256Hash,
		MIMEType:             &mimeType,
		FileExtension:        &extension,
		SizeBytes:            &sizeBytes,
		OriginalStorageKey:   &originalKey,
		QuarantineStorageKey: &quarantineKey,
		Score:                &finalScore,
		AIScore:              &aiScore,
		RiskLevel:            &riskLevel,
		CreatedAt:            now.Add(-time.Minute),
		UpdatedAt:            now,
		AnalyzerResult: json.RawMessage(`{
			"iocs": {
				"urls": ["https://ioc.example.com/payload"],
				"ips": ["8.8.8.8"],
				"domains": ["ioc.example.com"]
			},
			"results": [
				{
					"analyzer": "yara",
					"metadata": {
						"matches": [
							{
								"rule": "Suspicious_PowerShell_Encoded_Command",
								"severity": "high",
								"description": "PowerShell encoded command usage",
								"tags": ["script", "powershell"],
								"meta": {"severity": "high"},
								"strings": []
							}
						]
					}
				}
			],
			"scoring": {
				"rule_score": 80,
				"ai_score": 29,
				"final_score": 60,
				"formula": "0.6 * rule_score + 0.4 * ai_score",
				"weights": {"rule": 0.6, "ai": 0.4},
				"ai_model": {
					"name": "logistic_regression_v1",
					"features": {
						"yara_count": 1,
						"suspicious_api_count": 0,
						"max_entropy": 0
					}
				}
			}
		}`),
	}

	report, err := Build(job, now)
	if err != nil {
		t.Fatalf("build report: %v", err)
	}

	if report.SchemaVersion != SchemaVersion {
		t.Fatalf("expected schema version %q, got %q", SchemaVersion, report.SchemaVersion)
	}
	if report.Hashes.MD5 == nil || *report.Hashes.MD5 != md5Hash {
		t.Fatalf("expected md5 hash in report, got %#v", report.Hashes.MD5)
	}
	if report.Hashes.SHA256 == nil || *report.Hashes.SHA256 != sha256Hash {
		t.Fatalf("expected sha256 hash in report, got %#v", report.Hashes.SHA256)
	}
	if len(report.YARAHits) != 1 || report.YARAHits[0].Rule != "Suspicious_PowerShell_Encoded_Command" {
		t.Fatalf("expected YARA hit in report, got %#v", report.YARAHits)
	}
	if report.IOCs.URLs[0] != "https://ioc.example.com/payload" || report.IOCs.IPs[0] != "8.8.8.8" || report.IOCs.Domains[0] != "ioc.example.com" {
		t.Fatalf("expected IOCs in report, got %#v", report.IOCs)
	}
	if report.Scores.Final == nil || *report.Scores.Final != 60 {
		t.Fatalf("expected final score 60, got %#v", report.Scores.Final)
	}
	if report.Scores.Rule == nil || *report.Scores.Rule != 80 {
		t.Fatalf("expected rule score 80, got %#v", report.Scores.Rule)
	}
	if report.Scores.AI == nil || *report.Scores.AI != 29 {
		t.Fatalf("expected AI score 29, got %#v", report.Scores.AI)
	}
	if report.Scores.RiskLevel == nil || *report.Scores.RiskLevel != jobs.RiskMedium {
		t.Fatalf("expected medium risk level, got %#v", report.Scores.RiskLevel)
	}
	if report.Scores.AIModel == nil || report.Scores.AIModel.Name != "logistic_regression_v1" {
		t.Fatalf("expected AI model details, got %#v", report.Scores.AIModel)
	}

	if _, err := json.Marshal(report); err != nil {
		t.Fatalf("expected report JSON to be valid: %v", err)
	}
}

func TestBuildReportMergesModuleIOCsWhenTopLevelIOCsAreMissing(t *testing.T) {
	job := &jobs.AnalysisJob{
		ID:         "job-123",
		SourceType: jobs.SourceTypeUpload,
		Status:     jobs.StatusCompleted,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		AnalyzerResult: json.RawMessage(`{
			"results": [
				{"analyzer": "scripts", "iocs": {"urls": ["https://one.example"], "domains": ["one.example"]}},
				{"analyzer": "ioc", "iocs": {"urls": ["https://one.example"], "ips": ["1.1.1.1"]}}
			]
		}`),
	}

	report, err := Build(job, time.Now())
	if err != nil {
		t.Fatalf("build report: %v", err)
	}

	if len(report.IOCs.URLs) != 1 || report.IOCs.URLs[0] != "https://one.example" {
		t.Fatalf("expected deduplicated URLs, got %#v", report.IOCs.URLs)
	}
	if len(report.IOCs.IPs) != 1 || report.IOCs.IPs[0] != "1.1.1.1" {
		t.Fatalf("expected IP from module IOCs, got %#v", report.IOCs.IPs)
	}
	if len(report.IOCs.Domains) != 1 || report.IOCs.Domains[0] != "one.example" {
		t.Fatalf("expected domain from module IOCs, got %#v", report.IOCs.Domains)
	}
}

func TestRenderPDFRequiresReport(t *testing.T) {
	if _, err := RenderPDFWithCommand(t.Context(), "python3", nil); err == nil {
		t.Fatalf("expected nil report error")
	}
}
