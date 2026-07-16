package reports

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

const SchemaVersion = "malcore.report.v1"

type Report struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   string          `json:"generated_at"`
	Job           ReportJob       `json:"job"`
	File          ReportFile      `json:"file"`
	Scoring       ReportScoring   `json:"scoring"`
	Analysis      ReportAnalysis  `json:"analysis"`
	RawAnalysis   json.RawMessage `json:"raw_analysis_result,omitempty"`
}

type ReportJob struct {
	ID         string          `json:"id"`
	SourceType jobs.SourceType `json:"source_type"`
	Status     jobs.JobStatus  `json:"status"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

type ReportFile struct {
	MIMEType              *string              `json:"mime_type"`
	FileExtension         *string              `json:"file_extension"`
	SizeBytes             *int64               `json:"size_bytes"`
	MIMEExtensionMismatch bool                 `json:"mime_extension_mismatch"`
	Hashes                ReportFileHashes     `json:"hashes"`
	Storage               ReportStorageDetails `json:"storage"`
}

type ReportFileHashes struct {
	MD5    *string `json:"md5"`
	SHA256 *string `json:"sha256"`
}

type ReportStorageDetails struct {
	StorageKey           *string `json:"storage_key"`
	OriginalStorageKey   *string `json:"original_storage_key"`
	QuarantineStorageKey *string `json:"quarantine_storage_key"`
}

type ReportScoring struct {
	FinalScore *int            `json:"final_score"`
	AIScore    *int            `json:"ai_score"`
	RiskLevel  *jobs.RiskLevel `json:"risk_level"`
	RuleScore  *int            `json:"rule_score,omitempty"`
	Formula    string          `json:"formula"`
	AIModel    *ReportAIModel  `json:"ai_model,omitempty"`
}

type ReportAIModel struct {
	Name     string         `json:"name"`
	Features map[string]any `json:"features"`
}

type ReportAnalysis struct {
	SchemaVersion string              `json:"schema_version,omitempty"`
	Mode          string              `json:"mode,omitempty"`
	Analyzers     []string            `json:"analyzers"`
	IOCs          map[string][]string `json:"iocs"`
	YARAHits      []ReportYARAHit     `json:"yara_hits"`
	Findings      []ReportFinding     `json:"findings"`
	Modules       []ReportModule      `json:"modules"`
}

type ReportFinding struct {
	Analyzer    string         `json:"analyzer"`
	Type        string         `json:"type"`
	Severity    string         `json:"severity"`
	Description string         `json:"description,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

type ReportYARAHit struct {
	Rule        string   `json:"rule"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type ReportModule struct {
	Analyzer  string                `json:"analyzer"`
	Category  string                `json:"category,omitempty"`
	Supported bool                  `json:"supported"`
	Errors    []string              `json:"errors,omitempty"`
	Metadata  map[string]any        `json:"metadata,omitempty"`
	Findings  []ReportModuleFinding `json:"findings,omitempty"`
	IOCs      map[string][]string   `json:"iocs,omitempty"`
}

type ReportModuleFinding struct {
	Type        string         `json:"type"`
	Severity    string         `json:"severity"`
	Description string         `json:"description,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

type analyzerPayload struct {
	SchemaVersion string                   `json:"schema_version"`
	Mode          string                   `json:"mode"`
	Analyzers     []string                 `json:"analyzers"`
	IOCs          map[string][]string      `json:"iocs"`
	Results       []analyzerModulePayload  `json:"results"`
	Scoring       analyzerScoringContainer `json:"scoring"`
}

type analyzerScoringContainer struct {
	RuleScore int `json:"rule_score"`
	AIScore   int `json:"ai_score"`
	AiModel   struct {
		Name     string         `json:"name"`
		Features map[string]any `json:"features"`
	} `json:"ai_model"`
}

type analyzerModulePayload struct {
	Analyzer  string                 `json:"analyzer"`
	Category  string                 `json:"category"`
	Supported *bool                  `json:"supported"`
	Errors    []string               `json:"errors"`
	Metadata  map[string]any         `json:"metadata"`
	Findings  []analyzerFindingEntry `json:"findings"`
	IOCs      map[string][]string    `json:"iocs"`
}

type analyzerFindingEntry struct {
	Type        string         `json:"type"`
	Severity    string         `json:"severity"`
	Description string         `json:"description"`
	Extra       map[string]any `json:"-"`
}

func (f *analyzerFindingEntry) UnmarshalJSON(data []byte) error {
	type alias analyzerFindingEntry
	aux := map[string]any{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var parsed alias
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}

	delete(aux, "type")
	delete(aux, "severity")
	delete(aux, "description")

	*f = analyzerFindingEntry(parsed)
	if len(aux) > 0 {
		f.Extra = aux
	}
	return nil
}

func Build(job *jobs.AnalysisJob) (*Report, error) {
	if job == nil {
		return nil, fmt.Errorf("job is required")
	}

	report := &Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Job: ReportJob{
			ID:         job.ID,
			SourceType: job.SourceType,
			Status:     job.Status,
			CreatedAt:  job.CreatedAt.Format(time.RFC3339),
			UpdatedAt:  job.UpdatedAt.Format(time.RFC3339),
		},
		File: ReportFile{
			MIMEType:              job.MIMEType,
			FileExtension:         job.FileExtension,
			SizeBytes:             job.SizeBytes,
			MIMEExtensionMismatch: job.MIMEExtensionMismatch,
			Hashes: ReportFileHashes{
				MD5:    job.MD5Hash,
				SHA256: job.SHA256Hash,
			},
			Storage: ReportStorageDetails{
				StorageKey:           job.StorageKey,
				OriginalStorageKey:   job.OriginalStorageKey,
				QuarantineStorageKey: job.QuarantineStorageKey,
			},
		},
		Scoring: ReportScoring{
			FinalScore: job.Score,
			AIScore:    job.AIScore,
			RiskLevel:  job.RiskLevel,
			Formula:    "0.6*rule_score + 0.4*ai_score",
		},
		Analysis: ReportAnalysis{
			Analyzers: []string{},
			IOCs: map[string][]string{
				"urls":    []string{},
				"ips":     []string{},
				"domains": []string{},
			},
			YARAHits: []ReportYARAHit{},
			Findings: []ReportFinding{},
			Modules:  []ReportModule{},
		},
	}

	if len(job.AnalyzerResult) == 0 {
		return report, nil
	}

	report.RawAnalysis = append(json.RawMessage(nil), job.AnalyzerResult...)

	var payload analyzerPayload
	if err := json.Unmarshal(job.AnalyzerResult, &payload); err != nil {
		return nil, fmt.Errorf("decode analyzer result: %w", err)
	}

	report.Analysis.SchemaVersion = payload.SchemaVersion
	report.Analysis.Mode = payload.Mode
	report.Analysis.Analyzers = append(report.Analysis.Analyzers, payload.Analyzers...)
	report.Analysis.IOCs = normalizeIOCs(payload.IOCs)

	if payload.Scoring.RuleScore > 0 {
		report.Scoring.RuleScore = intPtr(payload.Scoring.RuleScore)
	}
	if strings.TrimSpace(payload.Scoring.AiModel.Name) != "" {
		report.Scoring.AIModel = &ReportAIModel{
			Name:     payload.Scoring.AiModel.Name,
			Features: payload.Scoring.AiModel.Features,
		}
	}

	for _, module := range payload.Results {
		reportModule := ReportModule{
			Analyzer:  module.Analyzer,
			Category:  module.Category,
			Supported: module.Supported == nil || *module.Supported,
			Errors:    append([]string(nil), module.Errors...),
			Metadata:  module.Metadata,
			IOCs:      normalizeIOCs(module.IOCs),
		}

		for _, finding := range module.Findings {
			moduleFinding := ReportModuleFinding{
				Type:        finding.Type,
				Severity:    finding.Severity,
				Description: finding.Description,
				Details:     copyMap(finding.Extra),
			}
			reportModule.Findings = append(reportModule.Findings, moduleFinding)
			report.Analysis.Findings = append(report.Analysis.Findings, ReportFinding{
				Analyzer:    module.Analyzer,
				Type:        finding.Type,
				Severity:    finding.Severity,
				Description: finding.Description,
				Details:     copyMap(finding.Extra),
			})
		}

		if strings.EqualFold(module.Analyzer, "yara") {
			report.Analysis.YARAHits = append(report.Analysis.YARAHits, collectYARAHits(module)...)
		}

		report.Analysis.Modules = append(report.Analysis.Modules, reportModule)
	}

	return report, nil
}

func collectYARAHits(module analyzerModulePayload) []ReportYARAHit {
	rawMatches, ok := module.Metadata["matches"].([]any)
	if !ok {
		return nil
	}

	hits := make([]ReportYARAHit, 0, len(rawMatches))
	for _, raw := range rawMatches {
		match, ok := raw.(map[string]any)
		if !ok {
			continue
		}

		hit := ReportYARAHit{
			Rule:        stringValue(match["rule"]),
			Severity:    stringValue(match["severity"]),
			Description: stringValue(match["description"]),
			Namespace:   stringValue(match["namespace"]),
			Tags:        stringSlice(match["tags"]),
		}
		if hit.Rule == "" {
			continue
		}
		hits = append(hits, hit)
	}

	return hits
}

func normalizeIOCs(iocs map[string][]string) map[string][]string {
	normalized := map[string][]string{
		"urls":    []string{},
		"ips":     []string{},
		"domains": []string{},
	}

	for key, values := range iocs {
		normalized[key] = append([]string(nil), values...)
	}

	return normalized
}

func copyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}

	clone := make(map[string]any, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}

	values := make([]string, 0, len(items))
	for _, item := range items {
		if text := strings.TrimSpace(stringValue(item)); text != "" {
			values = append(values, text)
		}
	}
	return values
}

func stringValue(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}

func intPtr(value int) *int {
	return &value
}
