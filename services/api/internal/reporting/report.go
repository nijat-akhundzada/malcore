package reporting

import (
	"encoding/json"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

const SchemaVersion = "malcore.report.v1"

type Report struct {
	SchemaVersion string       `json:"schema_version"`
	GeneratedAt   string       `json:"generated_at"`
	Job           ReportJob    `json:"job"`
	File          ReportFile   `json:"file"`
	Hashes        ReportHashes `json:"hashes"`
	YARAHits      []YARAHit    `json:"yara_hits"`
	IOCs          IOCReport    `json:"iocs"`
	Scores        ReportScores `json:"scores"`
}

type ReportJob struct {
	ID         string          `json:"id"`
	SourceType jobs.SourceType `json:"source_type"`
	Status     jobs.JobStatus  `json:"status"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

type ReportFile struct {
	MIMEType              *string `json:"mime_type"`
	Extension             *string `json:"extension"`
	MIMEExtensionMismatch bool    `json:"mime_extension_mismatch"`
	SizeBytes             *int64  `json:"size_bytes"`
	OriginalStorageKey    *string `json:"original_storage_key"`
	QuarantineStorageKey  *string `json:"quarantine_storage_key"`
}

type ReportHashes struct {
	MD5    *string `json:"md5"`
	SHA256 *string `json:"sha256"`
}

type YARAHit struct {
	Rule        string         `json:"rule"`
	Severity    string         `json:"severity,omitempty"`
	Description string         `json:"description,omitempty"`
	Namespace   any            `json:"namespace,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
	Strings     []any          `json:"strings,omitempty"`
}

type IOCReport struct {
	URLs    []string `json:"urls"`
	IPs     []string `json:"ips"`
	Domains []string `json:"domains"`
}

type ReportScores struct {
	Final     *int            `json:"final"`
	Rule      *int            `json:"rule"`
	AI        *int            `json:"ai"`
	RiskLevel *jobs.RiskLevel `json:"risk_level"`
	Formula   string          `json:"formula,omitempty"`
	Weights   *ScoreWeights   `json:"weights,omitempty"`
	AIModel   *ReportAIModel  `json:"ai_model,omitempty"`
}

type ScoreWeights struct {
	Rule float64 `json:"rule"`
	AI   float64 `json:"ai"`
}

type ReportAIModel struct {
	Name     string         `json:"name"`
	Features map[string]any `json:"features,omitempty"`
}

type analyzerPayload struct {
	IOCs    IOCReport        `json:"iocs"`
	Results []analyzerModule `json:"results"`
	Scoring analyzerScoring  `json:"scoring"`
}

type analyzerModule struct {
	Analyzer string         `json:"analyzer"`
	Findings []finding      `json:"findings"`
	Metadata map[string]any `json:"metadata"`
	IOCs     IOCReport      `json:"iocs"`
}

type finding struct {
	Type        string   `json:"type"`
	Rule        string   `json:"rule"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Namespace   any      `json:"namespace"`
	Tags        []string `json:"tags"`
}

type analyzerScoring struct {
	RuleScore  *int           `json:"rule_score"`
	AIScore    *int           `json:"ai_score"`
	FinalScore *int           `json:"final_score"`
	Formula    string         `json:"formula"`
	Weights    *ScoreWeights  `json:"weights"`
	AIModel    *ReportAIModel `json:"ai_model"`
}

func Build(job *jobs.AnalysisJob, generatedAt time.Time) (*Report, error) {
	var payload analyzerPayload
	if len(job.AnalyzerResult) > 0 {
		if err := json.Unmarshal(job.AnalyzerResult, &payload); err != nil {
			return nil, err
		}
	}

	report := &Report{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   generatedAt.UTC().Format(time.RFC3339),
		Job: ReportJob{
			ID:         job.ID,
			SourceType: job.SourceType,
			Status:     job.Status,
			CreatedAt:  job.CreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt:  job.UpdatedAt.UTC().Format(time.RFC3339),
		},
		File: ReportFile{
			MIMEType:              job.MIMEType,
			Extension:             job.FileExtension,
			MIMEExtensionMismatch: job.MIMEExtensionMismatch,
			SizeBytes:             job.SizeBytes,
			OriginalStorageKey:    job.OriginalStorageKey,
			QuarantineStorageKey:  job.QuarantineStorageKey,
		},
		Hashes: ReportHashes{
			MD5:    job.MD5Hash,
			SHA256: job.SHA256Hash,
		},
		YARAHits: yaraHits(payload),
		IOCs:     reportIOCs(payload),
		Scores:   reportScores(job, payload.Scoring),
	}

	return report, nil
}

func yaraHits(payload analyzerPayload) []YARAHit {
	hits := []YARAHit{}

	for _, module := range payload.Results {
		if module.Analyzer != "yara" {
			continue
		}

		moduleHits := yaraMatchesFromMetadata(module.Metadata)
		if len(moduleHits) > 0 {
			hits = append(hits, moduleHits...)
			continue
		}

		for _, item := range module.Findings {
			if item.Type != "yara_match" {
				continue
			}

			hits = append(hits, YARAHit{
				Rule:        item.Rule,
				Severity:    item.Severity,
				Description: item.Description,
				Namespace:   item.Namespace,
				Tags:        item.Tags,
			})
		}
	}

	return hits
}

func yaraMatchesFromMetadata(metadata map[string]any) []YARAHit {
	rawMatches, ok := metadata["matches"].([]any)
	if !ok {
		return nil
	}

	hits := make([]YARAHit, 0, len(rawMatches))
	for _, item := range rawMatches {
		match, ok := item.(map[string]any)
		if !ok {
			continue
		}

		hits = append(hits, YARAHit{
			Rule:        stringValue(match["rule"]),
			Severity:    stringValue(match["severity"]),
			Description: stringValue(match["description"]),
			Namespace:   match["namespace"],
			Tags:        stringSlice(match["tags"]),
			Meta:        mapValue(match["meta"]),
			Strings:     anySlice(match["strings"]),
		})
	}

	return hits
}

func reportIOCs(payload analyzerPayload) IOCReport {
	iocs := payload.IOCs
	if len(iocs.URLs)+len(iocs.IPs)+len(iocs.Domains) > 0 {
		return normalizeIOCs(iocs)
	}

	for _, module := range payload.Results {
		iocs.URLs = append(iocs.URLs, module.IOCs.URLs...)
		iocs.IPs = append(iocs.IPs, module.IOCs.IPs...)
		iocs.Domains = append(iocs.Domains, module.IOCs.Domains...)
	}

	return normalizeIOCs(iocs)
}

func normalizeIOCs(iocs IOCReport) IOCReport {
	return IOCReport{
		URLs:    uniqueStrings(iocs.URLs),
		IPs:     uniqueStrings(iocs.IPs),
		Domains: uniqueStrings(iocs.Domains),
	}
}

func reportScores(job *jobs.AnalysisJob, scoring analyzerScoring) ReportScores {
	final := job.Score
	if final == nil {
		final = scoring.FinalScore
	}

	ai := job.AIScore
	if ai == nil {
		ai = scoring.AIScore
	}

	return ReportScores{
		Final:     final,
		Rule:      scoring.RuleScore,
		AI:        ai,
		RiskLevel: job.RiskLevel,
		Formula:   scoring.Formula,
		Weights:   scoring.Weights,
		AIModel:   scoring.AIModel,
	}
}

func stringSlice(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}

	values := make([]string, 0, len(raw))
	for _, item := range raw {
		if value := stringValue(item); value != "" {
			values = append(values, value)
		}
	}

	return values
}

func anySlice(value any) []any {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	return values
}

func mapValue(value any) map[string]any {
	values, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return values
}

func stringValue(value any) string {
	valueString, ok := value.(string)
	if !ok {
		return ""
	}
	return valueString
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	unique := []string{}

	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		unique = append(unique, value)
	}

	return unique
}
