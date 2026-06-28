package jobs

import (
	"encoding/json"
	"time"
)

type JobStatus string

const (
	StatusPending       JobStatus = "pending"
	StatusQueued        JobStatus = "queued"
	StatusRunning       JobStatus = "running"
	StatusCompleted     JobStatus = "completed"
	StatusFailed        JobStatus = "failed"
	StatusNeedsPassword JobStatus = "needs_password"
)

type SourceType string

const (
	SourceTypeUpload SourceType = "upload"
	SourceTypeURL    SourceType = "url"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type AnalysisJob struct {
	ID                    string
	SourceType            SourceType
	Status                JobStatus
	MD5Hash               *string
	SHA256Hash            *string
	StorageKey            *string
	OriginalStorageKey    *string
	QuarantineStorageKey  *string
	MIMEType              *string
	FileExtension         *string
	MIMEExtensionMismatch bool
	SizeBytes             *int64
	Score                 *int
	AIScore               *int
	RiskLevel             *RiskLevel
	AnalyzerResult        json.RawMessage
	ErrorMessage          *string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
