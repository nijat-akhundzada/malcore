package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(ctx context.Context, sourceType SourceType) (*AnalysisJob, error) {
	query := `
		INSERT INTO analysis_jobs (source_type, status)
		VALUES ($1, $2)
		RETURNING id, source_type, status, md5_hash, sha256_hash, storage_key, original_storage_key, quarantine_storage_key, mime_type, file_extension, mime_extension_mismatch, size_bytes, score, ai_score, risk_level, analyzer_result, error_message, created_at, updated_at
	`

	var job AnalysisJob

	err := r.db.QueryRow(ctx, query, sourceType, StatusPending).Scan(
		&job.ID,
		&job.SourceType,
		&job.Status,
		&job.MD5Hash,
		&job.SHA256Hash,
		&job.StorageKey,
		&job.OriginalStorageKey,
		&job.QuarantineStorageKey,
		&job.MIMEType,
		&job.FileExtension,
		&job.MIMEExtensionMismatch,
		&job.SizeBytes,
		&job.Score,
		&job.AIScore,
		&job.RiskLevel,
		&job.AnalyzerResult,
		&job.ErrorMessage,
		&job.CreatedAt,
		&job.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create analysis job: %w", err)
	}

	return &job, nil
}

func (r *Repository) FindByID(ctx context.Context, id string) (*AnalysisJob, error) {
	query := `
		SELECT id, source_type, status, md5_hash, sha256_hash, storage_key, original_storage_key, quarantine_storage_key, mime_type, file_extension, mime_extension_mismatch, size_bytes, score, ai_score, risk_level, analyzer_result, error_message, created_at, updated_at
		FROM analysis_jobs
		WHERE id = $1
	`

	var job AnalysisJob

	err := r.db.QueryRow(ctx, query, id).Scan(
		&job.ID,
		&job.SourceType,
		&job.Status,
		&job.MD5Hash,
		&job.SHA256Hash,
		&job.StorageKey,
		&job.OriginalStorageKey,
		&job.QuarantineStorageKey,
		&job.MIMEType,
		&job.FileExtension,
		&job.MIMEExtensionMismatch,
		&job.SizeBytes,
		&job.Score,
		&job.AIScore,
		&job.RiskLevel,
		&job.AnalyzerResult,
		&job.ErrorMessage,
		&job.CreatedAt,
		&job.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("find analysis job by id: %w", err)
	}

	return &job, nil
}

func (r *Repository) UpdateFileMetadata(ctx context.Context, id string, md5Hash, sha256Hash, storageKey, originalStorageKey, quarantineStorageKey, mimeType, fileExtension string, mimeExtensionMismatch bool, sizeBytes int64) error {
	query := `
		UPDATE analysis_jobs
		SET md5_hash = $2,
		    sha256_hash = $3,
		    storage_key = $4,
		    original_storage_key = $5,
		    quarantine_storage_key = $6,
		    mime_type = $7,
		    file_extension = $8,
		    mime_extension_mismatch = $9,
		    size_bytes = $10,
		    updated_at = now()
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, id, md5Hash, sha256Hash, storageKey, originalStorageKey, quarantineStorageKey, mimeType, fileExtension, mimeExtensionMismatch, sizeBytes)
	if err != nil {
		return fmt.Errorf("update analysis job file metadata: %w", err)
	}
	return nil
}

func (r *Repository) UpdateStatus(ctx context.Context, id string, status JobStatus) error {
	query := `
		UPDATE analysis_jobs
		SET status = $2,
		    updated_at = now()
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("update analysis job status: %w", err)
	}
	return nil
}

func (r *Repository) Complete(ctx context.Context, id string, score int, aiScore int, riskLevel RiskLevel, analyzerResult json.RawMessage) error {
	query := `
		UPDATE analysis_jobs
		SET status = $2,
		    score = $3,
		    ai_score = $4,
		    risk_level = $5,
		    analyzer_result = $6,
		    error_message = NULL,
		    updated_at = now()
		WHERE id = $1
	`

	var resultValue any
	if len(analyzerResult) > 0 {
		resultValue = analyzerResult
	}

	_, err := r.db.Exec(ctx, query, id, StatusCompleted, score, aiScore, riskLevel, resultValue)
	if err != nil {
		return fmt.Errorf("complete analysis job: %w", err)
	}
	return nil
}

func (r *Repository) Fail(ctx context.Context, id string, message string) error {
	query := `
		UPDATE analysis_jobs
		SET status = $2,
		    error_message = $3,
		    updated_at = now()
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, id, StatusFailed, message)
	if err != nil {
		return fmt.Errorf("fail analysis job: %w", err)
	}
	return nil
}
