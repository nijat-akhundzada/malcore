package jobs

import (
	"context"
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
		RETURNING id, source_type, status, score, risk_level, error_message, created_at, updated_at
	`

	var job AnalysisJob

	err := r.db.QueryRow(ctx, query, sourceType, StatusPending).Scan(
		&job.ID,
		&job.SourceType,
		&job.Status,
		&job.Score,
		&job.RiskLevel,
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
		SELECT id, source_type, status, score, risk_level, error_message, created_at, updated_at
		FROM analysis_jobs
		WHERE id = $1
	`

	var job AnalysisJob

	err := r.db.QueryRow(ctx, query, id).Scan(
		&job.ID,
		&job.SourceType,
		&job.Status,
		&job.Score,
		&job.RiskLevel,
		&job.ErrorMessage,
		&job.CreatedAt,
		&job.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("find analysis job by id: %w", err)
	}

	return &job, nil
}
