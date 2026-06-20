package worker

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
)

type JobRepository interface {
	UpdateStatus(ctx context.Context, id string, status jobs.JobStatus) error
	Complete(ctx context.Context, id string, score int, riskLevel jobs.RiskLevel) error
	Fail(ctx context.Context, id string, message string) error
}

type AnalysisResult struct {
	Score     int
	RiskLevel jobs.RiskLevel
}

type Analyzer interface {
	Analyze(ctx context.Context, payload queue.AnalyzeFilePayload) (*AnalysisResult, error)
}

type PlaceholderAnalyzer struct{}

func (a PlaceholderAnalyzer) Analyze(ctx context.Context, payload queue.AnalyzeFilePayload) (*AnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &AnalysisResult{
		Score:     0,
		RiskLevel: jobs.RiskLow,
	}, nil
}

type Handler struct {
	repo     JobRepository
	analyzer Analyzer
}

func NewHandler(repo JobRepository, analyzer Analyzer) *Handler {
	return &Handler{
		repo:     repo,
		analyzer: analyzer,
	}
}

func (h *Handler) Register(mux *asynq.ServeMux) {
	mux.HandleFunc(queue.TypeAnalyzeFile, h.HandleAnalyzeFile)
}

func (h *Handler) HandleAnalyzeFile(ctx context.Context, task *asynq.Task) error {
	var payload queue.AnalyzeFilePayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("decode analyze file payload: %w", err)
	}

	if payload.JobID == "" {
		return fmt.Errorf("analyze file payload missing job_id")
	}

	if err := h.repo.UpdateStatus(ctx, payload.JobID, jobs.StatusRunning); err != nil {
		return err
	}

	result, err := h.analyzer.Analyze(ctx, payload)
	if err != nil {
		_ = h.repo.Fail(ctx, payload.JobID, err.Error())
		return err
	}

	if err := h.repo.Complete(ctx, payload.JobID, result.Score, result.RiskLevel); err != nil {
		return err
	}

	return nil
}
