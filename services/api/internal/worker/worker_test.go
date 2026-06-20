package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hibiken/asynq"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
)

type fakeRepo struct {
	statuses  []jobs.JobStatus
	completed bool
	failed    bool
	score     int
	riskLevel jobs.RiskLevel
	message   string
}

func (r *fakeRepo) UpdateStatus(ctx context.Context, id string, status jobs.JobStatus) error {
	r.statuses = append(r.statuses, status)
	return nil
}

func (r *fakeRepo) Complete(ctx context.Context, id string, score int, riskLevel jobs.RiskLevel) error {
	r.completed = true
	r.score = score
	r.riskLevel = riskLevel
	return nil
}

func (r *fakeRepo) Fail(ctx context.Context, id string, message string) error {
	r.failed = true
	r.message = message
	return nil
}

type fakeAnalyzer struct {
	result *AnalysisResult
	err    error
}

func (a fakeAnalyzer) Analyze(ctx context.Context, payload queue.AnalyzeFilePayload) (*AnalysisResult, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.result, nil
}

func TestHandleAnalyzeFileCompletesJob(t *testing.T) {
	repo := &fakeRepo{}
	handler := NewHandler(repo, fakeAnalyzer{
		result: &AnalysisResult{Score: 12, RiskLevel: jobs.RiskLow},
	})

	task := taskForPayload(t, queue.AnalyzeFilePayload{
		JobID:                "job-123",
		QuarantineStorageKey: "quarantine/job-123/file.bin",
		MIMEType:             "text/plain",
		SHA256Hash:           "abc",
	})

	if err := handler.HandleAnalyzeFile(context.Background(), task); err != nil {
		t.Fatalf("handle task: %v", err)
	}

	if len(repo.statuses) != 1 || repo.statuses[0] != jobs.StatusRunning {
		t.Fatalf("expected running status, got %#v", repo.statuses)
	}

	if !repo.completed || repo.score != 12 || repo.riskLevel != jobs.RiskLow {
		t.Fatalf("expected completed result, got completed=%v score=%d risk=%q", repo.completed, repo.score, repo.riskLevel)
	}
}

func TestHandleAnalyzeFileMarksJobFailedWhenAnalysisFails(t *testing.T) {
	repo := &fakeRepo{}
	handler := NewHandler(repo, fakeAnalyzer{err: errors.New("analysis failed")})

	task := taskForPayload(t, queue.AnalyzeFilePayload{JobID: "job-123"})

	if err := handler.HandleAnalyzeFile(context.Background(), task); err == nil {
		t.Fatalf("expected analysis error")
	}

	if !repo.failed || repo.message != "analysis failed" {
		t.Fatalf("expected failed job, got failed=%v message=%q", repo.failed, repo.message)
	}
}

func taskForPayload(t *testing.T, payload queue.AnalyzeFilePayload) *asynq.Task {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	return asynq.NewTask(queue.TypeAnalyzeFile, body)
}
