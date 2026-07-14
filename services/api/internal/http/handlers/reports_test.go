package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

type stubReportRepo struct {
	job *jobs.AnalysisJob
	err error
}

func (r *stubReportRepo) FindByID(_ context.Context, _ string) (*jobs.AnalysisJob, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.job, nil
}

func TestReportHandlerJSONReturnsStructuredReport(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	mime := "text/plain"
	sha := "sha256"
	score := 42
	ai := 17
	risk := jobs.RiskMedium
	handler := NewReportHandler(&stubReportRepo{
		job: &jobs.AnalysisJob{
			ID:             "job-123",
			SourceType:     jobs.SourceTypeUpload,
			Status:         jobs.StatusCompleted,
			MIMEType:       &mime,
			SHA256Hash:     &sha,
			Score:          &score,
			AIScore:        &ai,
			RiskLevel:      &risk,
			CreatedAt:      now,
			UpdatedAt:      now,
			AnalyzerResult: json.RawMessage(`{"results":[],"iocs":{"urls":[],"ips":[],"domains":[]}}`),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-123/report.json", nil)
	recorder := httptest.NewRecorder()
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "job-123")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))

	handler.JSON(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected json content type, got %q", recorder.Header().Get("Content-Type"))
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode json report: %v", err)
	}
	if payload["schema_version"] != "malcore.report.v1" {
		t.Fatalf("expected report schema version, got %#v", payload["schema_version"])
	}
}

func TestReportHandlerPDFReturnsPDFDocument(t *testing.T) {
	handler := NewReportHandler(&stubReportRepo{
		job: &jobs.AnalysisJob{
			ID:             "job-123",
			SourceType:     jobs.SourceTypeUpload,
			Status:         jobs.StatusCompleted,
			CreatedAt:      time.Now().UTC(),
			UpdatedAt:      time.Now().UTC(),
			AnalyzerResult: json.RawMessage(`{"results":[],"iocs":{"urls":[],"ips":[],"domains":[]}}`),
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/job-123/report.pdf", nil)
	recorder := httptest.NewRecorder()
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "job-123")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))

	handler.PDF(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "application/pdf" {
		t.Fatalf("expected pdf content type, got %q", recorder.Header().Get("Content-Type"))
	}
	if body := recorder.Body.String(); len(body) < 8 || body[:8] != "%PDF-1.4" {
		t.Fatalf("expected pdf output, got %q", body)
	}
}

func TestReportHandlerReturnsNotFound(t *testing.T) {
	handler := NewReportHandler(&stubReportRepo{err: pgx.ErrNoRows})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/missing/report.json", nil)
	recorder := httptest.NewRecorder()
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", "missing")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))

	handler.JSON(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, recorder.Code)
	}
}
