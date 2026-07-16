package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/reports"
)

type reportJobFinder interface {
	FindByID(ctx context.Context, id string) (*jobs.AnalysisJob, error)
}

type ReportHandler struct {
	repo reportJobFinder
}

func NewReportHandler(repo reportJobFinder) *ReportHandler {
	return &ReportHandler{repo: repo}
}

func (h *ReportHandler) JSON(w http.ResponseWriter, r *http.Request) {
	report, err := h.loadReport(r)
	if err != nil {
		h.handleError(w, err)
		return
	}

	filename := fmt.Sprintf("malcore-report-%s.json", report.Job.ID)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(report)
}

func (h *ReportHandler) PDF(w http.ResponseWriter, r *http.Request) {
	report, err := h.loadReport(r)
	if err != nil {
		h.handleError(w, err)
		return
	}

	document, err := reports.RenderPDF(report)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate PDF report")
		return
	}

	filename := fmt.Sprintf("malcore-report-%s.pdf", report.Job.ID)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}

func (h *ReportHandler) loadReport(r *http.Request) (*reports.Report, error) {
	id := chi.URLParam(r, "id")
	job, err := h.repo.FindByID(r.Context(), id)
	if err != nil {
		return nil, err
	}

	return reports.Build(job)
}

func (h *ReportHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		writeJSONError(w, http.StatusNotFound, "job not found")
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "failed to build report")
	}
}
