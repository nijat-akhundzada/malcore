package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

type JobHandler struct {
	repo *jobs.Repository
}

func NewJobHandler(repo *jobs.Repository) *JobHandler {
	return &JobHandler{repo: repo}
}

type CreateJobRequest struct {
	SourceType jobs.SourceType `json:"source_type"`
}

type JobResponse struct {
	ID           string          `json:"id"`
	SourceType   jobs.SourceType `json:"source_type"`
	Status       jobs.JobStatus  `json:"status"`
	Score        *int            `json:"score"`
	RiskLevel    *jobs.RiskLevel `json:"risk_level"`
	ErrorMessage *string         `json:"error_message"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

func (h *JobHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateJobRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.SourceType != jobs.SourceTypeUpload && req.SourceType != jobs.SourceTypeURL {
		writeJSONError(w, http.StatusBadRequest, "source_type must be upload or url")
		return
	}

	job, err := h.repo.Create(r.Context(), req.SourceType)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create job")
		return
	}

	writeJSON(w, http.StatusCreated, toJobResponse(job))
}

func (h *JobHandler) FindByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	job, err := h.repo.FindByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "job not found")
			return
		}

		writeJSONError(w, http.StatusInternalServerError, "failed to fetch job")
		return
	}

	writeJSON(w, http.StatusOK, toJobResponse(job))
}

func toJobResponse(job *jobs.AnalysisJob) JobResponse {
	return JobResponse{
		ID:           job.ID,
		SourceType:   job.SourceType,
		Status:       job.Status,
		Score:        job.Score,
		RiskLevel:    job.RiskLevel,
		ErrorMessage: job.ErrorMessage,
		CreatedAt:    job.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    job.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
