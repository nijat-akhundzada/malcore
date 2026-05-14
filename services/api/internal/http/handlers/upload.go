package handlers

import (
	"log/slog"
	"net/http"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/storage"
)

type UploadHandler struct {
	log     *slog.Logger
	repo    *jobs.Repository
	storage storage.Storage
}

func NewUploadHandler(log *slog.Logger, repo *jobs.Repository, store storage.Storage) *UploadHandler {
	return &UploadHandler{
		log:     log,
		repo:    repo,
		storage: store,
	}
}

type UploadResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

func (h *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	// Limit upload size to 10MB + 32KB overhead
	r.Body = http.MaxBytesReader(w, r.Body, (10<<20)+(32<<10))

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		h.log.Error("failed to parse multipart form", slog.String("error", err.Error()))
		writeJSONError(w, http.StatusBadRequest, "file too large or invalid multipart form")
		return
	}

	uploadType := r.FormValue("uploadType")
	h.log.Debug("processing upload request", slog.String("type", uploadType))

	var job *jobs.AnalysisJob
	var err error

	switch uploadType {
	case "file":
		f, _, fErr := r.FormFile("file")
		if fErr != nil {
			writeJSONError(w, http.StatusBadRequest, "file is required for file upload")
			return
		}
		defer f.Close()

		if r.MultipartForm.File["file"][0].Size == 0 {
			writeJSONError(w, http.StatusBadRequest, "empty file")
			return
		}

		job, err = h.repo.Create(r.Context(), jobs.SourceTypeUpload)
		if err == nil && job != nil {
			// Save file to secure storage
			storagePath, sErr := h.storage.Save(job.ID, f)
			if sErr != nil {
				h.log.Error("failed to save upload to storage", slog.String("job_id", job.ID), slog.String("error", sErr.Error()))
				writeJSONError(w, http.StatusInternalServerError, "failed to store uploaded file")
				return
			}
			h.log.Info("file upload stored successfully", slog.String("job_id", job.ID), slog.String("path", storagePath))
		}
	case "url":
		url := r.FormValue("url")
		if url == "" {
			writeJSONError(w, http.StatusBadRequest, "url is required for url upload")
			return
		}
		job, err = h.repo.Create(r.Context(), jobs.SourceTypeURL)
	default:
		writeJSONError(w, http.StatusBadRequest, "invalid uploadType")
		return
	}

	if err != nil {
		h.log.Error("failed to create job",
			slog.String("error", err.Error()),
			slog.String("type", uploadType),
		)
		writeJSONError(w, http.StatusInternalServerError, "failed to create job: "+err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, UploadResponse{
		JobID:  job.ID,
		Status: string(job.Status),
	})
}
