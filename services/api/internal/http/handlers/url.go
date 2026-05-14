package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/nijat-akhundzada/malcore/services/api/internal/downloader"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/storage"
)

type URLHandler struct {
	log        *slog.Logger
	repo       *jobs.Repository
	downloader downloader.Downloader
	storage    storage.Storage
}

func NewURLHandler(log *slog.Logger, repo *jobs.Repository, dl downloader.Downloader, store storage.Storage) *URLHandler {
	return &URLHandler{
		log:        log,
		repo:       repo,
		downloader: dl,
		storage:    store,
	}
}

type URLSubmitRequest struct {
	URL string `json:"url"`
}

type URLSubmitResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

func (h *URLHandler) Submit(w http.ResponseWriter, r *http.Request) {
	var req URLSubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.URL == "" {
		writeJSONError(w, http.StatusBadRequest, "url is required")
		return
	}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid url format")
		return
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		writeJSONError(w, http.StatusBadRequest, "only http and https are supported")
		return
	}

	// Use the robust downloader service
	result, err := h.downloader.Download(r.Context(), req.URL)
	if err != nil {
		h.log.Error("download failed", slog.String("url", req.URL), slog.String("error", err.Error()))
		writeJSONError(w, http.StatusBadRequest, "failed to reach or download URL: "+err.Error())
		return
	}
	defer result.Body.Close()

	h.log.Debug("url verified and metadata captured",
		slog.String("url", req.URL),
		slog.String("content_type", result.ContentType),
		slog.Int64("content_length", result.ContentLength),
	)

	// Create job
	job, err := h.repo.Create(r.Context(), jobs.SourceTypeURL)
	if err != nil {
		h.log.Error("failed to create job", slog.String("error", err.Error()))
		writeJSONError(w, http.StatusInternalServerError, "failed to create job")
		return
	}

	// Save downloaded content to secure storage
	storagePath, sErr := h.storage.Save(job.ID, result.Body)
	if sErr != nil {
		h.log.Error("failed to save download to storage", slog.String("job_id", job.ID), slog.String("error", sErr.Error()))
		writeJSONError(w, http.StatusInternalServerError, "failed to store downloaded file")
		return
	}

	h.log.Info("URL submission stored successfully",
		slog.String("job_id", job.ID),
		slog.String("path", storagePath),
	)

	writeJSON(w, http.StatusCreated, URLSubmitResponse{
		JobID:  job.ID,
		Status: string(job.Status),
	})
}
