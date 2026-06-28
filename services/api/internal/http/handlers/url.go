package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/nijat-akhundzada/malcore/services/api/internal/downloader"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
	"github.com/nijat-akhundzada/malcore/services/api/internal/storage"
)

type URLHandler struct {
	log        *slog.Logger
	repo       jobCreator
	downloader downloader.Downloader
	storage    storage.Storage
	enqueuer   queue.Enqueuer
}

func NewURLHandler(log *slog.Logger, repo jobCreator, dl downloader.Downloader, store storage.Storage, enqueuer queue.Enqueuer) *URLHandler {
	return &URLHandler{
		log:        log,
		repo:       repo,
		downloader: dl,
		storage:    store,
		enqueuer:   enqueuer,
	}
}

type URLSubmitRequest struct {
	URL             string `json:"url"`
	ArchivePassword string `json:"archive_password,omitempty"`
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

	archivePassword, err := normalizeArchivePassword(req.ArchivePassword)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	result, err := h.downloader.Download(r.Context(), req.URL)
	if err != nil {
		h.log.Error("download failed", slog.String("url", req.URL), slog.String("error", err.Error()))
		writeJSONError(w, http.StatusBadRequest, "failed to reach or download URL: "+err.Error())
		return
	}
	defer result.Body.Close()

	h.log.Debug("url verified and metadata captured",
		slog.String("url", req.URL),
		slog.String("final_url", result.FinalURL),
		slog.String("reported_content_type", result.ContentType),
		slog.Int64("content_length", result.ContentLength),
	)

	job, err := h.repo.Create(r.Context(), jobs.SourceTypeURL)
	if err != nil {
		h.log.Error("failed to create job", slog.String("error", err.Error()))
		writeJSONError(w, http.StatusInternalServerError, "failed to create job")
		return
	}

	saveResult, sErr := h.storage.Save(r.Context(), job.ID, result.FinalURL, result.Body)
	if sErr != nil {
		h.log.Error("failed to save download to storage", slog.String("job_id", job.ID), slog.String("error", sErr.Error()))
		writeJSONError(w, http.StatusInternalServerError, "failed to store downloaded file")
		return
	}

	if err := h.repo.UpdateFileMetadata(
		r.Context(),
		job.ID,
		saveResult.MD5Hash,
		saveResult.SHA256Hash,
		saveResult.StorageKey,
		saveResult.OriginalStorageKey,
		saveResult.QuarantineStorageKey,
		saveResult.MIMEType,
		saveResult.FileExtension,
		saveResult.MIMEExtensionMismatch,
		saveResult.SizeBytes,
	); err != nil {
		h.log.Error("failed to store file metadata", slog.String("job_id", job.ID), slog.String("error", err.Error()))
		writeJSONError(w, http.StatusInternalServerError, "failed to store file metadata")
		return
	}

	if err := enqueueAnalysis(r.Context(), h.repo, h.enqueuer, job.ID, saveResult, archivePassword); err != nil {
		h.log.Error("failed to queue analysis job", slog.String("job_id", job.ID), slog.String("error", err.Error()))
		writeJSONError(w, http.StatusInternalServerError, "failed to queue analysis job")
		return
	}

	h.log.Info("URL submission stored successfully",
		slog.String("job_id", job.ID),
		slog.String("final_url", result.FinalURL),
		slog.String("content_type", result.ContentType),
		slog.String("path", saveResult.Path),
		slog.String("storage_key", saveResult.StorageKey),
		slog.String("original_storage_key", saveResult.OriginalStorageKey),
		slog.String("quarantine_storage_key", saveResult.QuarantineStorageKey),
		slog.String("md5_hash", saveResult.MD5Hash),
		slog.String("sha256_hash", saveResult.SHA256Hash),
		slog.String("mime_type", saveResult.MIMEType),
		slog.String("file_extension", saveResult.FileExtension),
		slog.Bool("mime_extension_mismatch", saveResult.MIMEExtensionMismatch),
		slog.Int64("size_bytes", saveResult.SizeBytes),
	)

	writeJSON(w, http.StatusCreated, URLSubmitResponse{
		JobID:  job.ID,
		Status: string(jobs.StatusQueued),
	})
}
