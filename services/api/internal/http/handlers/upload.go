package handlers

import (
	"context"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
	"github.com/nijat-akhundzada/malcore/services/api/internal/storage"
)

const (
	maxUploadFileSize       = 10 << 20
	maxUploadOverhead       = 32 << 10
	maxArchivePasswordBytes = 512
)

type jobCreator interface {
	Create(ctx context.Context, sourceType jobs.SourceType) (*jobs.AnalysisJob, error)
	UpdateFileMetadata(ctx context.Context, id string, md5Hash, sha256Hash, storageKey, originalStorageKey, quarantineStorageKey, mimeType, fileExtension string, mimeExtensionMismatch bool, sizeBytes int64) error
	UpdateStatus(ctx context.Context, id string, status jobs.JobStatus) error
}

type UploadHandler struct {
	log      *slog.Logger
	repo     jobCreator
	storage  storage.Storage
	enqueuer queue.Enqueuer
}

func NewUploadHandler(log *slog.Logger, repo jobCreator, store storage.Storage, enqueuer queue.Enqueuer) *UploadHandler {
	return &UploadHandler{
		log:      log,
		repo:     repo,
		storage:  store,
		enqueuer: enqueuer,
	}
}

type UploadResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

func (h *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadFileSize+maxUploadOverhead)

	if err := r.ParseMultipartForm(maxUploadFileSize); err != nil {
		h.log.Error("failed to parse multipart form", slog.String("error", err.Error()))
		writeJSONError(w, http.StatusBadRequest, "file too large or invalid multipart form")
		return
	}

	archivePassword, err := normalizeArchivePassword(r.FormValue("archive_password"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	file, header, err := validatedFile(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer file.Close()

	job, err := h.repo.Create(r.Context(), jobs.SourceTypeUpload)
	if err != nil {
		h.log.Error("failed to create job",
			slog.String("error", err.Error()),
			slog.String("type", string(jobs.SourceTypeUpload)),
		)
		writeJSONError(w, http.StatusInternalServerError, "failed to create job")
		return
	}

	saveResult, err := h.storage.Save(r.Context(), job.ID, header.Filename, file)
	if err != nil {
		h.log.Error("failed to save upload to storage", slog.String("job_id", job.ID), slog.String("error", err.Error()))
		writeJSONError(w, http.StatusInternalServerError, "failed to store uploaded file")
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

	h.log.Info("file upload stored successfully",
		slog.String("job_id", job.ID),
		slog.String("filename", header.Filename),
		slog.Int64("size", header.Size),
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

	writeJSON(w, http.StatusCreated, UploadResponse{
		JobID:  job.ID,
		Status: string(jobs.StatusQueued),
	})
}

func enqueueAnalysis(ctx context.Context, repo jobCreator, enqueuer queue.Enqueuer, jobID string, saveResult *storage.SaveResult, archivePassword string) error {
	if err := enqueuer.EnqueueAnalyzeFile(ctx, queue.AnalyzeFilePayload{
		JobID:                jobID,
		StorageKey:           saveResult.StorageKey,
		OriginalStorageKey:   saveResult.OriginalStorageKey,
		QuarantineStorageKey: saveResult.QuarantineStorageKey,
		MIMEType:             saveResult.MIMEType,
		SHA256Hash:           saveResult.SHA256Hash,
		ArchivePassword:      archivePassword,
	}); err != nil {
		return err
	}

	return repo.UpdateStatus(ctx, jobID, jobs.StatusQueued)
}

func validatedFile(r *http.Request) (multipart.File, *multipart.FileHeader, error) {
	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, nil, errInvalidUpload("file is required")
	}

	if header == nil || strings.TrimSpace(header.Filename) == "" {
		_ = file.Close()
		return nil, nil, errInvalidUpload("invalid file")
	}

	if header.Size <= 0 {
		_ = file.Close()
		return nil, nil, errInvalidUpload("empty file")
	}

	if header.Size > maxUploadFileSize {
		_ = file.Close()
		return nil, nil, errInvalidUpload("file too large")
	}

	return file, header, nil
}

func normalizeArchivePassword(password string) (string, error) {
	if len(password) > maxArchivePasswordBytes {
		return "", errInvalidUpload("archive password too long")
	}

	if strings.Contains(password, "\x00") {
		return "", errInvalidUpload("archive password contains invalid characters")
	}

	return password, nil
}

type errInvalidUpload string

func (e errInvalidUpload) Error() string {
	return string(e)
}
