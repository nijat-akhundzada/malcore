package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
	"github.com/nijat-akhundzada/malcore/services/api/internal/storage"
)

type fakeJobRepo struct {
	created                 int
	fileMetadataUpdated     int
	sourceType              jobs.SourceType
	md5Hash                 string
	sha256Hash              string
	storageKey              string
	originalStorageKey      string
	quarantineStorageKey    string
	mimeType                string
	fileExtension           string
	mimeExtensionMismatch   bool
	sizeBytes               int64
	fileMetadataUpdateJobID string
	statusUpdated           int
	statusJobID             string
	status                  jobs.JobStatus
}

func (r *fakeJobRepo) Create(ctx context.Context, sourceType jobs.SourceType) (*jobs.AnalysisJob, error) {
	r.created++
	r.sourceType = sourceType

	return &jobs.AnalysisJob{
		ID:         "job-123",
		SourceType: sourceType,
		Status:     jobs.StatusPending,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}, nil
}

func (r *fakeJobRepo) UpdateFileMetadata(ctx context.Context, id string, md5Hash, sha256Hash, storageKey, originalStorageKey, quarantineStorageKey, mimeType, fileExtension string, mimeExtensionMismatch bool, sizeBytes int64) error {
	r.fileMetadataUpdated++
	r.fileMetadataUpdateJobID = id
	r.md5Hash = md5Hash
	r.sha256Hash = sha256Hash
	r.storageKey = storageKey
	r.originalStorageKey = originalStorageKey
	r.quarantineStorageKey = quarantineStorageKey
	r.mimeType = mimeType
	r.fileExtension = fileExtension
	r.mimeExtensionMismatch = mimeExtensionMismatch
	r.sizeBytes = sizeBytes
	return nil
}

func (r *fakeJobRepo) UpdateStatus(ctx context.Context, id string, status jobs.JobStatus) error {
	r.statusUpdated++
	r.statusJobID = id
	r.status = status
	return nil
}

type fakeEnqueuer struct {
	enqueued int
	payload  queue.AnalyzeFilePayload
}

func (e *fakeEnqueuer) EnqueueAnalyzeFile(ctx context.Context, payload queue.AnalyzeFilePayload) error {
	e.enqueued++
	e.payload = payload
	return nil
}

type fakeStorage struct {
	saved int
	body  []byte
}

func (s *fakeStorage) Save(ctx context.Context, jobID string, originalName string, reader io.Reader) (*storage.SaveResult, error) {
	s.saved++

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	s.body = body

	return &storage.SaveResult{
		Path:                  "storage/quarantine/" + jobID + "/file.bin",
		StorageKey:            "quarantine/" + jobID + "/file.bin",
		OriginalStorageKey:    "original/" + jobID + "/file.bin",
		QuarantineStorageKey:  "quarantine/" + jobID + "/file.bin",
		MD5Hash:               "5d41402abc4b2a76b9719d911017c592",
		SHA256Hash:            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		MIMEType:              "text/plain",
		FileExtension:         ".bin",
		MIMEExtensionMismatch: false,
		SizeBytes:             int64(len(body)),
	}, nil
}

func TestUploadCreatesJob(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	enqueuer := &fakeEnqueuer{}
	handler := NewUploadHandler(testLogger(), repo, store, enqueuer)

	req := multipartUploadRequest(t, "file", "sample.bin", []byte("hello"))
	res := httptest.NewRecorder()

	handler.Upload(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusCreated, res.Code, res.Body.String())
	}

	var payload UploadResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.JobID != "job-123" {
		t.Fatalf("expected job_id job-123, got %q", payload.JobID)
	}

	if payload.Status != string(jobs.StatusQueued) {
		t.Fatalf("expected status queued, got %q", payload.Status)
	}

	if repo.created != 1 || repo.sourceType != jobs.SourceTypeUpload {
		t.Fatalf("expected one upload job, got created=%d source=%q", repo.created, repo.sourceType)
	}

	if store.saved != 1 || string(store.body) != "hello" {
		t.Fatalf("expected stored upload body, got saved=%d body=%q", store.saved, string(store.body))
	}

	if repo.fileMetadataUpdated != 1 || repo.fileMetadataUpdateJobID != "job-123" {
		t.Fatalf("expected metadata update for job-123, got updated=%d job_id=%q", repo.fileMetadataUpdated, repo.fileMetadataUpdateJobID)
	}

	if repo.md5Hash != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("expected md5 hash to be stored, got %q", repo.md5Hash)
	}

	if repo.sha256Hash != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("expected sha256 hash to be stored, got %q", repo.sha256Hash)
	}

	if repo.storageKey != "quarantine/job-123/file.bin" {
		t.Fatalf("expected storage key to be stored, got %q", repo.storageKey)
	}

	if repo.originalStorageKey != "original/job-123/file.bin" || repo.quarantineStorageKey != "quarantine/job-123/file.bin" {
		t.Fatalf("expected original/quarantine keys to be stored, got original=%q quarantine=%q", repo.originalStorageKey, repo.quarantineStorageKey)
	}

	if repo.mimeType != "text/plain" || repo.fileExtension != ".bin" || repo.mimeExtensionMismatch || repo.sizeBytes != 5 {
		t.Fatalf("expected file metadata to be stored, got mime=%q ext=%q mismatch=%v size=%d", repo.mimeType, repo.fileExtension, repo.mimeExtensionMismatch, repo.sizeBytes)
	}

	if enqueuer.enqueued != 1 {
		t.Fatalf("expected one queued analysis task, got %d", enqueuer.enqueued)
	}

	if enqueuer.payload.JobID != "job-123" || enqueuer.payload.QuarantineStorageKey != "quarantine/job-123/file.bin" || enqueuer.payload.SHA256Hash != repo.sha256Hash {
		t.Fatalf("unexpected queue payload: %+v", enqueuer.payload)
	}

	if repo.statusUpdated != 1 || repo.statusJobID != "job-123" || repo.status != jobs.StatusQueued {
		t.Fatalf("expected queued status update, got count=%d job_id=%q status=%q", repo.statusUpdated, repo.statusJobID, repo.status)
	}
}

func TestUploadRejectsMissingFile(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	handler := NewUploadHandler(testLogger(), repo, store, &fakeEnqueuer{})

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	res := httptest.NewRecorder()

	handler.Upload(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, res.Code)
	}

	if repo.created != 0 || store.saved != 0 {
		t.Fatalf("expected no job/storage calls, got created=%d saved=%d", repo.created, store.saved)
	}
}

func TestUploadRejectsEmptyFile(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	handler := NewUploadHandler(testLogger(), repo, store, &fakeEnqueuer{})

	req := multipartUploadRequest(t, "file", "empty.bin", nil)
	res := httptest.NewRecorder()

	handler.Upload(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, res.Code)
	}

	if !strings.Contains(res.Body.String(), "empty file") {
		t.Fatalf("expected empty file error, got %s", res.Body.String())
	}

	if repo.created != 0 || store.saved != 0 {
		t.Fatalf("expected no job/storage calls, got created=%d saved=%d", repo.created, store.saved)
	}
}

func TestUploadRejectsFileLargerThanLimit(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	handler := NewUploadHandler(testLogger(), repo, store, &fakeEnqueuer{})

	req := multipartUploadRequest(t, "file", "large.bin", bytes.Repeat([]byte("x"), maxUploadFileSize+1))
	res := httptest.NewRecorder()

	handler.Upload(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusBadRequest, res.Code, res.Body.String())
	}

	if repo.created != 0 || store.saved != 0 {
		t.Fatalf("expected no job/storage calls, got created=%d saved=%d", repo.created, store.saved)
	}
}

func multipartUploadRequest(t *testing.T, fieldName, filename string, content []byte) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}

	if _, err := part.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/files/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
