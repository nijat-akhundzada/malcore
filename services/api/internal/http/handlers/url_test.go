package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nijat-akhundzada/malcore/services/api/internal/downloader"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

type fakeDownloader struct {
	result *downloader.DownloadResult
	err    error
	url    string
}

func (d *fakeDownloader) Download(ctx context.Context, targetURL string) (*downloader.DownloadResult, error) {
	d.url = targetURL

	if d.err != nil {
		return nil, d.err
	}

	return d.result, nil
}

func TestURLSubmitDownloadsFileAndCreatesJob(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	enqueuer := &fakeEnqueuer{}
	dl := &fakeDownloader{
		result: &downloader.DownloadResult{
			Body:          io.NopCloser(bytes.NewBufferString("url-body")),
			ContentType:   "application/octet-stream",
			ContentLength: 8,
			FinalURL:      "https://example.com/file.bin",
		},
	}
	handler := NewURLHandler(testLogger(), repo, dl, store, enqueuer)

	req := jsonRequest(t, URLSubmitRequest{URL: "https://example.com/file.bin"})
	res := httptest.NewRecorder()

	handler.Submit(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusCreated, res.Code, res.Body.String())
	}

	var payload URLSubmitResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if payload.JobID != "job-123" {
		t.Fatalf("expected job_id job-123, got %q", payload.JobID)
	}

	if payload.Status != string(jobs.StatusQueued) {
		t.Fatalf("expected status queued, got %q", payload.Status)
	}

	if dl.url != "https://example.com/file.bin" {
		t.Fatalf("expected downloader URL, got %q", dl.url)
	}

	if repo.created != 1 || repo.sourceType != jobs.SourceTypeURL {
		t.Fatalf("expected one url job, got created=%d source=%q", repo.created, repo.sourceType)
	}

	if store.saved != 1 || string(store.body) != "url-body" {
		t.Fatalf("expected stored download body, got saved=%d body=%q", store.saved, string(store.body))
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

	if repo.mimeType != "text/plain" || repo.fileExtension != ".bin" || repo.mimeExtensionMismatch || repo.sizeBytes != 8 {
		t.Fatalf("expected file metadata to be stored, got mime=%q ext=%q mismatch=%v size=%d", repo.mimeType, repo.fileExtension, repo.mimeExtensionMismatch, repo.sizeBytes)
	}

	if enqueuer.enqueued != 1 || enqueuer.payload.JobID != "job-123" {
		t.Fatalf("expected queued analysis task, got count=%d payload=%+v", enqueuer.enqueued, enqueuer.payload)
	}
}

func TestURLSubmitStoresFileEvenWhenReportedContentTypeIsUnsupported(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	dl := &fakeDownloader{
		result: &downloader.DownloadResult{
			Body:          io.NopCloser(bytes.NewBufferString("<html></html>")),
			ContentType:   "text/html; charset=utf-8",
			ContentLength: 13,
			FinalURL:      "https://example.com/",
		},
	}
	handler := NewURLHandler(testLogger(), repo, dl, store, &fakeEnqueuer{})

	req := jsonRequest(t, URLSubmitRequest{URL: "https://example.com/"})
	res := httptest.NewRecorder()

	handler.Submit(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusCreated, res.Code, res.Body.String())
	}

	if repo.created != 1 || store.saved != 1 || repo.fileMetadataUpdated != 1 {
		t.Fatalf("expected job/storage/metadata calls, got created=%d saved=%d metadata=%d", repo.created, store.saved, repo.fileMetadataUpdated)
	}
}

func TestURLSubmitStoresFileEvenWhenReportedContentTypeIsMissing(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	dl := &fakeDownloader{
		result: &downloader.DownloadResult{
			Body:          io.NopCloser(bytes.NewBufferString("body")),
			ContentLength: 4,
			FinalURL:      "https://example.com/file",
		},
	}
	handler := NewURLHandler(testLogger(), repo, dl, store, &fakeEnqueuer{})

	req := jsonRequest(t, URLSubmitRequest{URL: "https://example.com/file"})
	res := httptest.NewRecorder()

	handler.Submit(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusCreated, res.Code, res.Body.String())
	}

	if repo.created != 1 || store.saved != 1 || repo.fileMetadataUpdated != 1 {
		t.Fatalf("expected job/storage/metadata calls, got created=%d saved=%d metadata=%d", repo.created, store.saved, repo.fileMetadataUpdated)
	}
}

func TestURLSubmitRejectsDownloaderErrorsBeforeJobCreation(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	dl := &fakeDownloader{err: errors.New("blocked internal IP: 127.0.0.1")}
	handler := NewURLHandler(testLogger(), repo, dl, store, &fakeEnqueuer{})

	req := jsonRequest(t, URLSubmitRequest{URL: "http://localhost/file.bin"})
	res := httptest.NewRecorder()

	handler.Submit(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, res.Code)
	}

	if repo.created != 0 || store.saved != 0 {
		t.Fatalf("expected no job/storage calls, got created=%d saved=%d", repo.created, store.saved)
	}
}

func TestURLSubmitRejectsNonHTTPURLs(t *testing.T) {
	repo := &fakeJobRepo{}
	store := &fakeStorage{}
	dl := &fakeDownloader{}
	handler := NewURLHandler(testLogger(), repo, dl, store, &fakeEnqueuer{})

	req := jsonRequest(t, URLSubmitRequest{URL: "file:///etc/passwd"})
	res := httptest.NewRecorder()

	handler.Submit(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, res.Code)
	}

	if dl.url != "" || repo.created != 0 || store.saved != 0 {
		t.Fatalf("expected no downloader/job/storage calls, got url=%q created=%d saved=%d", dl.url, repo.created, store.saved)
	}
}

func jsonRequest(t *testing.T, payload any) *http.Request {
	t.Helper()

	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(payload); err != nil {
		t.Fatalf("encode request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/urls/submit", &body)
	req.Header.Set("Content-Type", "application/json")

	return req
}
