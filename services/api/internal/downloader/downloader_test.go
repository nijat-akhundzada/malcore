package downloader

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDownloadFollowsRedirectsAndCapturesHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/payload", http.StatusFound)
		case "/payload":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("X-Malcore-Test", "yes")
			_, _ = w.Write([]byte("downloaded"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	result, err := testDownloader().Download(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "downloaded" {
		t.Fatalf("expected downloaded body, got %q", string(body))
	}

	if result.ContentType != "application/octet-stream" {
		t.Fatalf("expected content type, got %q", result.ContentType)
	}

	if result.Headers.Get("X-Malcore-Test") != "yes" {
		t.Fatalf("expected captured header")
	}

	if result.FinalURL != server.URL+"/payload" {
		t.Fatalf("expected final redirected URL, got %q", result.FinalURL)
	}
}

func TestDownloadRejectsOversizedContentLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "6")
		_, _ = w.Write([]byte("toolarge"))
	}))
	defer server.Close()

	downloader := New(testLogger(), Options{
		MaxSize:            5,
		MaxAttempts:        3,
		RetryDelay:         time.Nanosecond,
		AllowInternalHosts: true,
	})

	_, err := downloader.Download(context.Background(), server.URL)
	if !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("expected ErrDownloadTooLarge, got %v", err)
	}
}

func TestDownloadRejectsOversizedBodyWithoutContentLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("toolarge"))
	}))
	defer server.Close()

	downloader := New(testLogger(), Options{
		MaxSize:            5,
		MaxAttempts:        3,
		RetryDelay:         time.Nanosecond,
		AllowInternalHosts: true,
	})

	_, err := downloader.Download(context.Background(), server.URL)
	if !errors.Is(err, ErrDownloadTooLarge) {
		t.Fatalf("expected ErrDownloadTooLarge, got %v", err)
	}
}

func TestDownloadRetriesServerErrors(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}

		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result, err := testDownloader().Download(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	defer result.Body.Close()

	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestDownloadDoesNotRetryClientErrors(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer server.Close()

	_, err := testDownloader().Download(context.Background(), server.URL)
	if err == nil {
		t.Fatalf("expected error")
	}

	if attempts != 1 {
		t.Fatalf("expected one attempt, got %d", attempts)
	}
}

func TestDownloadRejectsLocalhost(t *testing.T) {
	downloader := New(testLogger(), Options{
		MaxAttempts: 1,
		RetryDelay:  time.Nanosecond,
	})

	_, err := downloader.Download(context.Background(), "http://localhost/file.bin")
	if err == nil {
		t.Fatalf("expected localhost to be blocked")
	}
}

func testDownloader() *DefaultDownloader {
	return New(testLogger(), Options{
		MaxSize:            DefaultMaxDownloadSize,
		MaxAttempts:        3,
		RetryDelay:         time.Nanosecond,
		AllowInternalHosts: true,
	})
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
