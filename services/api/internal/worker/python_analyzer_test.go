package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
)

type fakeObjectFetcher struct {
	path          string
	err           error
	cleanupCalled bool
}

func (f *fakeObjectFetcher) Fetch(ctx context.Context, key string) (string, func(), error) {
	if f.err != nil {
		return "", nil, f.err
	}

	return f.path, func() {
		f.cleanupCalled = true
	}, nil
}

func TestPythonAnalyzerRunsCLIAndMapsFindingsToRisk(t *testing.T) {
	scriptPath := writeAnalyzerScript(t, `{"results":[{"findings":[{"severity":"medium"}]}]}`)
	inputPath := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(inputPath, []byte("MZ"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	fetcher := &fakeObjectFetcher{path: inputPath}
	analyzer, err := NewPythonAnalyzer(PythonAnalyzerOptions{
		Command:    "/bin/sh",
		ScriptPath: scriptPath,
		Timeout:    5 * time.Second,
		Fetcher:    fetcher,
	})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}

	result, err := analyzer.Analyze(context.Background(), queue.AnalyzeFilePayload{
		QuarantineStorageKey: "quarantine/job-123/file.bin",
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if result.Score != 50 || result.RiskLevel != jobs.RiskMedium {
		t.Fatalf("expected medium risk result, got score=%d risk=%q", result.Score, result.RiskLevel)
	}
	if !fetcher.cleanupCalled {
		t.Fatalf("expected fetched input cleanup to be called")
	}
}

func TestPythonAnalyzerRequiresStorageKey(t *testing.T) {
	analyzer, err := NewPythonAnalyzer(PythonAnalyzerOptions{
		Command:    "/bin/sh",
		ScriptPath: "unused",
		Fetcher:    &fakeObjectFetcher{path: "unused"},
	})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}

	if _, err := analyzer.Analyze(context.Background(), queue.AnalyzeFilePayload{}); err == nil {
		t.Fatalf("expected missing key error")
	}
}

func TestPythonAnalyzerReturnsFetchError(t *testing.T) {
	analyzer, err := NewPythonAnalyzer(PythonAnalyzerOptions{
		Command:    "/bin/sh",
		ScriptPath: "unused",
		Fetcher:    &fakeObjectFetcher{err: errors.New("download failed")},
	})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}

	_, err = analyzer.Analyze(context.Background(), queue.AnalyzeFilePayload{
		QuarantineStorageKey: "quarantine/job-123/file.bin",
	})
	if err == nil {
		t.Fatalf("expected fetch error")
	}
}

func writeAnalyzerScript(t *testing.T, output string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "analyzer.sh")
	content := "#!/bin/sh\nprintf '%s\\n' '" + output + "'\n"
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("write analyzer script: %v", err)
	}

	return path
}
