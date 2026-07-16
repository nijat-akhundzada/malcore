package worker

import (
	"context"
	"encoding/json"
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
	scriptPath := writeAnalyzerScript(t, `{"results":[{"analyzer":"scripts","findings":[{"type":"script_dynamic_execution","severity":"medium"}]}]}`)
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

	if result.Score != 34 || result.AIScore != 10 || result.RiskLevel != jobs.RiskMedium {
		t.Fatalf("expected medium risk result, got score=%d ai_score=%d risk=%q", result.Score, result.AIScore, result.RiskLevel)
	}

	var stored map[string]any
	if err := json.Unmarshal(result.AnalyzerResult, &stored); err != nil {
		t.Fatalf("decode stored analyzer result: %v", err)
	}

	scoring, ok := stored["scoring"].(map[string]any)
	if !ok {
		t.Fatalf("expected scoring block in analyzer result, got %s", string(result.AnalyzerResult))
	}
	if scoring["rule_score"] != float64(50) || scoring["ai_score"] != float64(10) {
		t.Fatalf("expected scoring block with rule=50 ai=10, got %#v", scoring)
	}
	if scoring["final_score"] != float64(34) || scoring["final_risk_level"] != "medium" {
		t.Fatalf("expected scoring block with final score and risk, got %#v", scoring)
	}
	if !fetcher.cleanupCalled {
		t.Fatalf("expected fetched input cleanup to be called")
	}
}

func TestPythonAnalyzerPassesArchivePasswordToCLIEnvironment(t *testing.T) {
	scriptPath := writeRawAnalyzerScript(t, `#!/bin/sh
if [ "$MALCORE_ARCHIVE_PASSWORD" != "secret" ]; then
  echo "missing password" >&2
  exit 2
fi
printf '%s\n' '{"results":[{"findings":[]}]}'
`)
	inputPath := filepath.Join(t.TempDir(), "sample.zip")
	if err := os.WriteFile(inputPath, []byte("PK\x03\x04"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}

	analyzer, err := NewPythonAnalyzer(PythonAnalyzerOptions{
		Command:    "/bin/sh",
		ScriptPath: scriptPath,
		Timeout:    5 * time.Second,
		Fetcher:    &fakeObjectFetcher{path: inputPath},
	})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}

	if _, err := analyzer.Analyze(context.Background(), queue.AnalyzeFilePayload{
		QuarantineStorageKey: "quarantine/job-123/archive.zip",
		ArchivePassword:      "secret",
	}); err != nil {
		t.Fatalf("analyze: %v", err)
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

	return writeRawAnalyzerScript(t, "#!/bin/sh\nprintf '%s\\n' '"+output+"'\n")
}

func writeRawAnalyzerScript(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "analyzer.sh")
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("write analyzer script: %v", err)
	}

	return path
}
