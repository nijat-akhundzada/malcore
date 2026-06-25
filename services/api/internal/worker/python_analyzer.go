package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
)

type PythonAnalyzerOptions struct {
	Command    string
	ScriptPath string
	Timeout    time.Duration
	Fetcher    ObjectFetcher
}

type PythonAnalyzer struct {
	command    string
	scriptPath string
	timeout    time.Duration
	fetcher    ObjectFetcher
}

type analyzerOutput struct {
	Results []analyzerModuleResult `json:"results"`
}

type analyzerModuleResult struct {
	Findings []analyzerFinding `json:"findings"`
}

type analyzerFinding struct {
	Severity string `json:"severity"`
}

func NewPythonAnalyzer(options PythonAnalyzerOptions) (*PythonAnalyzer, error) {
	command := strings.TrimSpace(options.Command)
	if command == "" {
		command = "python3"
	}

	scriptPath := strings.TrimSpace(options.ScriptPath)
	if scriptPath == "" {
		return nil, fmt.Errorf("analyzer script path is required")
	}

	if options.Fetcher == nil {
		return nil, fmt.Errorf("analyzer object fetcher is required")
	}

	return &PythonAnalyzer{
		command:    command,
		scriptPath: scriptPath,
		timeout:    options.Timeout,
		fetcher:    options.Fetcher,
	}, nil
}

func (a *PythonAnalyzer) Analyze(ctx context.Context, payload queue.AnalyzeFilePayload) (*AnalysisResult, error) {
	key := payload.QuarantineStorageKey
	if key == "" {
		key = payload.StorageKey
	}
	if key == "" {
		return nil, fmt.Errorf("analyze file payload missing quarantine storage key")
	}

	filePath, cleanup, err := a.fetcher.Fetch(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("fetch analyzer input: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	analysisCtx := ctx
	cancel := func() {}
	if a.timeout > 0 {
		analysisCtx, cancel = context.WithTimeout(ctx, a.timeout)
	}
	defer cancel()

	output, err := a.runCLI(analysisCtx, filePath)
	if err != nil {
		return nil, err
	}

	return resultFromAnalyzerOutput(output), nil
}

func (a *PythonAnalyzer) runCLI(ctx context.Context, filePath string) (*analyzerOutput, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, a.command, a.scriptPath, filePath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("python analyzer timed out")
		}

		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = strings.TrimSpace(stdout.String())
		}
		if message == "" {
			return nil, fmt.Errorf("run python analyzer: %w", err)
		}

		return nil, fmt.Errorf("run python analyzer: %w: %s", err, message)
	}

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("python analyzer returned empty output")
	}

	var output analyzerOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("decode python analyzer output: %w", err)
	}

	return &output, nil
}

func resultFromAnalyzerOutput(output *analyzerOutput) *AnalysisResult {
	score := 0

	for _, module := range output.Results {
		for _, finding := range module.Findings {
			if findingScore := scoreForSeverity(finding.Severity); findingScore > score {
				score = findingScore
			}
		}
	}

	return &AnalysisResult{
		Score:     score,
		RiskLevel: riskLevelForScore(score),
	}
}

func scoreForSeverity(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 50
	case "low":
		return 15
	default:
		return 0
	}
}

func riskLevelForScore(score int) jobs.RiskLevel {
	switch {
	case score >= 90:
		return jobs.RiskCritical
	case score >= 70:
		return jobs.RiskHigh
	case score >= 40:
		return jobs.RiskMedium
	default:
		return jobs.RiskLow
	}
}
