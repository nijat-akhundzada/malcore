package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultDockerCommand = "docker"
	DefaultImage         = "alpine:3.22"
	DefaultTimeout       = 10 * time.Second
	DefaultMemory        = "256m"
	DefaultCPUs          = "1"
	DefaultPidsLimit     = 64
	DefaultTmpfsSize     = "64m"
	DefaultUser          = "65534:65534"
	DefaultWorkDir       = "/malcore"
	DefaultOutputLimit   = 64 * 1024

	ContainerInputPath = "/malcore/input"
)

type DockerRunnerOptions struct {
	DockerCommand string
	Image         string
	Timeout       time.Duration
	Memory        string
	CPUs          string
	PidsLimit     int
	TmpfsSize     string
	User          string
	WorkDir       string
	OutputLimit   int64
	Executor      CommandExecutor
}

type RunRequest struct {
	FilePath string
	Command  []string
	Timeout  time.Duration
}

type Result struct {
	Sandbox         string   `json:"sandbox"`
	Image           string   `json:"image"`
	ContainerName   string   `json:"container_name"`
	InputPath       string   `json:"input_path"`
	Command         []string `json:"command"`
	ExitCode        int      `json:"exit_code"`
	TimedOut        bool     `json:"timed_out"`
	DurationMS      int64    `json:"duration_ms"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	StderrTruncated bool     `json:"stderr_truncated"`
}

type CommandOutput struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	StdoutTruncated bool
	StderrTruncated bool
	Err             error
}

type CommandExecutor interface {
	Execute(ctx context.Context, name string, args []string, outputLimit int64) CommandOutput
}

type DockerRunner struct {
	dockerCommand string
	image         string
	timeout       time.Duration
	memory        string
	cpus          string
	pidsLimit     int
	tmpfsSize     string
	user          string
	workDir       string
	outputLimit   int64
	executor      CommandExecutor
}

func NewDockerRunner(options DockerRunnerOptions) (*DockerRunner, error) {
	runner := &DockerRunner{
		dockerCommand: strings.TrimSpace(options.DockerCommand),
		image:         strings.TrimSpace(options.Image),
		timeout:       options.Timeout,
		memory:        strings.TrimSpace(options.Memory),
		cpus:          strings.TrimSpace(options.CPUs),
		pidsLimit:     options.PidsLimit,
		tmpfsSize:     strings.TrimSpace(options.TmpfsSize),
		user:          strings.TrimSpace(options.User),
		workDir:       strings.TrimSpace(options.WorkDir),
		outputLimit:   options.OutputLimit,
		executor:      options.Executor,
	}

	if runner.dockerCommand == "" {
		runner.dockerCommand = DefaultDockerCommand
	}
	if runner.image == "" {
		runner.image = DefaultImage
	}
	if runner.timeout <= 0 {
		runner.timeout = DefaultTimeout
	}
	if runner.memory == "" {
		runner.memory = DefaultMemory
	}
	if runner.cpus == "" {
		runner.cpus = DefaultCPUs
	}
	if runner.pidsLimit <= 0 {
		runner.pidsLimit = DefaultPidsLimit
	}
	if runner.tmpfsSize == "" {
		runner.tmpfsSize = DefaultTmpfsSize
	}
	if runner.user == "" {
		runner.user = DefaultUser
	}
	if runner.workDir == "" {
		runner.workDir = DefaultWorkDir
	}
	if runner.outputLimit <= 0 {
		runner.outputLimit = DefaultOutputLimit
	}
	if runner.executor == nil {
		runner.executor = osCommandExecutor{}
	}

	if strings.ContainsAny(runner.image, "\x00\r\n") {
		return nil, fmt.Errorf("sandbox image contains invalid characters")
	}

	return runner, nil
}

func (r *DockerRunner) Run(ctx context.Context, request RunRequest) (*Result, error) {
	inputPath, err := resolveInputPath(request.FilePath)
	if err != nil {
		return nil, err
	}

	command := request.Command
	if len(command) == 0 {
		command = DefaultProbeCommand()
	}

	containerName, err := randomContainerName()
	if err != nil {
		return nil, fmt.Errorf("generate sandbox container name: %w", err)
	}

	timeout := r.timeout
	if request.Timeout > 0 {
		timeout = request.Timeout
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	startedAt := time.Now()
	output := r.executor.Execute(runCtx, r.dockerCommand, r.dockerRunArgs(containerName, inputPath, command), r.outputLimit)
	duration := time.Since(startedAt)
	timedOut := runCtx.Err() == context.DeadlineExceeded

	result := &Result{
		Sandbox:         "docker",
		Image:           r.image,
		ContainerName:   containerName,
		InputPath:       ContainerInputPath,
		Command:         append([]string(nil), command...),
		ExitCode:        output.ExitCode,
		TimedOut:        timedOut,
		DurationMS:      duration.Milliseconds(),
		Stdout:          output.Stdout,
		Stderr:          output.Stderr,
		StdoutTruncated: output.StdoutTruncated,
		StderrTruncated: output.StderrTruncated,
	}

	if timedOut {
		r.forceRemove(containerName)
		return result, nil
	}

	if output.Err != nil && (output.ExitCode == 125 || output.ExitCode == -1) {
		return result, fmt.Errorf("run docker sandbox: %w", output.Err)
	}

	return result, nil
}

func (r *DockerRunner) dockerRunArgs(containerName string, inputPath string, command []string) []string {
	args := []string{
		"run",
		"--rm",
		"--pull=never",
		"--name", containerName,
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", strconv.Itoa(r.pidsLimit),
		"--memory", r.memory,
		"--cpus", r.cpus,
		"--user", r.user,
		"--workdir", r.workDir,
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=" + r.tmpfsSize,
		"--mount", "type=bind,source=" + inputPath + ",target=" + ContainerInputPath + ",readonly",
		r.image,
	}

	return append(args, command...)
}

func (r *DockerRunner) forceRemove(containerName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = r.executor.Execute(ctx, r.dockerCommand, []string{"rm", "-f", containerName}, 4*1024)
}

func DefaultProbeCommand() []string {
	return []string{
		"/bin/sh",
		"-c",
		"test -r " + ContainerInputPath + " && printf 'sandbox-ready\\n'",
	}
}

func resolveInputPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("sandbox input file is required")
	}
	if strings.Contains(trimmed, "\x00") {
		return "", fmt.Errorf("sandbox input file contains invalid characters")
	}

	absolute, err := filepath.Abs(trimmed)
	if err != nil {
		return "", fmt.Errorf("resolve sandbox input path: %w", err)
	}

	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve sandbox input symlink: %w", err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat sandbox input file: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("sandbox input must be a file")
	}

	return resolved, nil
}

func randomContainerName() (string, error) {
	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return "malcore-sandbox-" + hex.EncodeToString(randomBytes), nil
}

type osCommandExecutor struct{}

func (osCommandExecutor) Execute(ctx context.Context, name string, args []string, outputLimit int64) CommandOutput {
	var stdout cappedBuffer
	var stderr cappedBuffer
	stdout.limit = outputLimit
	stderr.limit = outputLimit

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		exitCode = -1

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	}

	return CommandOutput{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		ExitCode:        exitCode,
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
		Err:             err,
	}
}

type cappedBuffer struct {
	data      []byte
	limit     int64
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.truncated = true
		return len(p), nil
	}

	remaining := int(b.limit) - len(b.data)
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}

	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		b.truncated = true
		return len(p), nil
	}

	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	return string(b.data)
}

func (b *cappedBuffer) Truncated() bool {
	return b.truncated
}
