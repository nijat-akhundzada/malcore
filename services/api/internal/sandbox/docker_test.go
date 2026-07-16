package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordedCommand struct {
	name        string
	args        []string
	outputLimit int64
}

type fakeExecutor struct {
	calls       []recordedCommand
	output      CommandOutput
	blockRun    bool
	cleanupSeen bool
}

func (e *fakeExecutor) Execute(ctx context.Context, name string, args []string, outputLimit int64) CommandOutput {
	e.calls = append(e.calls, recordedCommand{
		name:        name,
		args:        append([]string(nil), args...),
		outputLimit: outputLimit,
	})

	if len(args) >= 1 && args[0] == "rm" {
		e.cleanupSeen = true
		return CommandOutput{ExitCode: 0}
	}

	if e.blockRun {
		<-ctx.Done()
		return CommandOutput{ExitCode: -1, Err: ctx.Err()}
	}

	return e.output
}

func TestDockerRunnerBuildsIsolatedCommand(t *testing.T) {
	inputPath := writeSandboxInput(t)
	executor := &fakeExecutor{
		output: CommandOutput{Stdout: "ok\n", ExitCode: 0},
	}

	runner, err := NewDockerRunner(DockerRunnerOptions{
		DockerCommand: "docker",
		Image:         "malcore-sandbox-test:local",
		Timeout:       time.Second,
		Memory:        "128m",
		CPUs:          "0.5",
		PidsLimit:     32,
		TmpfsSize:     "16m",
		OutputLimit:   4096,
		Executor:      executor,
	})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	result, err := runner.Run(context.Background(), RunRequest{
		FilePath: inputPath,
		Command:  []string{"/bin/sh", "-c", "echo ok"},
	})
	if err != nil {
		t.Fatalf("run sandbox: %v", err)
	}

	if result.ExitCode != 0 || result.Stdout != "ok\n" || result.TimedOut {
		t.Fatalf("unexpected result: %#v", result)
	}

	if len(executor.calls) != 1 {
		t.Fatalf("expected one docker call, got %d", len(executor.calls))
	}

	call := executor.calls[0]
	if call.name != "docker" {
		t.Fatalf("expected docker command, got %q", call.name)
	}
	if call.outputLimit != 4096 {
		t.Fatalf("expected output limit 4096, got %d", call.outputLimit)
	}

	assertArgSequence(t, call.args, "run", "--rm")
	assertArgSequence(t, call.args, "--pull=never")
	assertArgSequence(t, call.args, "--network", "none")
	assertArgSequence(t, call.args, "--read-only")
	assertArgSequence(t, call.args, "--cap-drop", "ALL")
	assertArgSequence(t, call.args, "--security-opt", "no-new-privileges")
	assertArgSequence(t, call.args, "--pids-limit", "32")
	assertArgSequence(t, call.args, "--memory", "128m")
	assertArgSequence(t, call.args, "--cpus", "0.5")
	assertArgSequence(t, call.args, "--user", DefaultUser)
	assertArgSequence(t, call.args, "--workdir", DefaultWorkDir)
	assertArgSequence(t, call.args, "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m")

	mount := argAfter(t, call.args, "--mount")
	if !strings.Contains(mount, "type=bind") ||
		!strings.Contains(mount, "source="+inputPath) ||
		!strings.Contains(mount, "target="+ContainerInputPath) ||
		!strings.Contains(mount, "readonly") {
		t.Fatalf("expected read-only sample bind mount, got %q", mount)
	}

	if call.args[len(call.args)-3] != "/bin/sh" ||
		call.args[len(call.args)-2] != "-c" ||
		call.args[len(call.args)-1] != "echo ok" {
		t.Fatalf("expected command at end of docker args, got %#v", call.args)
	}
}

func TestDockerRunnerUsesDefaultProbeCommand(t *testing.T) {
	inputPath := writeSandboxInput(t)
	executor := &fakeExecutor{output: CommandOutput{Stdout: "sandbox-ready\n", ExitCode: 0}}
	runner, err := NewDockerRunner(DockerRunnerOptions{Executor: executor})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	result, err := runner.Run(context.Background(), RunRequest{FilePath: inputPath})
	if err != nil {
		t.Fatalf("run sandbox: %v", err)
	}

	if strings.Join(result.Command, " ") != strings.Join(DefaultProbeCommand(), " ") {
		t.Fatalf("expected default probe command, got %#v", result.Command)
	}
}

func TestDockerRunnerCleansUpTimedOutContainer(t *testing.T) {
	inputPath := writeSandboxInput(t)
	executor := &fakeExecutor{blockRun: true}
	runner, err := NewDockerRunner(DockerRunnerOptions{
		Timeout:  time.Millisecond,
		Executor: executor,
	})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	result, err := runner.Run(context.Background(), RunRequest{
		FilePath: inputPath,
		Command:  []string{"/bin/sh", "-c", "sleep 60"},
	})
	if err != nil {
		t.Fatalf("timeout should be reported in result, got error: %v", err)
	}

	if !result.TimedOut {
		t.Fatalf("expected timed out result, got %#v", result)
	}
	if !executor.cleanupSeen {
		t.Fatalf("expected timed out container cleanup")
	}
	if len(executor.calls) != 2 {
		t.Fatalf("expected run and cleanup calls, got %d", len(executor.calls))
	}

	containerName := argAfter(t, executor.calls[0].args, "--name")
	assertArgSequence(t, executor.calls[1].args, "rm", "-f", containerName)
}

func TestDockerRunnerAllowsNonZeroContainerExit(t *testing.T) {
	inputPath := writeSandboxInput(t)
	executor := &fakeExecutor{
		output: CommandOutput{
			Stderr:   "program failed\n",
			ExitCode: 7,
			Err:      errors.New("exit status 7"),
		},
	}
	runner, err := NewDockerRunner(DockerRunnerOptions{Executor: executor})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	result, err := runner.Run(context.Background(), RunRequest{
		FilePath: inputPath,
		Command:  []string{"/malcore/input"},
	})
	if err != nil {
		t.Fatalf("non-zero program exit should not be infrastructure error: %v", err)
	}

	if result.ExitCode != 7 || result.Stderr != "program failed\n" {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestDockerRunnerReturnsDockerInfrastructureErrors(t *testing.T) {
	inputPath := writeSandboxInput(t)
	executor := &fakeExecutor{
		output: CommandOutput{
			Stderr:   "docker daemon unavailable\n",
			ExitCode: 125,
			Err:      errors.New("exit status 125"),
		},
	}
	runner, err := NewDockerRunner(DockerRunnerOptions{Executor: executor})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	result, err := runner.Run(context.Background(), RunRequest{FilePath: inputPath})
	if err == nil {
		t.Fatalf("expected docker infrastructure error")
	}
	if result == nil || result.ExitCode != 125 {
		t.Fatalf("expected partial result with docker exit code, got %#v", result)
	}
}

func TestDockerRunnerRejectsMissingInput(t *testing.T) {
	runner, err := NewDockerRunner(DockerRunnerOptions{Executor: &fakeExecutor{}})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}

	if _, err := runner.Run(context.Background(), RunRequest{FilePath: filepath.Join(t.TempDir(), "missing.bin")}); err == nil {
		t.Fatalf("expected missing input error")
	}
}

func writeSandboxInput(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve sample: %v", err)
	}
	return resolved
}

func assertArgSequence(t *testing.T, args []string, sequence ...string) {
	t.Helper()

	for i := 0; i <= len(args)-len(sequence); i++ {
		matched := true
		for j := range sequence {
			if args[i+j] != sequence[j] {
				matched = false
				break
			}
		}
		if matched {
			return
		}
	}

	t.Fatalf("expected args to contain sequence %#v, got %#v", sequence, args)
}

func argAfter(t *testing.T, args []string, name string) string {
	t.Helper()

	for i := 0; i < len(args)-1; i++ {
		if args[i] == name {
			return args[i+1]
		}
	}

	t.Fatalf("expected arg %q in %#v", name, args)
	return ""
}
