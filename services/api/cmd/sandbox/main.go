package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/nijat-akhundzada/malcore/services/api/internal/sandbox"
)

func main() {
	var filePath string
	var dockerCommand string
	var image string
	var timeout time.Duration
	var memory string
	var cpus string
	var pidsLimit int
	var tmpfsSize string
	var user string
	var outputLimit int64

	flag.StringVar(&filePath, "file", "", "local file path to mount at /malcore/input")
	flag.StringVar(&dockerCommand, "docker-command", sandbox.DefaultDockerCommand, "docker CLI command")
	flag.StringVar(&image, "image", sandbox.DefaultImage, "sandbox container image")
	flag.DurationVar(&timeout, "timeout", sandbox.DefaultTimeout, "maximum container runtime")
	flag.StringVar(&memory, "memory", sandbox.DefaultMemory, "container memory limit")
	flag.StringVar(&cpus, "cpus", sandbox.DefaultCPUs, "container CPU limit")
	flag.IntVar(&pidsLimit, "pids-limit", sandbox.DefaultPidsLimit, "container process limit")
	flag.StringVar(&tmpfsSize, "tmpfs-size", sandbox.DefaultTmpfsSize, "size for the isolated /tmp tmpfs")
	flag.StringVar(&user, "user", sandbox.DefaultUser, "container user")
	flag.Int64Var(&outputLimit, "output-limit", sandbox.DefaultOutputLimit, "stdout and stderr byte limit")
	flag.Parse()

	if filePath == "" {
		fail("missing required --file path", 2)
	}

	runner, err := sandbox.NewDockerRunner(sandbox.DockerRunnerOptions{
		DockerCommand: dockerCommand,
		Image:         image,
		Timeout:       timeout,
		Memory:        memory,
		CPUs:          cpus,
		PidsLimit:     pidsLimit,
		TmpfsSize:     tmpfsSize,
		User:          user,
		OutputLimit:   outputLimit,
	})
	if err != nil {
		fail(err.Error(), 2)
	}

	result, err := runner.Run(context.Background(), sandbox.RunRequest{
		FilePath: filePath,
		Command:  flag.Args(),
	})
	if result != nil {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(result); encodeErr != nil {
			fail("encode sandbox result: "+encodeErr.Error(), 1)
		}
	}
	if err != nil {
		fail(err.Error(), 1)
	}
	if result != nil && result.TimedOut {
		os.Exit(124)
	}
	if result != nil && result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}
}

func fail(message string, code int) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(code)
}
