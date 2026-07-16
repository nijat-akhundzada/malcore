# Sandbox Isolation

MALCORE supports a first-pass Docker isolation runner for controlled dynamic execution experiments.

This runner is intentionally separate from the normal API and worker flow. The API must never execute uploaded files, and the standard worker should not be given access to the Docker socket. Mounting `/var/run/docker.sock` into the worker would allow that container to control the host Docker daemon, which is effectively host-level power.

## Current Implementation

The Docker runner lives in:

```text
services/api/internal/sandbox
services/api/cmd/sandbox
```

The runner starts a container with:

* no network: `--network none`
* read-only root filesystem: `--read-only`
* no Linux capabilities: `--cap-drop ALL`
* no privilege escalation: `--security-opt no-new-privileges`
* non-root user: `65534:65534`
* memory limit
* CPU limit
* PID limit
* timeout
* bounded stdout/stderr capture
* read-only sample bind mount at `/malcore/input`
* isolated `/tmp` with `noexec`, `nosuid`, and `nodev`

The runner also uses `--pull=never`, so runtime sandbox execution does not fetch images from the internet.

## Local Usage

From `services/api`:

```bash
go run ./cmd/sandbox --file ../../samples/benign/strings64.exe
```

With no command, the sandbox runs a harmless probe that verifies the sample is readable inside the container.

To run a command against the sample:

```bash
go run ./cmd/sandbox --file ../../samples/benign/strings64.exe -- /bin/sh -c "ls -l /malcore/input"
```

To intentionally execute a Linux sample inside a compatible sandbox image:

```bash
go run ./cmd/sandbox --file ./sample-linux-binary -- /malcore/input
```

Windows `.exe` files do not execute inside the default Linux Alpine image. They require a purpose-built Windows or emulator-based sandbox in a separate isolated environment.

## Production Direction

For production dynamic analysis, use a dedicated sandbox host or service, not the normal API/worker container.

Recommended next steps:

* build a dedicated sandbox image per target OS/runtime
* run the sandbox service on isolated infrastructure
* store sandbox results as a separate analyzer module
* keep network disabled by default
* add optional fake-network capture later
* snapshot and destroy execution environments between runs

This keeps dynamic execution behind a clear trust boundary instead of mixing it into the static analyzer worker.
