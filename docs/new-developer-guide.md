# New Developer Guide

## Project Summary

MALCORE is a modular malware-analysis platform that accepts file uploads or URLs, stores samples safely, queues background analysis jobs, runs static analysis in Python, and returns scored JSON results through a Go API and React frontend.

The codebase is already past the "project skeleton" phase. The current repository contains a working end-to-end MVP for:

- file and URL submission
- quarantine/object storage
- async job processing with Redis/Asynq
- Python-based static analyzers
- YARA and IOC extraction
- rule-based and AI-assisted scoring
- frontend job polling, status pages, results dashboards, and report downloads

## Monorepo Layout

`apps/web`

- React + Vite frontend
- Main flow lives in `src/App.tsx`
- API calls live in `src/services/api.ts`
- Upload/job UI is split into small components under `src/components`

`services/api`

- Go API and worker entrypoints
- `cmd/api/main.go` starts the HTTP API
- `cmd/worker/main.go` starts the Asynq worker
- `internal/http/handlers` contains upload, URL, health, and job handlers
- `internal/jobs` contains the job model and PostgreSQL repository
- `internal/storage` handles local/MinIO-backed quarantine storage
- `internal/downloader` contains the SSRF-aware URL fetcher
- `internal/worker` bridges stored objects to the Python analyzer and scoring

`services/analyzer`

- Python analyzer CLI and modules
- `analyze.py` is the executable entrypoint
- `analyzers/runner.py` selects analyzers and assembles the JSON payload
- analyzer modules currently cover `pe`, `scripts`, `office`, `archive`, `ioc`, and `yara`
- `rules/` contains bundled YARA rules

`deployments/docker`

- Docker Compose for the stack

`docs`

- architecture, repository notes, and this onboarding guide

## Runtime Flow

1. The frontend submits either a multipart file upload or a URL.
2. The Go API creates an `analysis_jobs` record.
3. The sample is saved to storage, hashed, MIME-inspected, and tagged for mismatch.
4. The API enqueues an Asynq job with storage keys and optional archive password.
5. The Go worker fetches the stored object into a temp workspace.
6. The worker calls the Python analyzer CLI.
7. Python runs the applicable analyzers, merges IOCs, and emits JSON.
8. Go calculates rule score, AI score, final weighted score, and risk level.
9. The job record is updated to `completed` or `failed`.
10. Report endpoints build JSON and PDF exports from the stored job record.
11. The frontend polls and renders hashes, MIME, scores, findings, YARA hits, and IOCs.

## Current Task Status

Tasks `1-31` are now implemented in the repository.

Highlights:

- Uploads and URL submissions create queued analysis jobs.
- The worker calculates weighted final risk scores.
- Results are available through job APIs and dedicated report endpoints.
- Reports can be exported as JSON and PDF.
- The frontend includes a full upload page, a status page, and a results dashboard.

## Important Data Model

The main persisted entity is `analysis_jobs`.

Key fields:

- `id`
- `source_type`
- `status`
- `md5_hash`
- `sha256_hash`
- `storage_key`
- `original_storage_key`
- `quarantine_storage_key`
- `mime_type`
- `file_extension`
- `mime_extension_mismatch`
- `size_bytes`
- `score`
- `ai_score`
- `risk_level`
- `analyzer_result`
- `error_message`

The `analyzer_result` JSON is the source for frontend findings and IOC rendering.

## Scoring Model

The worker currently computes:

- rule-based score from YARA, entropy, macros, and finding severities
- AI score from a lightweight logistic-style feature model
- final score using `0.6 * rule_score + 0.4 * ai_score`

Risk mapping:

- `0-29`: low
- `30-59`: medium
- `60-79`: high
- `80-100`: critical

## What To Read First

If you are joining the project, read these in order:

1. `README.md`
2. `MALCORE.md`
3. `docs/architecture.md`
4. `services/api/internal/http/handlers/upload.go`
5. `services/api/internal/http/handlers/url.go`
6. `services/api/internal/worker/worker.go`
7. `services/api/internal/worker/python_analyzer.go`
8. `services/analyzer/analyzers/runner.py`
9. One analyzer module at a time, starting with `scripts` and `archive`
10. `apps/web/src/App.tsx` and `apps/web/src/components/FileListItem.tsx`

## How To Extend Safely

When adding new analysis capability:

1. Decide whether it belongs in Go orchestration or Python analysis.
2. Keep analyzers pure and JSON-oriented.
3. Prefer adding metadata and findings instead of ad hoc text blobs.
4. Add or update tests close to the changed module.
5. Keep storage and fetch paths non-executable and path-safe.
6. Treat URL intake and archive extraction as hostile input surfaces.

## Good Next Tasks

The most valuable near-term follow-ups are:

1. Improve analyzer coverage for PDF, APK, and ELF samples.
2. Add stronger persistence and integration tests around PostgreSQL, MinIO, Redis, and libmagic-backed file detection.
3. Add STIX export and threat-intelligence enrichment when you move beyond tasks `1-31`.
4. Prepare dynamic sandbox execution work under tasks `32+`.
