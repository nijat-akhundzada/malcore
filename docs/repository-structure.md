# Repository Structure

MALCORE uses a monorepo structure.

## Folders

### apps/web

Frontend application built with React and Vite.

This will contain the web dashboard for:

- file upload
- URL submission
- job status
- analysis results
- report downloads

### services/api

Main Go API service.

Responsibilities:

- accept uploads
- accept URL submissions
- create jobs
- expose job status
- expose reports
- communicate with database, queue, and storage
- host the worker entrypoint at `services/api/cmd/worker`

### services/analyzer

Python analyzer engine.

Responsibilities:

- PE analysis
- script analysis
- Office macro detection
- archive inspection
- YARA scanning
- IOC extraction

### deployments/docker

Docker and Docker Compose configuration.

### docs

Project documentation.

### services/analyzer/rules

YARA detection rules loaded by the analyzer runtime.
