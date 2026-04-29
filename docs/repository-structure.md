# Repository Structure

MALCORE uses a monorepo structure.

## Folders

### apps/web

Frontend application.

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

### services/worker

Go background worker service.

Responsibilities:

- consume analysis jobs from Redis
- coordinate analysis pipeline
- call Python analyzer
- update job status
- store results

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

### deployments/nginx

Future optional NGINX configuration.

This is not needed for local development but kept for future deployment examples.

### docs

Project documentation.

### rules/yara

YARA detection rules.