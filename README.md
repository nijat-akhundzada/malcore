# MALCORE

**MALCORE** is an open-source malware analysis sandbox for analyzing suspicious files and URLs.

The project is designed as a modular security analysis system that combines a Go-based backend with Python-based analysis engines. It focuses on safe file handling, static analysis, IOC extraction, YARA scanning, and transparent risk scoring.

> Built as a personal open-source cybersecurity project by Nijat Akhundzadeh.

---

## Goals

MALCORE aims to provide a practical and educational malware analysis platform for:

- security researchers
- backend engineers learning security systems
- students
- SOC/lab environments
- open-source contributors

The project is not just a file scanner. It is designed as a real analysis pipeline with job processing, quarantine storage, analyzer modules, scoring, and reports.

---

## Key Features

- Upload suspicious files for analysis
- Submit URLs and download files safely
- Store files in quarantine storage
- Generate file hashes such as MD5 and SHA256
- Detect MIME type and extension mismatches
- Run static analysis on supported file types
- Extract IOCs such as URLs, domains, and IP addresses
- Run YARA rule scanning
- Calculate rule-based risk scores
- Generate structured JSON reports
- Designed for future sandbox and dynamic analysis support

---

## Supported File Types

Initial supported file categories:

| Category | Extensions |
|---|---|
| Windows binaries | `.exe`, `.dll` |
| Scripts | `.ps1`, `.js`, `.vbs`, `.bat`, `.cmd` |
| Office documents | `.docx`, `.xls`, `.ppt` |
| Archives | `.zip`, `.rar`, `.7z` |
| Optional future types | `.pdf`, `.py`, `.apk`, `.jar`, `.elf`, `.bin` |

The first stable version will focus on static analysis before adding full dynamic sandbox execution.

---

## Architecture Overview

MALCORE uses a hybrid architecture:

```text
Frontend
   |
   v
Go API Service
   |
   v
PostgreSQL + Redis + MinIO
   |
   v
Go Worker Service
   |
   v
Python Analyzer Engine
   |
   v
Reports + Risk Scoring
````

### Why Go?

Go is used for:

* API development
* file upload handling
* URL downloading
* job orchestration
* worker services
* reliable backend infrastructure

### Why Python?

Python is used for malware analysis because its ecosystem is strong for:

* PE file analysis
* YARA integration
* Office macro analysis
* archive inspection
* IOC extraction
* scoring experiments

---

## Current Limitations

MALCORE is being built step by step.

Current planned limitations:

* No full VM-based dynamic sandbox in the first version
* No real malware execution without isolation
* Static analysis comes first
* Dynamic behavior monitoring will be added later
* External threat intelligence integrations are optional and future-focused

This project prioritizes safety, transparency, and modular design.

---

## Planned Analysis Pipeline

```text
File Upload or URL Submission
        |
        v
Input Validation
        |
        v
Quarantine Storage
        |
        v
Hashing + MIME Detection
        |
        v
Job Queue
        |
        v
Static Analysis
        |
        v
YARA + IOC Extraction
        |
        v
Risk Scoring
        |
        v
JSON / PDF Report
```

---

## Tech Stack

| Layer            | Technology     |
| ---------------- | -------------- |
| Backend API      | Go             |
| Router           | Chi            |
| Database         | PostgreSQL     |
| Queue            | Redis + Asynq  |
| Storage          | MinIO          |
| Analyzer Engine  | Python         |
| Frontend         | Next.js        |
| Containerization | Docker Compose |
| Rules            | YARA           |

---

## Getting Started

> Setup instructions will be added as the project evolves.

Planned local setup:

```bash
git clone https://github.com/nijat-akhundzada/malcore.git
cd malcore
docker compose up --build
```

---

## Repository Status

MALCORE is currently under active development.

The first development milestones are:

1. Define project scope and architecture
2. Build Go API skeleton
3. Add file upload and quarantine storage
4. Add job queue and worker service
5. Add Python analyzer engine
6. Add YARA and IOC extraction
7. Add scoring and reporting
8. Add frontend dashboard

---

## Safety Notice

MALCORE is intended for educational and defensive security research purposes only.

Do not upload or execute live malware on an unsafe machine. Dynamic execution must only be performed inside properly isolated environments.

---

## License

License will be added soon.

---

## Author

Built by **Nijat Akhundzadeh** as a personal open-source cybersecurity engineering project.
