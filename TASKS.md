## 1. Define Project Scope and README

**Instruction:**
Create the main `README.md` that clearly explains what MALCORE is.

**What to include:**

* Project name: MALCORE
* Short description (malware analysis sandbox)
* Key features (upload, URL scan, static analysis, scoring)
* Supported file types (.exe, .dll, .ps1, .js, office, archives)
* Architecture overview (Go + Python)
* Limitations (no full VM sandbox initially)
* Getting started instructions

**Why this matters:**
This is your **first impression**. It defines your personal brand.

**Done when:**

* Someone can understand the project in 2 minutes
* README looks like a serious open-source project

---

## 2. Design System Architecture Document

**Instruction:**
Create `docs/architecture.md`.

**What to include:**

* High-level system diagram
* Services:

  * Go API
  * Go Worker
  * Python Analyzer
  * PostgreSQL
  * Redis
  * MinIO
* Data flow (upload → analysis → report)
* Security boundaries (important for malware handling)

**Why this matters:**
Shows **senior-level thinking** and system design skills.

**Done when:**

* Diagram + explanation are clear
* Matches real production systems

---

## 3. Create Monorepo Structure

**Instruction:**
Initialize repository structure.

**Folders:**

```bash
apps/web
services/api
services/worker
services/analyzer
deployments/docker
deployments/nginx
docs
rules/yara
```

**Rules:**

* Each service must be isolated
* Clear naming (no confusion)

**Why this matters:**
Clean structure = easier scaling + contributors.

**Done when:**

* Repo is clean and understandable

---

## 4. Initialize Go API Service

**Instruction:**
Create backend API in Go.

**Requirements:**

* Use Chi router
* Add `/health` endpoint
* Add structured logging
* Load config from `.env`

**Why this matters:**
Foundation of entire system.

**Done when:**

* Server runs
* `/health` returns 200

---

## 5. Setup PostgreSQL and Migrations

**Instruction:**
Connect Go API to PostgreSQL.

**Requirements:**

* Use pgx
* Use goose for migrations
* Create initial migration system

**Why this matters:**
All data (jobs, results) depend on this.

**Done when:**

* DB connection works
* Migration runs successfully

---

## 6. Create Analysis Job Table

**Instruction:**
Design and implement job system.

**Fields:**

* id (UUID)
* status (pending, running, completed, failed)
* source_type (upload/url)
* score
* risk_level
* timestamps

**Why this matters:**
Everything in MALCORE is based on jobs.

**Done when:**

* Job can be created and queried

---

## 7. Implement File Upload Endpoint

**Instruction:**
Create endpoint to upload files.

**Endpoint:**
`POST /api/v1/files/upload`

**Requirements:**

* Multipart upload
* File size limit (10MB)
* Validate file presence
* Create job

**Security:**

* Reject empty or invalid files

**Done when:**

* Upload returns job_id

---

## 8. Implement URL Submission Endpoint

**Instruction:**
Allow scanning via URL.

**Endpoint:**
`POST /api/v1/urls/submit`

**Requirements:**

* Download file
* Timeout (30 seconds)
* Limit redirects
* Validate content type

**Security:**

* Block internal IPs (SSRF)
* Block localhost

**Done when:**

* URL creates job safely

---

## 9. Implement File Downloader Module

**Instruction:**
Create reusable downloader logic.

**Features:**

* Follow redirects
* Limit file size
* Capture HTTP headers
* Retry logic (3 attempts)

**Why:**
Used by URL submission.

**Done when:**

* Works reliably and safely

---

## 10. Implement Quarantine Storage

**Instruction:**
Store all files safely.

**Rules:**

* Random filenames
* No execution allowed
* No path traversal
* Isolated directory

**Example:**

```
/storage/quarantine/{job_id}/file.bin
```

**Done when:**

* Files stored safely and securely

---

## 11. Implement File Hashing

**Instruction:**
Generate file hashes.

**Hashes:**

* MD5
* SHA256

**Why:**
Used for identification and analysis.

**Done when:**

* Hashes stored in DB

---

## 12. Implement MIME Type Detection

**Instruction:**
Detect real file type.

**Tools:**

* libmagic (Go or Python)

**Checks:**

* MIME vs extension mismatch

**Done when:**

* MIME stored and mismatch flagged

---

## 13. Setup MinIO Storage

**Instruction:**
Integrate object storage.

**Tasks:**

* Setup MinIO container
* Upload files
* Store object paths

**Why:**
Scalable storage system.

**Done when:**

* Files accessible via MinIO

---

## 14. Setup Redis and Queue System

**Instruction:**
Setup async job processing.

**Tools:**

* Redis
* Asynq (Go)

**Tasks:**

* Define job types
* Configure queue

**Done when:**

* Jobs can be queued

---

## 15. Implement Worker Service

**Instruction:**
Create background worker.

**Responsibilities:**

* Pull jobs from queue
* Run analysis pipeline
* Update job status

**Done when:**

* Jobs processed automatically

---

## 16. Build Python Analyzer Framework

**Instruction:**
Create modular analyzer system.

**Structure:**

```
analyzers/
  pe/
  scripts/
  office/
  archive/
```

**Interface:**

* Input: file path
* Output: JSON result

**Done when:**

* Analyzer can be called from CLI

---

## 17. Implement PE File Analyzer

**Instruction:**
Analyze `.exe` and `.dll`.

**Extract:**

* imports
* sections
* entropy

**Tool:**

* pefile

**Done when:**

* Metadata returned as JSON

---

## 18. Implement Script Analyzer

**Instruction:**
Analyze `.ps1` and `.js`.

**Detect:**

* URLs
* base64
* eval/exec

**Done when:**

* Suspicious patterns detected

---

## 19. Implement Office Macro Analyzer

**Instruction:**
Analyze `.docx`, `.xls`, `.ppt`.

**Tool:**

* oletools

**Detect:**

* macros
* suspicious keywords

**Done when:**

* Macro presence flagged

---

## 20. Implement Archive Analyzer

**Instruction:**
Handle `.zip`, `.rar`, `.7z`.

**Features:**

* Extract files
* Support password input
* Limit recursion depth

**Done when:**

* Archives safely processed

---

## 21. Integrate YARA Scanning

**Instruction:**
Add signature detection.

**Tasks:**

* Load YARA rules
* Scan files
* Store matches

**Done when:**

* YARA hits saved

---

## 22. Implement IOC Extraction

**Instruction:**
Extract indicators of compromise.

**Extract:**

* URLs
* IPs
* domains

**Done when:**

* IOCs included in result

---

## 23. Implement Rule-Based Scoring

**Instruction:**
Create scoring rules.

**Inputs:**

* YARA hits
* entropy
* macros

**Output:**

* numeric score

**Done when:**

* Score generated consistently

---

## 24. Implement AI Scoring

**Instruction:**
Add simple ML scoring.

**Model:**

* logistic regression

**Features:**

* YARA count
* suspicious APIs
* entropy

**Done when:**

* AI score returned

---

## 25. Implement Final Risk Calculation

**Instruction:**
Combine scores.

**Formula:**

```
final = 0.6 * rule + 0.4 * ai
```

**Levels:**

* Low
* Medium
* High
* Critical

**Done when:**

* Risk level assigned

---

## 26. Generate JSON Report

**Instruction:**
Create structured output.

**Include:**

* hashes
* YARA hits
* IOCs
* scores

**Done when:**

* JSON valid and complete

---

## 27. Generate PDF Report

**Instruction:**
Create readable report.

**Tool:**

* reportlab or wkhtmltopdf

**Done when:**

* PDF generated

---

## 28. Implement Job Result Endpoint

**Instruction:**
Return analysis result.

**Endpoint:**
`GET /jobs/{id}/result`

**Done when:**

* Full result returned

---

## 29. Build Frontend Upload Page

**Instruction:**
Create UI for upload.

**Features:**

* File upload
* URL input
* Password field

**Done when:**

* User can submit job

---

## 30. Build Job Status Page

**Instruction:**
Display job progress.

**Done when:**

* Status visible

---

## 31. Build Results Dashboard

**Instruction:**
Display analysis results.

**Show:**

* score
* risk
* YARA
* IOCs

**Done when:**

* Data clearly visualized

---

## 32. Implement Sandbox Isolation (Advanced)

**Instruction:**
Prepare safe execution environment.

**Options:**

* Firejail
* Docker isolation

**Done when:**

* Files can run safely

---

## 33. Implement Behavior Monitoring (Advanced)

**Instruction:**
Track runtime behavior.

**Track:**

* processes
* file changes
* network

**Done when:**

* Behavior logged

---

## 34. Setup Docker Environment

**Instruction:**
Create full docker-compose.

**Services:**

* API
* Worker
* Redis
* PostgreSQL
* MinIO

**Done when:**

* System runs with one command

---


## 35. Add Logging and Audit System

**Instruction:**
Track system activity.

**Logs:**

* API requests
* job processing

**Done when:**

* Logs visible and useful

---

## 36. Create CONTRIBUTING.md

**Instruction:**
Define contribution rules.

**Include:**

* setup steps
* PR guidelines

**Done when:**

* Contributors can start easily

---

## 37. Setup GitHub Issues and Labels

**Instruction:**
Prepare repo for contributors.

**Labels:**

* good first issue
* bug
* enhancement

**Done when:**

* Repo is contributor-friendly