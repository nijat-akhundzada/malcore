-- +goose Up
ALTER TABLE analysis_jobs
    ADD COLUMN storage_key TEXT,
    ADD COLUMN original_storage_key TEXT,
    ADD COLUMN quarantine_storage_key TEXT;

CREATE INDEX idx_analysis_jobs_storage_key ON analysis_jobs(storage_key);
CREATE INDEX idx_analysis_jobs_original_storage_key ON analysis_jobs(original_storage_key);
CREATE INDEX idx_analysis_jobs_quarantine_storage_key ON analysis_jobs(quarantine_storage_key);

-- +goose Down
DROP INDEX IF EXISTS idx_analysis_jobs_quarantine_storage_key;
DROP INDEX IF EXISTS idx_analysis_jobs_original_storage_key;
DROP INDEX IF EXISTS idx_analysis_jobs_storage_key;

ALTER TABLE analysis_jobs
    DROP COLUMN IF EXISTS quarantine_storage_key,
    DROP COLUMN IF EXISTS original_storage_key,
    DROP COLUMN IF EXISTS storage_key;
