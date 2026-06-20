-- +goose Up
ALTER TABLE analysis_jobs
    ADD COLUMN md5_hash TEXT,
    ADD COLUMN sha256_hash TEXT;

ALTER TABLE analysis_jobs
    ADD CONSTRAINT analysis_jobs_md5_hash_check
    CHECK (md5_hash IS NULL OR length(md5_hash) = 32);

ALTER TABLE analysis_jobs
    ADD CONSTRAINT analysis_jobs_sha256_hash_check
    CHECK (sha256_hash IS NULL OR length(sha256_hash) = 64);

CREATE INDEX idx_analysis_jobs_md5_hash ON analysis_jobs(md5_hash);
CREATE INDEX idx_analysis_jobs_sha256_hash ON analysis_jobs(sha256_hash);

-- +goose Down
DROP INDEX IF EXISTS idx_analysis_jobs_sha256_hash;
DROP INDEX IF EXISTS idx_analysis_jobs_md5_hash;

ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_sha256_hash_check;

ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_md5_hash_check;

ALTER TABLE analysis_jobs
    DROP COLUMN IF EXISTS sha256_hash,
    DROP COLUMN IF EXISTS md5_hash;