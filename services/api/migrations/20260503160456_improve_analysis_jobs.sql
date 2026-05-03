-- +goose Up
ALTER TABLE analysis_jobs
    ADD CONSTRAINT analysis_jobs_source_type_check
    CHECK (source_type IN ('upload', 'url'));

ALTER TABLE analysis_jobs
    ADD CONSTRAINT analysis_jobs_status_check
    CHECK (status IN ('pending', 'queued', 'running', 'completed', 'failed', 'needs_password'));

ALTER TABLE analysis_jobs
    ADD CONSTRAINT analysis_jobs_score_check
    CHECK (score IS NULL OR (score >= 0 AND score <= 100));

ALTER TABLE analysis_jobs
    ADD CONSTRAINT analysis_jobs_risk_level_check
    CHECK (
        risk_level IS NULL OR
        risk_level IN ('low', 'medium', 'high', 'critical')
    );

CREATE INDEX idx_analysis_jobs_status ON analysis_jobs(status);
CREATE INDEX idx_analysis_jobs_created_at ON analysis_jobs(created_at);

-- +goose Down
DROP INDEX IF EXISTS idx_analysis_jobs_created_at;
DROP INDEX IF EXISTS idx_analysis_jobs_status;

ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_risk_level_check;

ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_score_check;

ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_status_check;

ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_source_type_check;