-- +goose Up
ALTER TABLE analysis_jobs
    ADD COLUMN ai_score INTEGER,
    ADD CONSTRAINT analysis_jobs_ai_score_check
    CHECK (ai_score IS NULL OR (ai_score >= 0 AND ai_score <= 100));

-- +goose Down
ALTER TABLE analysis_jobs
    DROP CONSTRAINT IF EXISTS analysis_jobs_ai_score_check;

ALTER TABLE analysis_jobs
    DROP COLUMN IF EXISTS ai_score;
