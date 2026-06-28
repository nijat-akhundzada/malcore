-- +goose Up
ALTER TABLE analysis_jobs
    ADD COLUMN analyzer_result JSONB;

-- +goose Down
ALTER TABLE analysis_jobs
    DROP COLUMN IF EXISTS analyzer_result;
