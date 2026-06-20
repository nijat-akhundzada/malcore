-- +goose Up
ALTER TABLE analysis_jobs
    ADD COLUMN mime_type TEXT,
    ADD COLUMN file_extension TEXT,
    ADD COLUMN mime_extension_mismatch BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN size_bytes BIGINT;

-- +goose Down
ALTER TABLE analysis_jobs
    DROP COLUMN IF EXISTS size_bytes,
    DROP COLUMN IF EXISTS mime_extension_mismatch,
    DROP COLUMN IF EXISTS file_extension,
    DROP COLUMN IF EXISTS mime_type;
