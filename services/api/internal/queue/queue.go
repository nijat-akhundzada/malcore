package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
)

const (
	TypeAnalyzeFile = "analysis:analyze_file"
	AnalysisQueue   = "analysis"
)

type AnalyzeFilePayload struct {
	JobID                string `json:"job_id"`
	StorageKey           string `json:"storage_key"`
	OriginalStorageKey   string `json:"original_storage_key"`
	QuarantineStorageKey string `json:"quarantine_storage_key"`
	MIMEType             string `json:"mime_type"`
	SHA256Hash           string `json:"sha256_hash"`
}

type Enqueuer interface {
	EnqueueAnalyzeFile(ctx context.Context, payload AnalyzeFilePayload) error
}

type Client struct {
	client *asynq.Client
}

type RedisOptions struct {
	Addr     string
	Password string
	DB       int
}

func NewClient(options RedisOptions) *Client {
	return &Client{
		client: asynq.NewClient(RedisClientOpt(options)),
	}
}

func RedisClientOpt(options RedisOptions) asynq.RedisClientOpt {
	return asynq.RedisClientOpt{
		Addr:     options.Addr,
		Password: options.Password,
		DB:       options.DB,
	}
}

func (c *Client) EnqueueAnalyzeFile(ctx context.Context, payload AnalyzeFilePayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal analyze file payload: %w", err)
	}

	task := asynq.NewTask(TypeAnalyzeFile, body)
	_, err = c.client.EnqueueContext(
		ctx,
		task,
		asynq.Queue(AnalysisQueue),
		asynq.MaxRetry(5),
		asynq.Timeout(10*time.Minute),
	)
	if err != nil {
		return fmt.Errorf("enqueue analyze file task: %w", err)
	}

	return nil
}

func (c *Client) Close() error {
	return c.client.Close()
}
