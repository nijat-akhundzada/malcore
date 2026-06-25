package worker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type ObjectFetcher interface {
	Fetch(ctx context.Context, key string) (string, func(), error)
}

type MinIOObjectFetcherOptions struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
	TempDir   string
}

type MinIOObjectFetcher struct {
	client  *minio.Client
	bucket  string
	tempDir string
}

func NewMinIOObjectFetcher(options MinIOObjectFetcherOptions) (*MinIOObjectFetcher, error) {
	if strings.TrimSpace(options.Endpoint) == "" {
		return nil, fmt.Errorf("minio endpoint is required")
	}
	if strings.TrimSpace(options.AccessKey) == "" {
		return nil, fmt.Errorf("minio access key is required")
	}
	if strings.TrimSpace(options.SecretKey) == "" {
		return nil, fmt.Errorf("minio secret key is required")
	}
	if strings.TrimSpace(options.Bucket) == "" {
		return nil, fmt.Errorf("minio bucket is required")
	}

	client, err := minio.New(options.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(options.AccessKey, options.SecretKey, ""),
		Secure: options.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}

	tempDir := options.TempDir
	if strings.TrimSpace(tempDir) == "" {
		tempDir = os.TempDir()
	}

	return &MinIOObjectFetcher{
		client:  client,
		bucket:  options.Bucket,
		tempDir: tempDir,
	}, nil
}

func (f *MinIOObjectFetcher) Fetch(ctx context.Context, key string) (string, func(), error) {
	safeKey, err := validateObjectKey(key)
	if err != nil {
		return "", nil, err
	}

	if err := os.MkdirAll(f.tempDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("create analyzer temp root: %w", err)
	}

	workDir, err := os.MkdirTemp(f.tempDir, "job-*")
	if err != nil {
		return "", nil, fmt.Errorf("create analyzer temp directory: %w", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(workDir)
	}

	object, err := f.client.GetObject(ctx, f.bucket, safeKey, minio.GetObjectOptions{})
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("get minio object: %w", err)
	}
	defer object.Close()

	targetPath := filepath.Join(workDir, path.Base(safeKey))
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("create analyzer input file: %w", err)
	}

	_, copyErr := io.Copy(target, object)
	closeErr := target.Close()
	if copyErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("download minio object: %w", copyErr)
	}
	if closeErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("close analyzer input file: %w", closeErr)
	}

	return targetPath, cleanup, nil
}

func validateObjectKey(key string) (string, error) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", fmt.Errorf("object key is required")
	}
	if strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("object key must be relative")
	}
	if strings.Contains(trimmed, "\\") || strings.Contains(trimmed, "\x00") {
		return "", fmt.Errorf("object key contains invalid characters")
	}

	cleaned := path.Clean(trimmed)
	if cleaned == "." || cleaned != trimmed {
		return "", fmt.Errorf("object key must be normalized")
	}

	for _, part := range strings.Split(cleaned, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("object key contains unsafe path segment")
		}
	}

	return cleaned, nil
}
