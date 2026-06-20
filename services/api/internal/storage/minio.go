package storage

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/nijat-akhundzada/malcore/services/api/internal/filemeta"
)

const (
	defaultMinIOOriginalPrefix   = "original"
	defaultMinIOQuarantinePrefix = "quarantine"
)

type MinIOOptions struct {
	Endpoint         string
	AccessKey        string
	SecretKey        string
	Bucket           string
	UseSSL           bool
	LocalStagingDir  string
	OriginalPrefix   string
	QuarantinePrefix string
}

type MinIOStorage struct {
	local            *LocalStorage
	client           *minio.Client
	bucket           string
	originalPrefix   string
	quarantinePrefix string
}

func NewMinIOStorage(ctx context.Context, options MinIOOptions) (*MinIOStorage, error) {
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

	store := &MinIOStorage{
		local:            NewLocalStorage(options.LocalStagingDir),
		client:           client,
		bucket:           options.Bucket,
		originalPrefix:   strings.Trim(options.OriginalPrefix, "/"),
		quarantinePrefix: strings.Trim(options.QuarantinePrefix, "/"),
	}
	if store.originalPrefix == "" {
		store.originalPrefix = defaultMinIOOriginalPrefix
	}
	if store.quarantinePrefix == "" {
		store.quarantinePrefix = defaultMinIOQuarantinePrefix
	}

	if err := store.ensureBucket(ctx); err != nil {
		return nil, err
	}

	return store, nil
}

func (s *MinIOStorage) Save(ctx context.Context, jobID string, originalName string, reader io.Reader) (*SaveResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	safeJobID, err := validateJobID(jobID)
	if err != nil {
		return nil, err
	}

	stagedPath, err := s.stagingPath(safeJobID)
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(stagedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, quarantineFilePerm)
	if err != nil {
		return nil, fmt.Errorf("create staged file: %w", err)
	}

	md5Hasher := md5.New()
	sha256Hasher := sha256.New()

	originalKey := s.objectKey(s.originalPrefix, safeJobID, stagedPath)
	stagingWriter := io.MultiWriter(file, md5Hasher, sha256Hasher)
	originalReader := io.TeeReader(reader, stagingWriter)

	_, err = s.client.PutObject(ctx, s.bucket, originalKey, originalReader, -1, minio.PutObjectOptions{
		ContentType: "application/octet-stream",
	})
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("upload original object to minio: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close staged file: %w", err)
	}
	fileInfo, err := os.Stat(stagedPath)
	if err != nil {
		return nil, fmt.Errorf("stat staged file: %w", err)
	}
	sizeBytes := fileInfo.Size()

	metadata, err := filemeta.Detect(stagedPath, originalName)
	if err != nil {
		return nil, fmt.Errorf("detect staged file metadata: %w", err)
	}

	quarantineKey := s.objectKey(s.quarantinePrefix, safeJobID, stagedPath)
	quarantineFile, err := os.Open(stagedPath)
	if err != nil {
		return nil, fmt.Errorf("open staged file for quarantine upload: %w", err)
	}
	defer quarantineFile.Close()

	_, err = s.client.PutObject(ctx, s.bucket, quarantineKey, quarantineFile, sizeBytes, minio.PutObjectOptions{
		ContentType: metadata.MIMEType,
	})
	if err != nil {
		return nil, fmt.Errorf("upload quarantine object to minio: %w", err)
	}

	return &SaveResult{
		Path:                  stagedPath,
		StorageKey:            quarantineKey,
		OriginalStorageKey:    originalKey,
		QuarantineStorageKey:  quarantineKey,
		MD5Hash:               hex.EncodeToString(md5Hasher.Sum(nil)),
		SHA256Hash:            hex.EncodeToString(sha256Hasher.Sum(nil)),
		MIMEType:              metadata.MIMEType,
		FileExtension:         metadata.FileExtension,
		MIMEExtensionMismatch: metadata.MIMEExtensionMismatch,
		SizeBytes:             sizeBytes,
	}, nil
}

func (s *MinIOStorage) ensureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("check minio bucket: %w", err)
	}

	if exists {
		return nil
	}

	if err := s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{}); err != nil {
		return fmt.Errorf("create minio bucket: %w", err)
	}

	return nil
}

func (s *MinIOStorage) stagingPath(jobID string) (string, error) {
	root, err := filepath.Abs(s.local.root)
	if err != nil {
		return "", fmt.Errorf("resolve staging root: %w", err)
	}

	if err := os.MkdirAll(root, quarantineDirPerm); err != nil {
		return "", fmt.Errorf("create staging root: %w", err)
	}

	jobDir := filepath.Join(root, jobID)
	if err := os.MkdirAll(jobDir, quarantineDirPerm); err != nil {
		return "", fmt.Errorf("create staging job directory: %w", err)
	}

	randomName, err := generateRandomName(16)
	if err != nil {
		return "", fmt.Errorf("generate staged filename: %w", err)
	}

	fullPath := filepath.Join(jobDir, randomName+".bin")
	if !isPathInside(jobDir, fullPath) {
		return "", fmt.Errorf("generated staging path escapes job directory")
	}

	return fullPath, nil
}

func (s *MinIOStorage) objectKey(prefix string, jobID string, fullPath string) string {
	return path.Join(prefix, jobID, path.Base(fullPath))
}
