package storage

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nijat-akhundzada/malcore/services/api/internal/filemeta"
)

const (
	DefaultQuarantineDir = "storage/quarantine"
	quarantineDirPerm    = 0700
	quarantineFilePerm   = 0600
)

var jobIDPattern = regexp.MustCompile(`^[a-fA-F0-9-]{36}$`)

type Storage interface {
	Save(ctx context.Context, jobID string, originalName string, reader io.Reader) (*SaveResult, error)
}

type SaveResult struct {
	Path                  string
	StorageKey            string
	OriginalStorageKey    string
	QuarantineStorageKey  string
	MD5Hash               string
	SHA256Hash            string
	MIMEType              string
	FileExtension         string
	MIMEExtensionMismatch bool
	SizeBytes             int64
}

type LocalStorage struct {
	root string
}

func NewLocalStorage(root string) *LocalStorage {
	if root == "" {
		root = DefaultQuarantineDir
	}
	return &LocalStorage{root: root}
}

func (s *LocalStorage) Save(ctx context.Context, jobID string, originalName string, r io.Reader) (*SaveResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	safeJobID, err := validateJobID(jobID)
	if err != nil {
		return nil, err
	}

	root, err := filepath.Abs(s.root)
	if err != nil {
		return nil, fmt.Errorf("resolve quarantine root: %w", err)
	}

	if err := os.MkdirAll(root, quarantineDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create quarantine root: %w", err)
	}

	jobDir := filepath.Join(root, safeJobID)
	if err := os.MkdirAll(jobDir, quarantineDirPerm); err != nil {
		return nil, fmt.Errorf("failed to create job directory: %w", err)
	}

	randomName, err := generateRandomName(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random name: %w", err)
	}

	fullPath := filepath.Join(jobDir, randomName+".bin")
	if !isPathInside(jobDir, fullPath) {
		return nil, fmt.Errorf("generated path escapes job directory")
	}

	file, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, quarantineFilePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}

	md5Hasher := md5.New()
	sha256Hasher := sha256.New()

	writer := io.MultiWriter(file, md5Hasher, sha256Hasher)

	sizeBytes, err := io.Copy(writer, r)
	if err != nil {
		return nil, fmt.Errorf("failed to write file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("failed to close file: %w", err)
	}

	metadata, err := filemeta.Detect(fullPath, originalName)
	if err != nil {
		return nil, fmt.Errorf("failed to detect file metadata: %w", err)
	}

	md5Hash := hex.EncodeToString(md5Hasher.Sum(nil))
	sha256Hash := hex.EncodeToString(sha256Hasher.Sum(nil))

	return &SaveResult{
		Path:                  fullPath,
		StorageKey:            localStorageKey(safeJobID, fullPath),
		OriginalStorageKey:    localStorageKey(safeJobID, fullPath),
		QuarantineStorageKey:  localStorageKey(safeJobID, fullPath),
		MD5Hash:               md5Hash,
		SHA256Hash:            sha256Hash,
		MIMEType:              metadata.MIMEType,
		FileExtension:         metadata.FileExtension,
		MIMEExtensionMismatch: metadata.MIMEExtensionMismatch,
		SizeBytes:             sizeBytes,
	}, nil
}

func localStorageKey(jobID string, fullPath string) string {
	return path.Join(jobID, filepath.Base(fullPath))
}

func validateJobID(jobID string) (string, error) {
	cleaned := filepath.Clean(jobID)
	if cleaned != jobID || !filepath.IsLocal(jobID) || !jobIDPattern.MatchString(jobID) {
		return "", fmt.Errorf("invalid job id")
	}

	return jobID, nil
}

func isPathInside(parent string, child string) bool {
	parentAbs, err := filepath.Abs(parent)
	if err != nil {
		return false
	}

	childAbs, err := filepath.Abs(child)
	if err != nil {
		return false
	}

	relative, err := filepath.Rel(parentAbs, childAbs)
	if err != nil {
		return false
	}

	return relative == "." || (!filepath.IsAbs(relative) && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func generateRandomName(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
