package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	DefaultQuarantineDir = "storage/quarantine"
)

type Storage interface {
	Save(jobID string, reader io.Reader) (string, error)
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

func (s *LocalStorage) Save(jobID string, r io.Reader) (string, error) {
	// 1. Create isolated directory for this job
	// jobID should be a UUID, but we join strictly to avoid traversal
	jobDir := filepath.Join(s.root, filepath.Clean(jobID))
	if err := os.MkdirAll(jobDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create job directory: %w", err)
	}

	// 2. Generate random filename
	randomName, err := generateRandomName(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate random name: %w", err)
	}
	filename := randomName + ".bin"
	fullPath := filepath.Join(jobDir, filename)

	// 3. Save file with non-executable permissions (0600)
	// O_TRUNC to ensure we don't append if file somehow exists
	file, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	if _, err := io.Copy(file, r); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}

	return fullPath, nil
}

func generateRandomName(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
