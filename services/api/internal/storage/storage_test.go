package storage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validJobID = "a64526aa-ef03-47c6-8c3d-27a9d37065cb"

func TestLocalStorageSavesFileInIsolatedJobDirectory(t *testing.T) {
	root := t.TempDir()
	store := NewLocalStorage(root)

	result, err := store.Save(context.Background(), validJobID, "sample.txt", strings.NewReader("sample"))
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	expectedJobDir := filepath.Join(root, validJobID)
	if !isPathInside(expectedJobDir, result.Path) {
		t.Fatalf("expected path %q inside job dir %q", result.Path, expectedJobDir)
	}

	if filepath.Base(result.Path) == "file.bin" {
		t.Fatalf("expected randomized filename, got %q", filepath.Base(result.Path))
	}

	if filepath.Ext(result.Path) != ".bin" {
		t.Fatalf("expected .bin extension, got %q", filepath.Ext(result.Path))
	}

	body, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}

	if string(body) != "sample" {
		t.Fatalf("expected saved body, got %q", string(body))
	}
}

func TestLocalStorageReturnsFileHashes(t *testing.T) {
	root := t.TempDir()
	store := NewLocalStorage(root)

	result, err := store.Save(context.Background(), validJobID, "hello.txt", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	if result.MD5Hash != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("expected md5 hash for hello, got %q", result.MD5Hash)
	}

	if result.SHA256Hash != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("expected sha256 hash for hello, got %q", result.SHA256Hash)
	}
}

func TestLocalStorageReturnsFileMetadata(t *testing.T) {
	root := t.TempDir()
	store := NewLocalStorage(root)

	result, err := store.Save(context.Background(), validJobID, "hello.txt", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	if result.MIMEType != "text/plain" {
		t.Fatalf("expected text/plain MIME type, got %q", result.MIMEType)
	}

	if result.FileExtension != ".txt" {
		t.Fatalf("expected .txt extension, got %q", result.FileExtension)
	}

	if result.MIMEExtensionMismatch {
		t.Fatalf("expected no MIME/extension mismatch")
	}

	if result.SizeBytes != 5 {
		t.Fatalf("expected size 5, got %d", result.SizeBytes)
	}

	if result.StorageKey == "" {
		t.Fatalf("expected storage key to be set")
	}

	if result.OriginalStorageKey == "" || result.QuarantineStorageKey == "" {
		t.Fatalf("expected original and quarantine storage keys to be set")
	}
}

func TestLocalStorageUsesNonExecutablePermissions(t *testing.T) {
	root := t.TempDir()
	store := NewLocalStorage(root)

	result, err := store.Save(context.Background(), validJobID, "sample.txt", strings.NewReader("sample"))
	if err != nil {
		t.Fatalf("save: %v", err)
	}

	jobDirInfo, err := os.Stat(filepath.Dir(result.Path))
	if err != nil {
		t.Fatalf("stat job dir: %v", err)
	}

	if jobDirInfo.Mode().Perm() != quarantineDirPerm {
		t.Fatalf("expected job dir permissions %o, got %o", quarantineDirPerm, jobDirInfo.Mode().Perm())
	}

	fileInfo, err := os.Stat(result.Path)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}

	if fileInfo.Mode().Perm() != quarantineFilePerm {
		t.Fatalf("expected file permissions %o, got %o", quarantineFilePerm, fileInfo.Mode().Perm())
	}

	if fileInfo.Mode().Perm()&0111 != 0 {
		t.Fatalf("expected saved file to be non-executable, got %o", fileInfo.Mode().Perm())
	}
}

func TestLocalStorageGeneratesRandomFilenames(t *testing.T) {
	root := t.TempDir()
	store := NewLocalStorage(root)

	first, err := store.Save(context.Background(), validJobID, "one.txt", strings.NewReader("one"))
	if err != nil {
		t.Fatalf("first save: %v", err)
	}

	second, err := store.Save(context.Background(), validJobID, "two.txt", strings.NewReader("two"))
	if err != nil {
		t.Fatalf("second save: %v", err)
	}

	if first.Path == second.Path {
		t.Fatalf("expected random filenames, got duplicate path %q", first.Path)
	}
}

func TestLocalStorageRejectsPathTraversalJobID(t *testing.T) {
	root := t.TempDir()
	store := NewLocalStorage(root)

	invalidJobIDs := []string{
		"../" + validJobID,
		".." + string(filepath.Separator) + validJobID,
		validJobID + string(filepath.Separator) + "nested",
		"/" + validJobID,
		"not-a-uuid",
	}

	for _, jobID := range invalidJobIDs {
		t.Run(jobID, func(t *testing.T) {
			if _, err := store.Save(context.Background(), jobID, "sample.txt", strings.NewReader("sample")); err == nil {
				t.Fatalf("expected invalid job id %q to be rejected", jobID)
			}
		})
	}
}
