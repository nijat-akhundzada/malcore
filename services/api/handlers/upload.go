package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"malcore-backend/models"
)

// UploadHandler handles file uploads
type UploadHandler struct {
	StorageDir string
}

// NewUploadHandler creates a new upload handler
func NewUploadHandler(storageDir string) *UploadHandler {
	// Ensure storage directory exists
	os.MkdirAll(storageDir, 0755)
	return &UploadHandler{
		StorageDir: storageDir,
	}
}

// ServeHTTP handles POST requests for file uploads
func (h *UploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	// Parse multipart form (max 100MB)
	err := r.ParseMultipartForm(100 << 20) // 100 MB
	if err != nil {
		h.sendError(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	uploadType := r.FormValue("uploadType")
	password := r.FormValue("password")
	fileName := r.FormValue("fileName")

	var fileInfo *models.FileInfo

	switch uploadType {
	case "file":
		fileInfo, err = h.handleFileUpload(r, fileName, password)
	case "url":
		url := r.FormValue("url")
		fileInfo, err = h.handleURLUpload(url, fileName, password)
	default:
		h.sendError(w, "Invalid upload type", http.StatusBadRequest)
		return
	}

	if err != nil {
		h.sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send success response
	response := models.UploadResponse{
		Success: true,
		FileID:  fileInfo.ID,
		Message: "File uploaded successfully",
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleFileUpload processes direct file uploads
func (h *UploadHandler) handleFileUpload(r *http.Request, fileName, password string) (*models.FileInfo, error) {
	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, fmt.Errorf("failed to get file: %v", err)
	}
	defer file.Close()

	// Use provided filename or original
	fileId := time.Now().UnixNano()
	finalName := fileName
	if finalName == "" {
		finalName = header.Filename
	}

	// Generate unique file ID
	fileID := fmt.Sprintf("%d_%s", fileId, finalName)
	filePath := filepath.Join(h.StorageDir, fileID)

	// Create destination file
	dst, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %v", err)
	}
	defer dst.Close()

	// Copy file content
	written, err := io.Copy(dst, file)
	if err != nil {
		return nil, fmt.Errorf("failed to save file: %v", err)
	}

	return &models.FileInfo{
		ID:         fileID,
		Name:       finalName,
		Type:       "file",
		Size:       written,
		Password:   password,
		UploadTime: time.Now(),
		Path:       filePath,
	}, nil
}

// handleURLUpload downloads files from URLs
func (h *UploadHandler) handleURLUpload(url, fileName, password string) (*models.FileInfo, error) {
	// Validate URL
	if url == "" {
		return nil, fmt.Errorf("URL is required")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Download file
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Determine filename
	finalName := fileName
	if finalName == "" {
		// Try to get filename from Content-Disposition header
		contentDisposition := resp.Header.Get("Content-Disposition")
		if contentDisposition != "" {
			fmt.Printf("im here")

			fmt.Print(url)

			_, params, err := mime.ParseMediaType(contentDisposition)
			if err == nil && params["filename"] != "" {
				finalName = params["filename"]
			}
		}
		// Fallback to URL path
		if finalName == "" {
			finalName = filepath.Base(url)
		}
	} else {
		finalName = filepath.Base(finalName)
	}

	// Generate unique file ID
	uniqueTimeBasedId := time.Now().UnixNano()

	fileID := fmt.Sprintf("%d_%s", uniqueTimeBasedId, finalName)
	filePath := filepath.Join(h.StorageDir, fileID)

	// Create destination file
	dst, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %v", err)
	}
	defer dst.Close()

	// Copy downloaded content
	written, err := io.Copy(dst, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to save file: %v", err)
	}

	return &models.FileInfo{
		ID:         fileID,
		Name:       finalName,
		Type:       "url",
		Size:       written,
		Password:   password,
		UploadTime: time.Now(),
		Path:       filePath,
		SourceURL:  url,
	}, nil
}

// sendError sends a JSON error response
func (h *UploadHandler) sendError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	response := models.UploadResponse{
		Success: false,
		Message: message,
	}
	json.NewEncoder(w).Encode(response)
}
