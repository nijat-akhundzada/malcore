package models

import (
	"time"
)

// UploadRequest represents the incoming upload request
type UploadRequest struct {
	File       []byte `json:"-"`
	URL        string `json:"url,omitempty"`
	Password   string `json:"password,omitempty"`
	FileName   string `json:"fileName,omitempty"`
	UploadType string `json:"uploadType"` // "file" or "url"
}

// UploadResponse represents the response to an upload request
type UploadResponse struct {
	Success bool   `json:"success"`
	FileID  string `json:"fileId,omitempty"`
	Message string `json:"message"`
}

// FileInfo stores metadata about an uploaded file
type FileInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"` // "file" or "url"
	Size       int64     `json:"size"`
	Password   string    `json:"-"` // Never send password in response
	UploadTime time.Time `json:"uploadTime"`
	Path       string    `json:"path"`
	SourceURL  string    `json:"sourceUrl,omitempty"`
}

// UploadStatus represents the status of a file upload
type UploadStatus struct {
	FileID   string    `json:"fileId"`
	Status   string    `json:"status"` // "pending", "processing", "completed", "error"
	Message  string    `json:"message,omitempty"`
	FileInfo *FileInfo `json:"fileInfo,omitempty"`
}
