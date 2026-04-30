package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"zorbox-backend/handlers"
)

func main() {
	// Get working directory
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed to get working directory:", err)
	}

	// Setup storage directory
	storageDir := filepath.Join(wd, "storage")
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Fatal("Failed to create storage directory:", err)
	}

	// Create upload handler
	uploadHandler := handlers.NewUploadHandler(storageDir)

	// Create Chi router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// CORS configuration
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "https://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Routes
	r.Post("/api/upload", uploadHandler.ServeHTTP)
	r.Get("/api/health", healthHandler)
	r.Get("/api/files/*", fileServer(storageDir))

	// Start server
	port := ":8080"
	fmt.Printf("🚀 Zorbox Backend Server starting on port %s\n", port)
	fmt.Printf("📁 Storage directory: %s\n", storageDir)
	fmt.Println("📡 API Endpoints:")
	fmt.Println("  POST /api/upload     - Upload files")
	fmt.Println("  GET  /api/health     - Health check")
	fmt.Println("  GET  /api/files/{id} - Access uploaded files")

	if err := http.ListenAndServe(port, r); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// healthHandler returns the health status
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// fileServer serves uploaded files
func fileServer(storageDir string) http.HandlerFunc {
	return http.StripPrefix("/api/files/", http.FileServer(http.Dir(storageDir))).ServeHTTP
}
