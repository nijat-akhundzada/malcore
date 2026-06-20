package router

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nijat-akhundzada/malcore/services/api/internal/downloader"
	"github.com/nijat-akhundzada/malcore/services/api/internal/http/handlers"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
	"github.com/nijat-akhundzada/malcore/services/api/internal/storage"
)

func New(log *slog.Logger, jobRepo *jobs.Repository, store storage.Storage, enqueuer queue.Enqueuer) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	jobHandler := handlers.NewJobHandler(jobRepo)
	dl := downloader.NewDefaultDownloader(log)
	uploadHandler := handlers.NewUploadHandler(log, jobRepo, store, enqueuer)
	urlHandler := handlers.NewURLHandler(log, jobRepo, dl, store, enqueuer)

	r.Get("/health", handlers.Health)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/jobs", jobHandler.Create)
		r.Get("/jobs/{id}", jobHandler.FindByID)

		r.Post("/files/upload", uploadHandler.Upload)
		r.Post("/urls/submit", urlHandler.Submit)
	})

	log.Info("router initialized")

	return r
}
