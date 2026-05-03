package router

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nijat-akhundzada/malcore/services/api/internal/http/handlers"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
)

func New(log *slog.Logger, jobRepo *jobs.Repository) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	jobHandler := handlers.NewJobHandler(jobRepo)

	r.Get("/health", handlers.Health)

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/jobs", jobHandler.Create)
		r.Get("/jobs/{id}", jobHandler.FindByID)
	})

	log.Info("router initialized")

	return r
}
