package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/nijat-akhundzada/malcore/services/api/internal/config"
	"github.com/nijat-akhundzada/malcore/services/api/internal/database"
	httprouter "github.com/nijat-akhundzada/malcore/services/api/internal/http/router"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/logger"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
	"github.com/nijat-akhundzada/malcore/services/api/internal/storage"
)

func main() {
	_ = godotenv.Load()

	cfg := config.Load()
	log := logger.New(cfg.AppEnv)

	ctx := context.Background()

	db, err := database.NewPostgresPool(ctx, cfg.DatabaseURL, log)
	if err != nil {
		log.Error("database connection failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer db.Close()

	if err := database.RunMigrations(ctx, cfg.DatabaseURL, log); err != nil {
		log.Error("database migrations failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	jobRepo := jobs.NewRepository(db)

	store, err := newStorage(ctx, cfg)
	if err != nil {
		log.Error("storage initialization failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	queueClient := queue.NewClient(queue.RedisOptions{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	defer queueClient.Close()

	router := httprouter.New(log, jobRepo, store, queueClient)

	server := &http.Server{
		Addr:         cfg.HTTPAddr(),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("starting api server",
			slog.String("addr", cfg.HTTPAddr()),
			slog.String("env", cfg.AppEnv),
		)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	waitForShutdown(log, server)
}

func newStorage(ctx context.Context, cfg config.Config) (storage.Storage, error) {
	switch strings.ToLower(cfg.StorageBackend) {
	case "local":
		return storage.NewLocalStorage(""), nil
	case "minio", "":
		return storage.NewMinIOStorage(ctx, storage.MinIOOptions{
			Endpoint:  cfg.MinIOEndpoint,
			AccessKey: cfg.MinIOAccessKey,
			SecretKey: cfg.MinIOSecretKey,
			Bucket:    cfg.MinIOBucket,
			UseSSL:    cfg.MinIOUseSSL,
		})
	default:
		return nil, fmt.Errorf("unsupported storage backend %q", cfg.StorageBackend)
	}
}

func waitForShutdown(log *slog.Logger, server *http.Server) {
	quit := make(chan os.Signal, 1)

	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit

	log.Info("shutting down api server")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("server shutdown failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	log.Info("api server stopped")
}
