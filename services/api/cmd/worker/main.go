package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/joho/godotenv"
	"github.com/nijat-akhundzada/malcore/services/api/internal/config"
	"github.com/nijat-akhundzada/malcore/services/api/internal/database"
	"github.com/nijat-akhundzada/malcore/services/api/internal/jobs"
	"github.com/nijat-akhundzada/malcore/services/api/internal/logger"
	"github.com/nijat-akhundzada/malcore/services/api/internal/queue"
	"github.com/nijat-akhundzada/malcore/services/api/internal/worker"
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

	server := asynq.NewServer(
		queue.RedisClientOpt(queue.RedisOptions{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		}),
		asynq.Config{
			Concurrency: cfg.WorkerConcurrency,
			Queues: map[string]int{
				queue.AnalysisQueue: 10,
			},
		},
	)

	fetcher, err := worker.NewMinIOObjectFetcher(worker.MinIOObjectFetcherOptions{
		Endpoint:  cfg.MinIOEndpoint,
		AccessKey: cfg.MinIOAccessKey,
		SecretKey: cfg.MinIOSecretKey,
		Bucket:    cfg.MinIOBucket,
		UseSSL:    cfg.MinIOUseSSL,
		TempDir:   cfg.AnalyzerTempDir,
	})
	if err != nil {
		log.Error("object fetcher initialization failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	analyzer, err := worker.NewPythonAnalyzer(worker.PythonAnalyzerOptions{
		Command:    cfg.AnalyzerCommand,
		ScriptPath: cfg.AnalyzerScript,
		Timeout:    time.Duration(cfg.AnalyzerTimeout) * time.Second,
		Fetcher:    fetcher,
	})
	if err != nil {
		log.Error("analyzer initialization failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	mux := asynq.NewServeMux()
	worker.NewHandler(
		jobs.NewRepository(db),
		analyzer,
	).Register(mux)

	go func() {
		log.Info("starting worker",
			slog.String("redis_addr", cfg.RedisAddr),
			slog.Int("concurrency", cfg.WorkerConcurrency),
			slog.String("analyzer_script", cfg.AnalyzerScript),
		)

		if err := server.Run(mux); err != nil {
			log.Error("worker stopped with error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	waitForShutdown(log, server)
}

func waitForShutdown(log *slog.Logger, server *asynq.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit

	log.Info("shutting down worker")
	server.Shutdown()
	log.Info("worker stopped")
}
