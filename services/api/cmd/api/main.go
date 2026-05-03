package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/nijat-akhundzada/malcore/services/api/internal/config"
	httprouter "github.com/nijat-akhundzada/malcore/services/api/internal/http/router"
	"github.com/nijat-akhundzada/malcore/services/api/internal/logger"
)

func main() {
	_ = godotenv.Load()

	cfg := config.Load()
	log := logger.New(cfg.AppEnv)

	router := httprouter.New(log)

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
