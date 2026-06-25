package config

import (
	"os"
	"strconv"
)

type Config struct {
	AppEnv            string
	HTTPHost          string
	HTTPPort          string
	LogLevel          string
	DatabaseURL       string
	StorageBackend    string
	MinIOEndpoint     string
	MinIOAccessKey    string
	MinIOSecretKey    string
	MinIOBucket       string
	MinIOUseSSL       bool
	RedisAddr         string
	RedisPassword     string
	RedisDB           int
	WorkerConcurrency int
	AnalyzerCommand   string
	AnalyzerScript    string
	AnalyzerTimeout   int
	AnalyzerTempDir   string
}

func Load() Config {
	return Config{
		AppEnv:            getEnv("APP_ENV", "development"),
		HTTPHost:          getEnv("HTTP_HOST", "0.0.0.0"),
		HTTPPort:          getEnv("HTTP_PORT", "8080"),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://malcore:malcore@localhost:5432/malcore?sslmode=disable"),
		StorageBackend:    getEnv("STORAGE_BACKEND", "minio"),
		MinIOEndpoint:     getEnv("MINIO_ENDPOINT", "localhost:9000"),
		MinIOAccessKey:    getEnv("MINIO_ACCESS_KEY", "malcore"),
		MinIOSecretKey:    getEnv("MINIO_SECRET_KEY", "malcore-password"),
		MinIOBucket:       getEnv("MINIO_BUCKET", "malcore-quarantine"),
		MinIOUseSSL:       getEnv("MINIO_USE_SSL", "false") == "true",
		RedisAddr:         getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:     getEnv("REDIS_PASSWORD", ""),
		RedisDB:           getEnvInt("REDIS_DB", 0),
		WorkerConcurrency: getEnvInt("WORKER_CONCURRENCY", 2),
		AnalyzerCommand:   getEnv("ANALYZER_COMMAND", "python3"),
		AnalyzerScript:    getEnv("ANALYZER_SCRIPT", "/app/analyzer/analyze.py"),
		AnalyzerTimeout:   getEnvInt("ANALYZER_TIMEOUT_SECONDS", 60),
		AnalyzerTempDir:   getEnv("ANALYZER_TEMP_DIR", "/tmp/malcore-analyzer"),
	}
}

func (c Config) HTTPAddr() string {
	return c.HTTPHost + ":" + c.HTTPPort
}

func getEnv(key string, fallback string) string {
	value := os.Getenv(key)

	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return parsed
}
