package config

import "os"

type Config struct {
	AppEnv      string
	HTTPHost    string
	HTTPPort    string
	LogLevel    string
	DatabaseURL string
}

func Load() Config {
	return Config{
		AppEnv:      getEnv("APP_ENV", "development"),
		HTTPHost:    getEnv("HTTP_HOST", "0.0.0.0"),
		HTTPPort:    getEnv("HTTP_PORT", "8080"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		DatabaseURL: getEnv("DATABASE_URL", ""),
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
