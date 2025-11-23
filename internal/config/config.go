package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env               string
	Port              string
	DatabaseURL       string
	RedisURL          string
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	JWTExpiration     time.Duration
}

func Load() (*Config, error) {
	cfg := &Config{
		Env:               getEnv("ENV", "development"),
		Port:              getEnv("PORT", "50051"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://user:Bogdan_20 @localhost:5432/auth_db?sslmode=disable"),
		RedisURL:          getEnv("REDIS_URL", "redis://localhost:6379/0"),
		JWTPrivateKeyPath: getEnv("JWT_PRIVATE_KEY_PATH", "./keys/private.pem"),
		JWTPublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem"),
	}

	// Parse JWT expiration
	expirationStr := getEnv("JWT_EXPIRATION", "24h")
	expiration, err := time.ParseDuration(expirationStr)
	if err != nil {
		return nil, err
	}
	cfg.JWTExpiration = expiration

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}

	return defaultValue
}
