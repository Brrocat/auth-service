package main

import (
	"auth-service/internal/config"
	"auth-service/internal/handler"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
	"auth-service/internal/service"
	"auth-service/pkg/jwt"
	"auth-service/pkg/password"
	"github.com/Brrocat/car-sharing-protos/proto/auth"
	"google.golang.org/grpc"
	"log"
	"log/slog"
	"net"
	"os"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Setup logger
	logger := setupLogger(cfg.Env)

	// Initialize repositories
	userRepo, err := postgres.NewUserRepository(cfg.DatabaseURL)
	if err != nil {
		logger.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer userRepo.Close()

	sessionRepo, err := redis.NewSessionRepository(cfg.RedisURL)
	if err != nil {
		logger.Error("Failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	defer sessionRepo.Close()

	// Initialize utilities
	jwtManager := jwt.NewManager(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath, cfg.JWTExpiration)
	passwordHasher := password.NewHasher()

	// Initialize service
	authService := service.NewAuthService(userRepo, sessionRepo, jwtManager, passwordHasher, logger)

	// Initialize gRPC handler
	authHandler := handler.NewAuthHandler(authService, logger)

	// Start gRPC server
	lis, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		logger.Error("Failed to listen", "port", cfg.Port, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer()
	auth.RegisterAuthServiceServer(grpcServer, authHandler)

	logger.Info("Starting auth service", "port", cfg.Port, "env", cfg.Env)
	if err := grpcServer.Serve(lis); err != nil {
		logger.Error("Failed to serve gRPC", "error", err)
		os.Exit(1)
	}
}

func setupLogger(env string) *slog.Logger {
	var logger *slog.Logger

	switch env {
	case "development":
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	default:
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		}))
	}

	return logger
}