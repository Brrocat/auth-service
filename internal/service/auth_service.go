package service

import (
	"auth-service/internal/models"
	"auth-service/internal/repository/postgres"
	"auth-service/internal/repository/redis"
	"auth-service/pkg/jwt"
	"auth-service/pkg/password"
	"context"
	"errors"
	"fmt"
	"log/slog"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserNotActive      = errors.New("user account is not active")
	ErrInvalidToken       = errors.New("invalid token")
)

type AuthService struct {
	userRepo     *postgres.UserRepository
	sessionRepo  *redis.SessionRepository
	jwtManager   *jwt.Manager
	passwordHash *password.Hasher
	logger       *slog.Logger
}

func NewAuthService(
	userRepo *postgres.UserRepository,
	sessionRepo *redis.SessionRepository,
	jwtManager *jwt.Manager,
	passwordHash *password.Hasher,
	logger *slog.Logger,
) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		jwtManager:   jwtManager,
		passwordHash: passwordHash,
		logger:       logger,
	}
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*models.User, string, string, error) {
	s.logger.Debug("Attempting login", "email", email)

	// Get user by email
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Failed to get user by email", "email", email, "error", err)
		return nil, "", "", ErrInvalidCredentials
	}

	if user == nil {
		s.logger.Warn("User not found", "email", email)
		return nil, "", "", ErrInvalidCredentials
	}

	if !user.IsActive {
		s.logger.Warn("User account is not active", "user_id", user.ID)
		return nil, "", "", ErrUserNotActive
	}

	// Verify password
	if !s.passwordHash.Check(password, user.PasswordHash) {
		s.logger.Warn("Invalid password", "email", email)
		return nil, "", "", ErrInvalidCredentials
	}

	// Generate tokens
	accessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		s.logger.Error("Failed to generate access token", "user_id", user.ID, "error", err)
		return nil, "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		s.logger.Error("Failed to generate refresh token", "user_id", user.ID, "error", err)
		return nil, "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in Redis
	refreshExpiration := s.jwtManager.GetRefreshExpiration()
	err = s.sessionRepo.StoreRefreshToken(ctx, user.ID, refreshToken, refreshExpiration)
	if err != nil {
		s.logger.Error("Failed to store refresh token", "user_id", user.ID, "error", err)
		return nil, "", "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	s.logger.Info("User logged in successfully", "user_id", user.ID, "email", email)
	return user, accessToken, refreshToken, nil
}

func (s *AuthService) VerifyToken(ctx context.Context, token string) (*models.User, error) {
	claims, err := s.jwtManager.VerifyToken(token)
	if err != nil {
		s.logger.Warn("Token verification failed", "error", err)
		return nil, ErrInvalidToken
	}

	// Get user from database to ensure they still exist and are active
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		s.logger.Error("Failed to get user by ID", "user_id", claims.UserID, "error", err)
		return nil, ErrUserNotFound
	}

	if user == nil {
		s.logger.Warn("User not found during token verification", "user_id", claims.UserID)
		return nil, ErrUserNotFound
	}

	if !user.IsActive {
		s.logger.Warn("User account is not active during token verification", "user_id", claims.UserID)
		return nil, ErrUserNotActive
	}

	s.logger.Debug("Token verified successfully", "user_id", claims.UserID)
	return user, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	claims, err := s.jwtManager.VerifyToken(refreshToken)
	if err != nil {
		s.logger.Warn("Refresh token verification failed", "error", err)
		return "", "", ErrInvalidToken
	}

	// Verify that the refresh token exists in Redis
	storedToken, err := s.sessionRepo.GetRefreshToken(ctx, claims.UserID)
	if err != nil {
		s.logger.Error("Failed to get refresh token from Redis", "user_id", claims.UserID, "error", err)
		return "", "", fmt.Errorf("failed to verify refresh token: %w", err)
	}

	if storedToken != refreshToken {
		s.logger.Warn("Refresh token mismatch", "user_id", claims.UserID)
		return "", "", ErrInvalidToken
	}

	// Get user to ensure they still exist and are active
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		s.logger.Error("Failed to get user by ID during token refresh", "user_id", claims.UserID, "error", err)
		return "", "", ErrUserNotFound
	}

	if user == nil || !user.IsActive {
		s.logger.Warn("User not found or inactive during token refresh", "user_id", claims.UserID)
		return "", "", ErrUserNotFound
	}

	// Generate new tokens
	newAccessToken, err := s.jwtManager.GenerateAccessToken(user.ID, user.Email, user.Role)
	if err != nil {
		s.logger.Error("Failed to generate new access token", "user_id", user.ID, "error", err)
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		s.logger.Error("Failed to generate new refresh token", "user_id", user.ID, "error", err)
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Update refresh token in Redis
	refreshExpiration := s.jwtManager.GetRefreshExpiration()
	err = s.sessionRepo.StoreRefreshToken(ctx, user.ID, newRefreshToken, refreshExpiration)
	if err != nil {
		s.logger.Error("Failed to store new refresh token", "user_id", user.ID, "error", err)
		return "", "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	s.logger.Info("Tokens refreshed successfully", "user_id", user.ID)
	return newAccessToken, newRefreshToken, nil
}

func (s *AuthService) Register(ctx context.Context, req *models.CreateUserRequest) (*models.User, error) {
	s.logger.Debug("Attempting user registration", "email", req.Email)

	// Check if user already exists
	existingUser, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Error("Failed to check existing user", "email", req.Email, "error", err)
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	if existingUser != nil {
		s.logger.Warn("User already exists", "email", req.Email)
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Hash password
	passwordHash, err := s.passwordHash.Hash(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password", "email", req.Email, "error", err)
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Set default role if not provided
	if req.Role == "" {
		req.Role = "user"
	}

	// Create user
	user, err := s.userRepo.CreateUser(ctx, req, passwordHash)
	if err != nil {
		s.logger.Error("Failed to create user", "email", req.Email, "error", err)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.Info("User registered successfully", "user_id", user.ID, "email", req.Email)
	return user, nil
}
