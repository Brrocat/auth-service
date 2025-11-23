package handler

import (
	"auth-service/internal/service"
	"context"
	"github.com/Brrocat/car-sharing-protos/proto/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
)

type AuthHandler struct {
	auth.UnimplementedAuthServiceServer
	authService *service.AuthService
	logger      *slog.Logger
}

func NewAuthHandler(authService *service.AuthService, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

func (h *AuthHandler) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	h.logger.Debug("Login request received", "email", req.Email)

	user, accessToken, refreshToken, err := h.authService.Login(ctx, req.Email, req.Password)
	if err != nil {
		h.logger.Warn("Login failed", "email", req.Email, "error", err)

		switch err {
		case service.ErrInvalidCredentials:
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		case service.ErrUserNotActive:
			return nil, status.Error(codes.PermissionDenied, "user account is not active")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	h.logger.Info("Login successful", "user_id", user.ID, "email", req.Email)

	return &auth.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    nil, // This should be calculated based on token expiration
	}, nil
}

func (h *AuthHandler) VerifyToken(ctx context.Context, req *auth.VerifyTokenRequest) (*auth.VerifyTokenResponse, error) {
	h.logger.Debug("VerifyToken request received")

	user, err := h.authService.VerifyToken(ctx, req.Token)
	if err != nil {
		h.logger.Warn("Token verification failed ", "error", err)

		switch err {
		case service.ErrInvalidToken:
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		case service.ErrUserNotFound, service.ErrUserNotActive:
			return nil, status.Error(codes.PermissionDenied, "user not found or inactive")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	h.logger.Debug("Token verify successfully", "user_id", user.ID)

	return &auth.VerifyTokenResponse{
		Valid:  true,
		UserId: user.ID,
		Email:  user.Email,
		Role:   user.Role,
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.RefreshTokenResponse, error) {
	h.logger.Debug("RefreshToken request received")

	accessToken, refreshToken, err := h.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		h.logger.Warn("Token refresh failed", "error", err)

		switch err {
		case service.ErrInvalidToken:
			return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
		case service.ErrUserNotFound:
			return nil, status.Error(codes.Unauthenticated, "user not found")
		default:
			return nil, status.Error(codes.Internal, "internal server error")
		}
	}

	h.logger.Info("Token refresh successful")

	return &auth.RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    nil, // This shold be calculated based on token expiration
	}, nil
}
