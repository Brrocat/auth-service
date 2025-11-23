package redis

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"time"
)

type SessionRepository struct {
	client *redis.Client
}

func NewSessionRepository(redisURL string) (*SessionRepository, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &SessionRepository{client: client}, nil
}

func (r *SessionRepository) Close() {
	if r.client != nil {
		r.client.Close()
	}
}

func (r *SessionRepository) StoreRefreshToken(ctx context.Context, userID, refreshToken string, expiration time.Duration) error {
	key := fmt.Sprintf("refresh_token:%s", userID)
	err := r.client.Set(ctx, key, refreshToken, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to store refresh token: %w", err)
	}
	return nil
}

func (r *SessionRepository) GetRefreshToken(ctx context.Context, userID string) (string, error) {
	key := fmt.Sprintf("refresh_token:%s", userID)
	token, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", fmt.Errorf("failed to get refresh token: %w", err)
	}
	return token, nil
}

func (r *SessionRepository) DeleteRefreshToken(ctx context.Context, userID string) error {
	key := fmt.Sprintf("refresh_token:%s", userID)
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	return nil
}

func (r *SessionRepository) StoreSession(ctx context.Context, sessionID string, data map[string]interface{}, expiration time.Duration) error {
	key := fmt.Sprintf("session:%s", sessionID)
	err := r.client.HSet(ctx, key, data).Err()
	if err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	// Set expiration
	err = r.client.Expire(ctx, key, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to set session expiration: %w", err)
	}

	return nil
}

func (r *SessionRepository) GetSession(ctx context.Context, sessionID string) (map[string]string, error) {
	key := fmt.Sprintf("session:%s", sessionID)
	result, err := r.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return result, nil
}
