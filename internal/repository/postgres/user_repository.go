package postgres

import (
	"auth-service/internal/models"
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type UserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(databaseURL string) (*UserRepository, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &UserRepository{db: pool}, nil
}

func (r *UserRepository) Close() {
	if r.db != nil {
		r.db.Close()
	}
}

func (r *UserRepository) CreateUser(ctx context.Context, user *models.CreateUserRequest, passwordHash string) (*models.User, error) {
	query := `
			INSERT INTO users (email, password_hash, role, is_action)
			VALUES ($1, $2, $3, $4)
			RETURNING id, created_at, updated_at  
	`

	var id string
	var createdAt, updatedAt time.Time

	err := r.db.QueryRow(ctx, query,
		user.Email,
		passwordHash,
		user.Role,
		true,
	).Scan(&id, &createdAt, &updatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &models.User{
		ID:           id,
		Email:        user.Email,
		PasswordHash: passwordHash,
		Role:         user.Role,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
		IsActive:     true,
	}, nil
}

func (r *UserRepository) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	query := `
			SELECT id, email, password_hash, role, created_at, updated_at,  is_active
			FROM users
			WHERE id = $1 AND is_active = true  
	`

	var user *models.User
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.IsActive,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return user, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, password_hash, role, created_at, updated_at, is_active
		FROM users
		WHERE email = $1 AND is_active = true
	`

	var user models.User
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.IsActive,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) UpdateUser(ctx context.Context, id string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	query := "UPDATE users SET "
	params := []interface{}{}
	paramCount := 1

	for field, value := range updates {
		query += fmt.Sprintf("%s = $%d, ", field, paramCount)
		params = append(params, value)
		paramCount++
	}

	query += "updated_at = NOW() WHERE id = $" + fmt.Sprintf("%d", paramCount)
	params = append(params, id)

	_, err := r.db.Exec(ctx, query, params...)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (r *UserRepository) DeleteUser(ctx context.Context, id string) error {
	query := "UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1"
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}
