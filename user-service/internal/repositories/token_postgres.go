package repositories

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jcob-sikorski/cloud-native-platform/internal/models"
	"github.com/jmoiron/sqlx"
)

// PostgresRefreshTokenRepository implements RefreshTokenRepository for PostgreSQL
type PostgresRefreshTokenRepository struct {
	db *sqlx.DB
}

// NewPostgresRefreshTokenRepository creates a new instance of PostgresRefreshTokenRepository
func NewPostgresRefreshTokenRepository(db *sqlx.DB) *PostgresRefreshTokenRepository {
	return &PostgresRefreshTokenRepository{db: db}
}

// CreateToken inserts a new refresh token into the database
func (repo *PostgresRefreshTokenRepository) CreateToken(token models.RefreshToken) error {
	token.CreatedAt = time.Now() // Ensure CreatedAt is set
	_, err := repo.db.Exec(`
        INSERT INTO refresh_tokens (token, user_id, expires_at, created_at, is_revoked) VALUES ($1, $2, $3, $4, $5)`,
		token.Token, token.UserID, token.ExpiresAt, token.CreatedAt, token.IsRevoked)
	if err != nil {
		return fmt.Errorf("error creating refresh token: %w", err)
	}
	return nil
}

// GetToken retrieves a refresh token from the database
func (repo *PostgresRefreshTokenRepository) GetToken(tokenString string) (*models.RefreshToken, error) {
	var rt models.RefreshToken
	err := repo.db.Get(&rt, `
        SELECT token, user_id, expires_at, created_at, is_revoked FROM refresh_tokens WHERE token = $1`, tokenString)
	if err == sql.ErrNoRows {
		return nil, nil // Token not found
	}
	if err != nil {
		return nil, fmt.Errorf("error querying refresh token: %w", err)
	}
	return &rt, nil
}

// RevokeToken marks a refresh token as revoked
func (repo *PostgresRefreshTokenRepository) RevokeToken(tokenString string) error {
	result, err := repo.db.Exec(`UPDATE refresh_tokens SET is_revoked = TRUE WHERE token = $1`, tokenString)
	if err != nil {
		return fmt.Errorf("error revoking refresh token: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("refresh token %s not found for revocation", tokenString)
	}
	return nil
}

// RevokeAllUserTokens revokes all tokens for a specific user
func (repo *PostgresRefreshTokenRepository) RevokeAllUserTokens(userID string) error {
	result, err := repo.db.Exec(`UPDATE refresh_tokens SET is_revoked = TRUE WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("error revoking all user refresh tokens: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("no refresh tokens found for user ID %s to revoke", userID)
	}
	return nil
}
