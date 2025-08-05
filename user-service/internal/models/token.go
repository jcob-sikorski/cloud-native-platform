package models

import "time"

// Token represents a JWT refresh token or similar authentication token.
// This was the original placeholder, keeping it for now if needed, but RefreshToken is more specific.
type Token struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// RefreshToken represents a refresh token stored in the database
type RefreshToken struct {
	Token     string    `db:"token"`
	UserID    string    `db:"user_id"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
	IsRevoked bool      `db:"is_revoked"`
}
