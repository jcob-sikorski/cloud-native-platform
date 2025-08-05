package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jcob-sikorski/cloud-native-platform/internal/models"
)

// Claims defines the JWT claims structure
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// generateAccessToken generates a new JWT access token
func GenerateAccessToken(user *models.User, jwtSecret []byte) (string, error) {
	// Access token with a short lifespan (e.g., 15 minutes)
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Roles:    user.Roles, // Assuming user.Roles is already []string or pq.StringArray compatible
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}
