package auth

// LoginRequest struct for handling login requests
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RefreshRequest struct for handling refresh token requests
type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

// TokenResponse struct for sending back access and refresh tokens
type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// RegisterRequest represents the request body for user registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}
