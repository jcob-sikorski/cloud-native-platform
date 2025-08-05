package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus" // Import logrus
	"golang.org/x/crypto/bcrypt"

	"github.com/jcob-sikorski/cloud-native-platform/internal/auth"
	"github.com/jcob-sikorski/cloud-native-platform/internal/models"
	"github.com/jcob-sikorski/cloud-native-platform/internal/repositories"
)

// AuthService provides authentication-related business logic.
type AuthService interface {
	RegisterUser(username, password, email string) (*models.UserResponse, error)
	LoginUser(username, password string) (string, string, *models.UserResponse, error)
	RefreshToken(refreshTokenString string) (string, string, *models.UserResponse, error)
	LogoutUser(refreshTokenString string) error
}

type authService struct {
	userRepo  repositories.UserRepository
	tokenRepo repositories.RefreshTokenRepository
	jwtSecret []byte
}

// NewAuthService creates a new AuthService.
func NewAuthService(userRepo repositories.UserRepository, tokenRepo repositories.RefreshTokenRepository, jwtSecret []byte) AuthService {
	return &authService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		jwtSecret: jwtSecret,
	}
}

// RegisterUser registers a new user, hashes their password, and saves them to the database.
func (s *authService) RegisterUser(username, password, email string) (*models.UserResponse, error) {
	// Check if username or email already exists
	usernameExists, err := s.userRepo.CheckUsernameExists(username, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check username existence: %w", err)
	}
	if usernameExists {
		return nil, errors.New("username already exists")
	}

	emailExists, err := s.userRepo.CheckEmailExists(email, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}
	if emailExists {
		return nil, errors.New("email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := models.User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		Roles:        []string{"user"}, // Default role
	}

	userResp, err := s.userRepo.CreateUser(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in repository: %w", err)
	}

	return userResp, nil
}

// LoginUser authenticates a user and generates JWT and refresh tokens upon successful login.
func (s *authService) LoginUser(username, password string) (string, string, *models.UserResponse, error) {
	// --- START DEBUG LOGGING ---
	logrus.Debugf("AuthService.LoginUser: Attempting login for username '%s'", username)
	logrus.Debugf("AuthService.LoginUser: Received password (plain-text, for debug only!): '%s'", password) // CAUTION: Do NOT log plain passwords in production!
	// --- END DEBUG LOGGING ---

	user, err := s.userRepo.GetUserByUsername(username)
	if err != nil {
		logrus.Errorf("AuthService.LoginUser: Error retrieving user '%s' from repository: %v", username, err)
		return "", "", nil, errors.New("invalid credentials")
	}
	if user == nil {
		logrus.Debugf("AuthService.LoginUser: User '%s' not found in database.", username)
		return "", "", nil, errors.New("invalid credentials")
	}

	// --- START DEBUG LOGGING ---
	logrus.Debugf("AuthService.LoginUser: User '%s' found. Stored hash from DB: '%s'", username, user.PasswordHash)
	// --- END DEBUG LOGGING ---

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// --- START DEBUG LOGGING ---
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			logrus.Errorf("AuthService.LoginUser: Password mismatch for user '%s'. Bcrypt error: %v", username, err)
		} else {
			logrus.Errorf("AuthService.LoginUser: Unexpected bcrypt comparison error for user '%s': %v", username, err)
		}
		// --- END DEBUG LOGGING ---
		return "", "", nil, errors.New("invalid credentials")
	}

	// --- START DEBUG LOGGING ---
	logrus.Debugf("AuthService.LoginUser: Password matched for user '%s'. Generating tokens.", username)
	// --- END DEBUG LOGGING ---

	accessToken, err := auth.GenerateAccessToken(user, s.jwtSecret)
	if err != nil {
		logrus.Errorf("AuthService.LoginUser: Failed to generate access token for user '%s': %v", username, err)
		return "", "", nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		logrus.Errorf("AuthService.LoginUser: Failed to generate refresh token for user '%s': %v", username, err)
		return "", "", nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	userResp, err := s.userRepo.GetUserByID(user.ID) // Get UserResponse format
	if err != nil {
		logrus.Errorf("AuthService.LoginUser: Failed to get user response after login for user '%s': %v", username, err)
		return "", "", nil, fmt.Errorf("failed to get user response after login: %w", err)
	}

	return accessToken, refreshToken, userResp, nil
}

// RefreshToken validates a refresh token and issues new access and refresh tokens.
func (s *authService) RefreshToken(refreshTokenString string) (string, string, *models.UserResponse, error) {
	storedToken, err := s.tokenRepo.GetToken(refreshTokenString)
	if err != nil || storedToken == nil || storedToken.IsRevoked || storedToken.ExpiresAt.Before(time.Now()) {
		logrus.Errorf("AuthService.RefreshToken: Invalid, expired, or revoked refresh token: %v", err)
		return "", "", nil, errors.New("invalid or expired refresh token")
	}

	user, err := s.userRepo.GetUserByID(storedToken.UserID)
	if err != nil || user == nil {
		logrus.Errorf("AuthService.RefreshToken: User associated with refresh token '%s' not found: %v", storedToken.UserID, err)
		return "", "", nil, errors.New("user associated with refresh token not found")
	}

	// Revoke the old refresh token to ensure one-time use
	if err := s.tokenRepo.RevokeToken(refreshTokenString); err != nil {
		logrus.Errorf("AuthService.RefreshToken: Failed to revoke old refresh token '%s': %v", refreshTokenString, err)
		return "", "", nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// Generate new tokens
	newAccessToken, err := auth.GenerateAccessToken(&models.User{
		ID: user.ID, Username: user.Username, Roles: user.Roles,
	}, s.jwtSecret)
	if err != nil {
		logrus.Errorf("AuthService.RefreshToken: Failed to generate new access token for user '%s': %v", user.ID, err)
		return "", "", nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	newRefreshToken, err := s.generateRefreshToken(&models.User{
		ID: user.ID, Username: user.Username, Roles: user.Roles,
	})
	if err != nil {
		logrus.Errorf("AuthService.RefreshToken: Failed to generate new refresh token for user '%s': %v", user.ID, err)
		return "", "", nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	return newAccessToken, newRefreshToken, user, nil
}

// LogoutUser revokes a specific refresh token.
func (s *authService) LogoutUser(refreshTokenString string) error {
	err := s.tokenRepo.RevokeToken(refreshTokenString)
	if err != nil {
		logrus.Errorf("AuthService.LogoutUser: Failed to revoke refresh token '%s': %v", refreshTokenString, err)
	}
	return err
}

// generateRefreshToken generates a new refresh token and stores it in the database
func (s *authService) generateRefreshToken(user *models.User) (string, error) {
	// Refresh token with a long lifespan (e.g., 7 days)
	tokenString := uuid.New().String()
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	refreshToken := models.RefreshToken{
		Token:     tokenString,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
		IsRevoked: false, // Ensure it's not revoked initially
	}

	err := s.tokenRepo.CreateToken(refreshToken)
	if err != nil {
		logrus.Errorf("AuthService.generateRefreshToken: Failed to save refresh token for user '%s': %v", user.ID, err)
		return "", fmt.Errorf("failed to save refresh token: %w", err)
	}

	return tokenString, nil
}
