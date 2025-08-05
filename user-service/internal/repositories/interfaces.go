package repositories

import "github.com/jcob-sikorski/cloud-native-platform/internal/models"

// UserRepository defines the interface for user data operations
type UserRepository interface {
	GetAllUsers(limit, offset int, sortBy, sortOrder, roleFilter string) ([]models.UserResponse, error)
	GetUserByID(id string) (*models.UserResponse, error) // Returns UserResponse for external use
	GetFullUserByID(id string) (*models.User, error)     // Returns full User for internal use
	GetUserByUsername(username string) (*models.User, error)
	CreateUser(user models.User) (*models.UserResponse, error)
	UpdateUser(id string, update models.UserUpdate) (*models.UserResponse, error)
	DeleteUser(id string) error
	GetUsersCount(roleFilter string) (int, error)
	CheckUsernameExists(username string, excludeUserID string) (bool, error)
	CheckEmailExists(email string, excludeUserID string) (bool, error)
}

// RefreshTokenRepository defines the interface for refresh token data operations
type RefreshTokenRepository interface {
	CreateToken(token models.RefreshToken) error
	GetToken(tokenString string) (*models.RefreshToken, error)
	RevokeToken(tokenString string) error
	RevokeAllUserTokens(userID string) error
}
