package services

import (
	"errors"
	"fmt"

	"github.com/jcob-sikorski/cloud-native-platform/internal/models"
	"github.com/jcob-sikorski/cloud-native-platform/internal/repositories"
	"golang.org/x/crypto/bcrypt"
)

// UserService provides business logic for user management.
type UserService interface {
	CreateUser(user models.User) (*models.UserResponse, error)
	GetUserByID(id string) (*models.UserResponse, error) // For API responses
	GetFullUserByID(id string) (*models.User, error)     // For internal use
	GetAllUsers(page, pageSize int, sortBy, sortOrder, roleFilter string) ([]models.UserResponse, int, error)
	UpdateUser(id string, update models.UserUpdate) (*models.UserResponse, error)
	DeleteUser(id string) error
}

type userService struct {
	userRepo repositories.UserRepository
}

// NewUserService creates a new UserService.
func NewUserService(userRepo repositories.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

// CreateUser creates a new user.
func (s *userService) CreateUser(user models.User) (*models.UserResponse, error) {
	// Check if username or email already exists
	usernameExists, err := s.userRepo.CheckUsernameExists(user.Username, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check username existence: %w", err)
	}
	if usernameExists {
		return nil, errors.New("username already exists")
	}

	emailExists, err := s.userRepo.CheckEmailExists(user.Email, "")
	if err != nil {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}
	if emailExists {
		return nil, errors.New("email already exists")
	}

	// Hash password before saving
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}
	user.PasswordHash = string(hashedPassword)

	userResp, err := s.userRepo.CreateUser(user)
	if err != nil {
		return nil, fmt.Errorf("service: failed to create user: %w", err)
	}
	return userResp, nil
}

// GetUserByID retrieves a user by their ID.
func (s *userService) GetUserByID(id string) (*models.UserResponse, error) {
	user, err := s.userRepo.GetUserByID(id)
	if err != nil {
		return nil, fmt.Errorf("service: failed to get user by ID: %w", err)
	}
	if user == nil {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// GetFullUserByID retrieves a full user by their ID for internal use (e.g., password check)
func (s *userService) GetFullUserByID(id string) (*models.User, error) {
	user, err := s.userRepo.GetFullUserByID(id) // Calls the new repository method
	if err != nil {
		return nil, fmt.Errorf("service: failed to get full user by ID: %w", err)
	}
	if user == nil {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// GetAllUsers retrieves all users with pagination, sorting, and filtering.
func (s *userService) GetAllUsers(page, pageSize int, sortBy, sortOrder, roleFilter string) ([]models.UserResponse, int, error) {
	offset := (page - 1) * pageSize
	users, err := s.userRepo.GetAllUsers(pageSize, offset, sortBy, sortOrder, roleFilter)
	if err != nil {
		return nil, 0, fmt.Errorf("service: failed to get all users: %w", err)
	}

	totalCount, err := s.userRepo.GetUsersCount(roleFilter)
	if err != nil {
		return nil, 0, fmt.Errorf("service: failed to get users count: %w", err)
	}

	return users, totalCount, nil
}

// UpdateUser updates an existing user.
func (s *userService) UpdateUser(id string, update models.UserUpdate) (*models.UserResponse, error) {
	// Check for duplicate username/email if they are being updated
	if update.Username != nil {
		exists, err := s.userRepo.CheckUsernameExists(*update.Username, id)
		if err != nil {
			return nil, fmt.Errorf("failed to check username existence during update: %w", err)
		}
		if exists {
			return nil, errors.New("username already taken")
		}
	}
	if update.Email != nil {
		exists, err := s.userRepo.CheckEmailExists(*update.Email, id)
		if err != nil {
			return nil, fmt.Errorf("failed to check email existence during update: %w", err)
		}
		if exists {
			return nil, errors.New("email already taken")
		}
	}

	userResp, err := s.userRepo.UpdateUser(id, update)
	if err != nil {
		return nil, fmt.Errorf("service: failed to update user: %w", err)
	}
	return userResp, nil
}

// DeleteUser deletes a user by their ID.
func (s *userService) DeleteUser(id string) error {
	// Optionally, revoke all user's refresh tokens upon deletion
	// if err := s.tokenRepo.RevokeAllUserTokens(id); err != nil {
	// 	logrus.Warnf("Failed to revoke all tokens for user %s during deletion: %v", id, err)
	// }

	if err := s.userRepo.DeleteUser(id); err != nil {
		return fmt.Errorf("service: failed to delete user: %w", err)
	}
	return nil
}
