package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jcob-sikorski/cloud-native-platform/internal/models"
	"github.com/jcob-sikorski/cloud-native-platform/internal/services"
	"github.com/jcob-sikorski/cloud-native-platform/pkg/utils"
	"github.com/sirupsen/logrus"
)

// UserHandler handles user-related HTTP requests.
type UserHandler struct {
	userService services.UserService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(userService services.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// CreateUser handles the creation of a new user.
func (h *UserHandler) CreateUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}

	// Basic validation (more robust validation can be added via validator.v10)
	if user.Username == "" || user.PasswordHash == "" || user.Email == "" {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Username, password, and email are required")
		return
	}
	if !utils.IsValidEmail(user.Email) {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid email format")
		return
	}
	if !utils.IsStrongPassword(user.PasswordHash) { // PasswordHash here is the plain password from input
		utils.SendErrorResponse(c, http.StatusBadRequest, "Password is not strong enough. It must be at least 8 characters long and include uppercase, lowercase, digit, and special characters.")
		return
	}

	createdUser, err := h.userService.CreateUser(user)
	if err != nil {
		logrus.Errorf("Error creating user: %v", err)
		utils.SendErrorResponse(c, http.StatusConflict, err.Error()) // Use StatusConflict for existing user
		return
	}

	utils.SendSuccessResponse(c, http.StatusCreated, "User created successfully", createdUser)
}

// GetUserByID handles fetching a user by their ID.
func (h *UserHandler) GetUserByID(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		utils.SendErrorResponse(c, http.StatusBadRequest, "User ID is required")
		return
	}

	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		logrus.Errorf("Error getting user by ID %s: %v", userID, err)
		utils.SendErrorResponse(c, http.StatusNotFound, err.Error())
		return
	}

	utils.SendSuccessResponse(c, http.StatusOK, "User retrieved successfully", user)
}

// GetAllUsers handles fetching all users with pagination, sorting, and filtering.
func (h *UserHandler) GetAllUsers(c *gin.Context) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	sortBy := c.DefaultQuery("sortBy", "username")  // Default sort by username
	sortOrder := c.DefaultQuery("sortOrder", "asc") // Default sort order ascending
	roleFilter := c.Query("role")                   // Optional filter by role

	users, totalCount, err := h.userService.GetAllUsers(page, pageSize, sortBy, sortOrder, roleFilter)
	if err != nil {
		logrus.Errorf("Error getting all users: %v", err)
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve users")
		return
	}

	utils.SendSuccessResponse(c, http.StatusOK, "Users retrieved successfully", gin.H{
		"users":      users,
		"totalCount": totalCount,
		"page":       page,
		"pageSize":   pageSize,
	})
}

// UpdateUser handles updating an existing user's details.
func (h *UserHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		utils.SendErrorResponse(c, http.StatusBadRequest, "User ID is required")
		return
	}

	currentUserID := c.GetString("userID")
	currentUserRole := c.GetString("role")

	// Check permissions: admin can update anyone, regular users only themselves
	if currentUserRole != "admin" && currentUserID != userID {
		utils.SendErrorResponse(c, http.StatusForbidden, "You do not have the required permissions")
		return
	}

	var updateRequest models.UserUpdate
	if err := c.ShouldBindJSON(&updateRequest); err != nil {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Non-admin users cannot change roles
	if currentUserRole != "admin" && updateRequest.Roles != nil && len(updateRequest.Roles) > 0 {
		utils.SendErrorResponse(c, http.StatusForbidden, "You cannot change user roles")
		return
	}

	// Password update logic
	if updateRequest.NewPassword != "" {
		// Validate password strength
		if !utils.IsStrongPassword(updateRequest.NewPassword) {
			utils.SendErrorResponse(c, http.StatusBadRequest, "Password is not strong enough. It must be at least 8 characters long and include uppercase, lowercase, digit, and special characters.")
			return
		}

		// Regular users must provide current password
		if currentUserRole != "admin" {
			if updateRequest.CurrentPassword == "" {
				utils.SendErrorResponse(c, http.StatusBadRequest, "Current password is required to update password")
				return
			}

			// Fetch current user
			existingUser, err := h.userService.GetFullUserByID(userID)
			if err != nil {
				utils.SendErrorResponse(c, http.StatusNotFound, "User not found")
				return
			}

			if !utils.CheckPasswordHash(updateRequest.CurrentPassword, existingUser.PasswordHash) {
				utils.SendErrorResponse(c, http.StatusUnauthorized, "Current password is incorrect")
				return
			}
		}

		// If all checks pass, hash the new password
		hashedPassword, err := utils.HashPassword(updateRequest.NewPassword)
		if err != nil {
			utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to hash password")
			return
		}
		updateRequest.PasswordHash = hashedPassword
	}

	updatedUser, err := h.userService.UpdateUser(userID, updateRequest)
	if err != nil {
		logrus.Errorf("Error updating user %s: %v", userID, err)
		if strings.Contains(err.Error(), "not found") {
			utils.SendErrorResponse(c, http.StatusNotFound, "User not found")
			return
		}
		utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to update user")
		return
	}

	utils.SendSuccessResponse(c, http.StatusOK, "User updated successfully", updatedUser)
}

// DeleteUser handles deleting a user by their ID.
func (h *UserHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if userID == "" {
		utils.SendErrorResponse(c, http.StatusBadRequest, "User ID is required")
		return
	}

	err := h.userService.DeleteUser(userID)
	if err != nil {
		logrus.Errorf("Error deleting user %s: %v", userID, err)
		utils.SendErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	utils.SendSuccessResponse(c, http.StatusOK, "User deleted successfully", nil)
}
