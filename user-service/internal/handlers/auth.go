package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jcob-sikorski/cloud-native-platform/internal/auth"
	"github.com/jcob-sikorski/cloud-native-platform/internal/services"
	"github.com/jcob-sikorski/cloud-native-platform/pkg/utils"
	"github.com/sirupsen/logrus"
)

// AuthHandler handles authentication-related HTTP requests.
type AuthHandler struct {
	authService services.AuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authService services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// Register handles user registration.
func (h *AuthHandler) Register(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}

	// Basic validation (more robust validation can be added via validator.v10)
	if req.Username == "" || req.Password == "" || req.Email == "" {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Username, password, and email are required")
		return
	}
	if !utils.IsValidEmail(req.Email) {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid email format")
		return
	}
	if !utils.IsStrongPassword(req.Password) {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Password is not strong enough. It must be at least 8 characters long and include uppercase, lowercase, digit, and special characters.")
		return
	}

	userResp, err := h.authService.RegisterUser(req.Username, req.Password, req.Email)
	if err != nil {
		logrus.Errorf("Error registering user: %v", err)
		utils.SendErrorResponse(c, http.StatusConflict, err.Error()) // Use StatusConflict for existing user
		return
	}

	utils.SendSuccessResponse(c, http.StatusCreated, "User registered successfully", userResp)
}

// Login handles user login.
func (h *AuthHandler) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}

	// Basic validation
	if req.Username == "" || req.Password == "" {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Username and password are required")
		return
	}

	accessToken, refreshToken, _, err := h.authService.LoginUser(req.Username, req.Password)
	if err != nil {
		logrus.Errorf("Error logging in user: %v", err)
		utils.SendErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}

	response := auth.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	// You might want to set refresh token as an HttpOnly cookie
	// c.SetCookie("refresh_token", refreshToken, int(7*24*time.Hour/time.Second), "/", "localhost", false, true)

	utils.SendSuccessResponse(c, http.StatusOK, "Login successful", response)
}

// RefreshToken handles token refresh requests.
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req auth.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}

	newAccessToken, newRefreshToken, _, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		logrus.Errorf("Error refreshing token: %v", err)
		utils.SendErrorResponse(c, http.StatusUnauthorized, err.Error())
		return
	}

	response := auth.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}
	utils.SendSuccessResponse(c, http.StatusOK, "Token refreshed successfully", response)
}

// Logout handles user logout by revoking the refresh token.
func (h *AuthHandler) Logout(c *gin.Context) {
	var logoutRequest struct {
		RefreshToken string `json:"refreshToken" binding:"required"`
	}

	if err := c.ShouldBindJSON(&logoutRequest); err != nil {
		utils.SendErrorResponse(c, http.StatusBadRequest, "Refresh token is required")
		return
	}

	// Try to revoke the token
	err := h.authService.LogoutUser(logoutRequest.RefreshToken)
	if err != nil {
		// Check if it's a "token not found" error vs already revoked
		// You'll need to distinguish between these cases in your service/repository
		if strings.Contains(err.Error(), "not found") {
			logrus.Errorf("Logout failed: %v", err)
			utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to logout")
			return
		}
		// If it's already revoked, treat as success (idempotent)
		logrus.Warnf("Logout attempted with token that may already be revoked: %v", err)
	}

	utils.SendSuccessResponse(c, http.StatusOK, "Logged out successfully", nil)
}
