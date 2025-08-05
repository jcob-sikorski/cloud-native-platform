package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	// Added for bcrypt.GenerateFromPassword in truncateTables
	"github.com/jcob-sikorski/cloud-native-platform/internal/auth"
	"github.com/jcob-sikorski/cloud-native-platform/internal/config"
	"github.com/jcob-sikorski/cloud-native-platform/internal/database"
	"github.com/jcob-sikorski/cloud-native-platform/internal/handlers"
	"github.com/jcob-sikorski/cloud-native-platform/internal/repositories"
	"github.com/jcob-sikorski/cloud-native-platform/internal/services"
	"github.com/jcob-sikorski/cloud-native-platform/pkg/utils"
)

// Global variables for the test suite
var router *gin.Engine // This will be the main router without global rate limiting
var userRepo repositories.UserRepository
var tokenRepo repositories.RefreshTokenRepository
var userService services.UserService
var authService services.AuthService
var healthHandler *handlers.HealthHandler
var userHandler *handlers.UserHandler
var authHandler *handlers.AuthHandler
var jwtSecret []byte
var dbURL string // Store DB URL for external commands if needed

// TestMain sets up the test environment before all tests run and tears it down afterwards.
func TestMain(m *testing.M) {
	// Load environment variables for tests
	if err := godotenv.Load("../../.env"); err != nil { // Adjust path if .env is not in project root
		logrus.Warn("No .env file found for tests, assuming environment variables are set.")
	}

	// Initialize configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration for tests: %v", err)
	}
	jwtSecret = cfg.JWTSecret

	// Connect to database
	db, err := database.ConnectDB(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database for tests: %v", err)
	}
	defer db.Close()

	// Initialize repositories
	userRepo = repositories.NewPostgresUserRepository(db)
	tokenRepo = repositories.NewPostgresRefreshTokenRepository(db)

	// Initialize services
	userService = services.NewUserService(userRepo)
	authService = services.NewAuthService(userRepo, tokenRepo, jwtSecret)

	// Initialize handlers
	healthHandler = handlers.NewHealthHandler()
	userHandler = handlers.NewUserHandler(userService)
	authHandler = handlers.NewAuthHandler(authService)

	// Set Gin to TestMode
	gin.SetMode(gin.TestMode)
	router = gin.Default()

	// IMPORTANT: Removed global RateLimitMiddleware here.
	// It will be applied only in TestRateLimiting for isolation.

	// Setup routes
	router.GET("/health", healthHandler.HealthCheck)

	authRoutes := router.Group("/auth")
	{
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/refresh", authHandler.RefreshToken)
		authRoutes.POST("/logout", authHandler.Logout)
	}

	protected := router.Group("/")
	protected.Use(auth.JwtAuthMiddleware(jwtSecret))
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.GetString("userID")
			user, err := userService.GetUserByID(userID)
			if err != nil {
				utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve user profile")
				return
			}
			utils.SendSuccessResponse(c, http.StatusOK, "User profile", user)
		})

		// This route allows an authenticated user to update their own profile.
		// It should NOT be in the admin group.
		protected.PUT("/users/:id", userHandler.UpdateUser)

		usersGroup := protected.Group("/users")
		usersGroup.Use(auth.RequireRole("admin"))
		{
			usersGroup.POST("/", userHandler.CreateUser)
			usersGroup.GET("/", userHandler.GetAllUsers)
			usersGroup.GET("/:id", userHandler.GetUserByID)
			usersGroup.DELETE("/:id", userHandler.DeleteUser)
			// The PUT route for /users/:id is intentionally removed from here
			// because it's now handled by the `protected` group above, allowing
			// non-admin users to update their own profiles.
		}
	}

	// Run the tests
	exitCode := m.Run()

	// Teardown (optional, but good practice for external resources)
	// For database, we rely on `truncateTables` for test isolation.

	os.Exit(exitCode)
}

// truncateTables clears all data from relevant tables before each test.
func truncateTables(t *testing.T) {
	db, err := database.ConnectDB(config.DatabaseConfig{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		User:     os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		DBName:   os.Getenv("POSTGRES_DB"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	})
	require.NoError(t, err, "Failed to connect to DB for truncation")
	defer db.Close()

	_, err = db.Exec("TRUNCATE TABLE users RESTART IDENTITY CASCADE;")
	require.NoError(t, err, "Failed to truncate users table")
	_, err = db.Exec("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE;")
	require.NoError(t, err, "Failed to truncate refresh_tokens table")

	// Define the password string here.
	password := "adminpassword"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err, "Failed to hash password for admin user")

	_, err = db.Exec(`
		INSERT INTO users (id, username, email, password_hash, first_name, last_name, roles, created_at, updated_at)
		VALUES (
			'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
			'admin',
			'admin@example.com',
			$1,
			'', -- Add empty string for first_name
			'', -- Add empty string for last_name
			ARRAY['admin', 'user'],
			NOW(), NOW()
		) ON CONFLICT (username) DO NOTHING;`, hashedPassword)
	require.NoError(t, err, "Failed to insert default admin user")
}

// performRequest is a helper to make HTTP requests to the Gin router.
func performRequest(method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.Marshal(body)
	}

	req, _ := http.NewRequest(method, path, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req) // Use the global router
	return w
}

// registerUserHelper is a helper to register a user and return their ID.
func registerUserHelper(t *testing.T, username, password, email string) string {
	body := gin.H{
		"username": username,
		"password": password,
		"email":    email,
	}
	w := performRequest("POST", "/auth/register", body, nil)
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	data := response["data"].(map[string]interface{})
	return data["id"].(string)
}

// loginUserHelper is a helper to log in a user and return access and refresh tokens.
func loginUserHelper(t *testing.T, username, password string) (string, string) {
	body := gin.H{
		"username": username,
		"password": password,
	}
	w := performRequest("POST", "/auth/login", body, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	data := response["data"].(map[string]interface{})
	return data["accessToken"].(string), data["refreshToken"].(string)
}

// adminLoginHelper logs in the admin user and returns their access token.
func adminLoginHelper(t *testing.T) string {
	accessToken, _ := loginUserHelper(t, "admin", "adminpassword")
	return accessToken
}

// --- Test Cases ---

func TestHealthCheck(t *testing.T) {
	truncateTables(t) // Ensure clean state for this test

	w := performRequest("GET", "/health", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var response utils.JSONResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "success", response.Status)
	assert.Equal(t, "Service is healthy", response.Message)
}

func TestUserRegistration(t *testing.T) {
	truncateTables(t)

	// Test 1: Successful registration
	t.Run("Successful Registration", func(t *testing.T) {
		body := gin.H{
			"username": "testuser1",
			"password": "StrongPassword123!",
			"email":    "testuser1@example.com",
		}
		w := performRequest("POST", "/auth/register", body, nil)
		assert.Equal(t, http.StatusCreated, w.Code)

		var response utils.JSONResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "success", response.Status)
		assert.Equal(t, "User registered successfully", response.Message)
		data := response.Data.(map[string]interface{})
		assert.NotEmpty(t, data["id"])
		assert.Equal(t, "testuser1", data["username"])
		assert.Equal(t, "testuser1@example.com", data["email"])
		assert.Contains(t, data["roles"].([]interface{}), "user")
	})

	// Test 2: Duplicate username
	t.Run("Duplicate Username", func(t *testing.T) {
		body := gin.H{
			"username": "testuser1", // Already registered
			"password": "AnotherPassword1!",
			"email":    "another@example.com",
		}
		w := performRequest("POST", "/auth/register", body, nil)
		assert.Equal(t, http.StatusConflict, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Contains(t, response.Message, "username already exists")
	})

	// Test 3: Duplicate email
	t.Run("Duplicate Email", func(t *testing.T) {
		body := gin.H{
			"username": "testuser2",
			"password": "AnotherPassword1!",
			"email":    "testuser1@example.com", // Already registered
		}
		w := performRequest("POST", "/auth/register", body, nil)
		assert.Equal(t, http.StatusConflict, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Contains(t, response.Message, "email already exists")
	})

	// Test 4: Weak password
	t.Run("Weak Password", func(t *testing.T) {
		body := gin.H{
			"username": "weakpassuser",
			"password": "weak", // Too short/simple
			"email":    "weak@example.com",
		}
		w := performRequest("POST", "/auth/register", body, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Contains(t, response.Message, "Password is not strong enough")
	})

	// Test 5: Invalid email format
	t.Run("Invalid Email Format", func(t *testing.T) {
		body := gin.H{
			"username": "invalidemail",
			"password": "StrongPassword123!",
			"email":    "invalid-email",
		}
		w := performRequest("POST", "/auth/register", body, nil)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Contains(t, response.Message, "Invalid email format")
	})
}

func TestUserLogin(t *testing.T) {
	truncateTables(t)
	registerUserHelper(t, "loginuser", "LoginPass123!", "login@example.com")

	// Test 1: Successful login
	t.Run("Successful Login", func(t *testing.T) {
		accessToken, refreshToken := loginUserHelper(t, "loginuser", "LoginPass123!")
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	// Test 2: Invalid password
	t.Run("Invalid Password", func(t *testing.T) {
		body := gin.H{
			"username": "loginuser",
			"password": "WrongPassword!",
		}
		w := performRequest("POST", "/auth/login", body, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Equal(t, "invalid credentials", response.Message) // Changed from assert.Contains
	})

	// Test 3: User not found
	t.Run("User Not Found", func(t *testing.T) {
		body := gin.H{
			"username": "nonexistentuser",
			"password": "AnyPassword1!",
		}
		w := performRequest("POST", "/auth/login", body, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Equal(t, "invalid credentials", response.Message) // Changed from assert.Contains
	})
}

func TestGetUserProfile(t *testing.T) {
	truncateTables(t)
	userID := registerUserHelper(t, "profileuser", "ProfilePass123!", "profile@example.com")
	accessToken, _ := loginUserHelper(t, "profileuser", "ProfilePass123!")

	// Test 1: Get own profile with valid token
	t.Run("Get Own Profile with Valid Token", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer " + accessToken}
		w := performRequest("GET", "/profile", nil, headers)
		assert.Equal(t, http.StatusOK, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "success", response.Status)
		data := response.Data.(map[string]interface{})
		assert.Equal(t, userID, data["id"])
		assert.Equal(t, "profileuser", data["username"])
	})

	// Test 2: Get profile with invalid token
	t.Run("Get Profile with Invalid Token", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer invalidtoken"}
		w := performRequest("GET", "/profile", nil, headers)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	// Test 3: Get profile with no token
	t.Run("Get Profile with No Token", func(t *testing.T) {
		w := performRequest("GET", "/profile", nil, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestAdminUserManagement(t *testing.T) {
	truncateTables(t)
	adminAccessToken := adminLoginHelper(t)
	// --- DEBUGGING ADMIN TOKEN ---
	t.Logf("DEBUG: Admin access token received: %s", adminAccessToken)

	// Register a non-admin user for testing
	testUserID := registerUserHelper(t, "manageuser", "ManagePass123!", "manage@example.com")
	t.Logf("DEBUG: Registered non-admin user with ID: %s", testUserID)

	// Test 1: Admin gets all users
	t.Run("Admin Get All Users", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer " + adminAccessToken}
		w := performRequest("GET", "/users/?page=1&pageSize=10", nil, headers)
		assert.Equal(t, http.StatusOK, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "success", response.Status)
		data := response.Data.(map[string]interface{})
		users := data["users"].([]interface{})
		assert.GreaterOrEqual(t, len(users), 2)         // admin + manageuser
		assert.Equal(t, float64(2), data["totalCount"]) // Ensure total count is correct
	})

	// Test 2: Admin gets a specific user by ID
	t.Run("Admin Get User By ID", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer " + adminAccessToken}
		w := performRequest("GET", fmt.Sprintf("/users/%s", testUserID), nil, headers)
		assert.Equal(t, http.StatusOK, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "success", response.Status)
		data := response.Data.(map[string]interface{})
		assert.Equal(t, testUserID, data["id"])
		assert.Equal(t, "manageuser", data["username"])
	})

	// Test 3: Admin updates a user
	t.Run("Admin Update User", func(t *testing.T) {
		if adminAccessToken == "" {
			t.Fatal("Admin access token is empty, cannot run test")
		}

		headers := map[string]string{"Authorization": "Bearer " + adminAccessToken}
		updateBody := gin.H{
			"firstName": "Updated",
			"lastName":  "User",
			"address": gin.H{
				"street":  "456 Oak Ave",
				"city":    "Newtown",
				"state":   "NY",
				"zipCode": "10001",
				"country": "USA",
			},
		}

		// Admin should be able to update any user (including testUserID)
		t.Logf("DEBUG: Admin PUT request to /users/%s with token %s", testUserID, adminAccessToken)

		w := performRequest("PUT", fmt.Sprintf("/users/%s", testUserID), updateBody, headers)

		// Add debugging for admin update failure
		if w.Code != http.StatusOK {
			t.Logf("Admin update failed. Expected 200, got %d. Response body: %s", w.Code, w.Body.String())
		}
		assert.Equal(t, http.StatusOK, w.Code)

		if w.Code == http.StatusOK {
			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Equal(t, "success", response["status"])

			data := response["data"].(map[string]interface{})
			assert.Equal(t, "Updated", data["firstName"])
			assert.Equal(t, "User", data["lastName"])

			address := data["address"].(map[string]interface{})
			assert.Equal(t, "456 Oak Ave", address["street"])
		}
	})

	// Test 4: Non-admin user tries to access /users (should be forbidden)
	t.Run("Non-Admin Forbidden Access to All Users", func(t *testing.T) {
		userAccessToken, _ := loginUserHelper(t, "manageuser", "ManagePass123!")
		headers := map[string]string{"Authorization": "Bearer " + userAccessToken}
		w := performRequest("GET", "/users/", nil, headers)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// Test 5: Non-admin user tries to update another user (should be forbidden)
	t.Run("Non-Admin Forbidden Update Other User", func(t *testing.T) {
		userAccessToken, _ := loginUserHelper(t, "manageuser", "ManagePass123!")
		headers := map[string]string{"Authorization": "Bearer " + userAccessToken}
		updateBody := gin.H{"firstName": "Attempted"}
		w := performRequest("PUT", fmt.Sprintf("/users/%s", "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"), updateBody, headers)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	// Test 6: Non-admin user tries to update their own profile (should be allowed)
	t.Run("Non-Admin Update Own Profile", func(t *testing.T) {
		userAccessToken, _ := loginUserHelper(t, "manageuser", "ManagePass123!")

		// testUserID IS the correct user ID for "manageuser" since we registered it above
		// The issue is likely in the route configuration, not the test logic
		manageUserID := testUserID

		headers := map[string]string{"Authorization": "Bearer " + userAccessToken}
		updateBody := gin.H{"firstName": "SelfUpdated"}

		t.Logf("DEBUG: Non-admin PUT request to /users/%s with token %s", manageUserID, userAccessToken)

		w := performRequest("PUT", fmt.Sprintf("/users/%s", manageUserID), updateBody, headers)

		// Add detailed debugging for self-update failure
		if w.Code != http.StatusOK {
			t.Logf("Self-update failed. Expected 200, got %d. Response body: %s", w.Code, w.Body.String())

			// Let's also verify what's in the JWT token by decoding it
			t.Logf("DEBUG: Attempting to decode JWT token to verify user ID")
			// You might want to add JWT parsing here to verify the token contains the right user ID
		}

		assert.Equal(t, http.StatusOK, w.Code)

		// Only proceed if the request was successful
		if w.Code != http.StatusOK {
			return
		}

		// Only parse response if request was successful
		var response utils.JSONResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		if err != nil {
			t.Logf("Failed to unmarshal response: %v. Body: %s", err, w.Body.String())
			require.NoError(t, err)
			return
		}

		assert.Equal(t, "success", response.Status)

		// Add nil check for response.Data
		if response.Data == nil {
			t.Log("Response data is nil")
			assert.NotNil(t, response.Data)
			return
		}

		data, ok := response.Data.(map[string]interface{})
		if !ok {
			t.Logf("Response data is not a map, it's: %T", response.Data)
			assert.True(t, ok)
			return
		}

		assert.Equal(t, "SelfUpdated", data["firstName"])
	})

	// Test 7: Admin deletes a user
	t.Run("Admin Delete User", func(t *testing.T) {
		headers := map[string]string{"Authorization": "Bearer " + adminAccessToken}
		w := performRequest("DELETE", fmt.Sprintf("/users/%s", testUserID), nil, headers)
		assert.Equal(t, http.StatusOK, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "success", response.Status)
		assert.Equal(t, "User deleted successfully", response.Message)

		// Verify deletion
		w = performRequest("GET", fmt.Sprintf("/users/%s", testUserID), nil, headers)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestRefreshToken(t *testing.T) {
	truncateTables(t)
	registerUserHelper(t, "refreshuser", "RefreshPass123!", "refresh@example.com")
	_, refreshToken := loginUserHelper(t, "refreshuser", "RefreshPass123!")

	// Test 1: Successful token refresh
	t.Run("Successful Token Refresh", func(t *testing.T) {
		body := gin.H{"refreshToken": refreshToken}
		w := performRequest("POST", "/auth/refresh", body, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "success", response.Status)
		data := response.Data.(map[string]interface{})
		newAccessToken := data["accessToken"].(string)
		newRefreshToken := data["refreshToken"].(string)
		assert.NotEmpty(t, newAccessToken)
		assert.NotEmpty(t, newRefreshToken)

		// Verify old refresh token is revoked
		oldToken, err := tokenRepo.GetToken(refreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, oldToken)
		assert.True(t, oldToken.IsRevoked)

		// Try to use the new access token
		headers := map[string]string{"Authorization": "Bearer " + newAccessToken}
		w = performRequest("GET", "/profile", nil, headers)
		assert.Equal(t, http.StatusOK, w.Code) // Should work with new token
	})

	// Test 2: Use revoked refresh token
	t.Run("Use Revoked Refresh Token", func(t *testing.T) {
		// The refreshToken from the previous test is now revoked
		body := gin.H{"refreshToken": refreshToken}
		w := performRequest("POST", "/auth/refresh", body, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Contains(t, response.Message, "invalid or expired refresh token")
	})

	// Test 3: Invalid refresh token
	t.Run("Invalid Refresh Token", func(t *testing.T) {
		body := gin.H{"refreshToken": "invalid-uuid-token"}
		w := performRequest("POST", "/auth/refresh", body, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Contains(t, response.Message, "invalid or expired refresh token")
	})
}

func TestLogout(t *testing.T) {
	truncateTables(t)
	registerUserHelper(t, "logoutuser", "LogoutPass123!", "logout@example.com")
	_, refreshToken := loginUserHelper(t, "logoutuser", "LogoutPass123!")

	// Test 1: Successful logout
	t.Run("Successful Logout", func(t *testing.T) {
		body := gin.H{"refreshToken": refreshToken}
		w := performRequest("POST", "/auth/logout", body, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "success", response.Status)
		assert.Equal(t, "Logged out successfully", response.Message)

		// Verify token is revoked in DB
		storedToken, err := tokenRepo.GetToken(refreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, storedToken)
		assert.True(t, storedToken.IsRevoked)
	})

	// Test 2: Logout with already revoked token
	t.Run("Logout with Already Revoked Token", func(t *testing.T) {
		// Use the same refresh token again (already revoked from previous test)
		logoutBody := gin.H{"refreshToken": refreshToken}
		w := performRequest("POST", "/auth/logout", logoutBody, nil)

		// Logout should be idempotent - return success even if token already revoked
		assert.Equal(t, http.StatusOK, w.Code)

		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "success", response.Status)
		assert.Equal(t, "Logged out successfully", response.Message)
	})

	// Test 3: Logout with invalid token - should return error (strict behavior)
	t.Run("Logout with Invalid Token", func(t *testing.T) {
		body := gin.H{"refreshToken": "non-existent-token"}
		w := performRequest("POST", "/auth/logout", body, nil)

		// Expecting error for invalid tokens (strict behavior)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		var response utils.JSONResponse
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "error", response.Status)
		assert.Equal(t, "Failed to logout", response.Message)
	})
}

func TestRateLimiting(t *testing.T) {
	// This test needs its own router instance with the rate limit middleware applied.
	// The global 'router' is now free of global rate limiting.
	rateLimitRouter := gin.Default()
	rateLimitRouter.Use(utils.RateLimitMiddleware())
	rateLimitRouter.GET("/health", healthHandler.HealthCheck) // Add a route to test

	// Helper function for this specific test
	performRateLimitRequest := func(method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
		var reqBody []byte
		if body != nil {
			reqBody, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, path, bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		rateLimitRouter.ServeHTTP(w, req)
		return w
	}

	// First 5 requests should pass
	for i := 0; i < utils.RateLimitMaxRequests; i++ { // Use the exported constant
		w := performRateLimitRequest("GET", "/health", nil, nil)
		assert.Equal(t, http.StatusOK, w.Code, fmt.Sprintf("Request %d should pass", i+1))
	}

	// (Rate limit interval is 1 minute, max requests is 5)
	// 6th request should be rate-limited
	w := performRateLimitRequest("GET", "/health", nil, nil)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "6th request should be rate-limited")
	var response utils.JSONResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "error", response.Status)
	assert.Contains(t, response.Message, "Too many requests")

	// Wait for the rate limit interval to pass (1 minute + a small buffer)
	t.Log("Waiting for rate limit to reset (1 minute)...")
	time.Sleep(utils.RateLimitInterval + 5*time.Second) // Corrected: use utils.RateLimitInterval

	// After reset, request should pass again
	w = performRateLimitRequest("GET", "/health", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code, "Request after reset should pass")
}
