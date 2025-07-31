package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// --- User and Data Models ---

// Address represents a user's address details
type Address struct {
	Street  string `json:"street" db:"address_street"`
	City    string `json:"city" db:"address_city"`
	State   string `json:"state" db:"address_state"`
	ZipCode string `json:"zipCode" db:"address_zip_code"`
	Country string `json:"country" db:"address_country"`
}

// User represents a user model for the e-commerce platform
type User struct {
	ID           string         `json:"id" db:"id"`
	Username     string         `json:"username" binding:"required" db:"username"`
	Email        string         `json:"email" binding:"required,email" db:"email"`
	PasswordHash string         `json:"passwordHash" binding:"required" db:"password_hash"`
	FirstName    string         `json:"firstName,omitempty" db:"first_name"`
	LastName     string         `json:"lastName,omitempty" db:"last_name"`
	Address      *Address       `json:"address,omitempty"`
	Roles        pq.StringArray `json:"roles,omitempty" db:"roles"`
	// Fields for Address struct, directly mapped for scanning with sqlx
	AddressStreet  sql.NullString `json:"-" db:"address_street"`
	AddressCity    sql.NullString `json:"-" db:"address_city"`
	AddressState   sql.NullString `json:"-" db:"address_state"`
	AddressZipCode sql.NullString `json:"-" db:"address_zip_code"`
	AddressCountry sql.NullString `json:"-" db:"address_country"`
}

// UserUpdate represents a user model for updating user details
type UserUpdate struct {
	Username  *string  `json:"username,omitempty"`
	Email     *string  `json:"email,omitempty" binding:"omitempty,email"`
	FirstName *string  `json:"firstName,omitempty"`
	LastName  *string  `json:"lastName,omitempty"`
	Address   *Address `json:"address,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

// UserResponse is a simplified struct for API responses, omitting sensitive fields
type UserResponse struct {
	ID        string   `json:"id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FirstName string   `json:"firstName,omitempty"`
	LastName  string   `json:"lastName,omitempty"`
	Address   *Address `json:"address,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

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

// Claims defines the JWT claims structure
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// RefreshToken represents a refresh token stored in the database
type RefreshToken struct {
	Token     string    `db:"token"`
	UserID    string    `db:"user_id"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
	IsRevoked bool      `db:"is_revoked"`
}

// --- Repository Interfaces ---

// UserRepository defines the interface for user data operations
type UserRepository interface {
	GetAllUsers(limit, offset int, sortBy, sortOrder, roleFilter string) ([]UserResponse, error)
	GetUserByID(id string) (*UserResponse, error)
	GetUserByUsername(username string) (*User, error)
	CreateUser(user User) (*UserResponse, error)
	UpdateUser(id string, update UserUpdate) (*UserResponse, error)
	DeleteUser(id string) error
	GetUsersCount(roleFilter string) (int, error)
	CheckUsernameExists(username string, excludeUserID string) (bool, error)
	CheckEmailExists(email string, excludeUserID string) (bool, error)
}

// RefreshTokenRepository defines the interface for refresh token data operations
type RefreshTokenRepository interface {
	CreateToken(token RefreshToken) error
	GetToken(tokenString string) (*RefreshToken, error)
	RevokeToken(tokenString string) error
	RevokeAllUserTokens(userID string) error
}

// --- PostgreSQL Repository Implementations ---

// PostgresUserRepository implements UserRepository for PostgreSQL
type PostgresUserRepository struct {
	db *sqlx.DB
}

// NewPostgresUserRepository creates a new instance of PostgresUserRepository
func NewPostgresUserRepository(db *sqlx.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

// GetAllUsers retrieves all users from the database with pagination, filtering, and sorting
func (repo *PostgresUserRepository) GetAllUsers(limit, offset int, sortBy, sortOrder, roleFilter string) ([]UserResponse, error) {
	var users []User
	queryBuilder := `
        SELECT id, username, email, first_name, last_name,
               address_street, address_city, address_state, address_zip_code, address_country, roles
        FROM users
    `
	args := []interface{}{}
	argCounter := 1

	// Add filtering by role
	if roleFilter != "" {
		queryBuilder += fmt.Sprintf(" WHERE $%d = ANY(roles)", argCounter)
		args = append(args, roleFilter)
		argCounter++
	}

	// Add sorting
	if sortBy != "" {
		if sortOrder == "desc" {
			queryBuilder += fmt.Sprintf(" ORDER BY %s DESC", sortBy)
		} else {
			queryBuilder += fmt.Sprintf(" ORDER BY %s ASC", sortBy)
		}
	} else {
		// Default sort order
		queryBuilder += " ORDER BY username ASC"
	}

	// Add pagination
	queryBuilder += fmt.Sprintf(" OFFSET $%d LIMIT $%d", argCounter, argCounter+1)
	args = append(args, offset, limit)

	err := repo.db.Select(&users, queryBuilder, args...)
	if err != nil {
		return nil, fmt.Errorf("error querying users: %w", err)
	}

	var userResponses []UserResponse
	for _, u := range users {
		userResponses = append(userResponses, convertToUserResponse(u))
	}
	return userResponses, nil
}

// GetUsersCount returns the total number of users, optionally filtered by role
func (repo *PostgresUserRepository) GetUsersCount(roleFilter string) (int, error) {
	var count int
	queryBuilder := "SELECT COUNT(*) FROM users"
	args := []interface{}{}
	if roleFilter != "" {
		queryBuilder += " WHERE $1 = ANY(roles)"
		args = append(args, roleFilter)
	}

	err := repo.db.Get(&count, queryBuilder, args...)
	if err != nil {
		return 0, fmt.Errorf("error counting users: %w", err)
	}
	return count, nil
}

// GetUserByID retrieves a user by their ID from the database
func (repo *PostgresUserRepository) GetUserByID(id string) (*UserResponse, error) {
	var u User
	err := repo.db.Get(&u, `
        SELECT id, username, email, password_hash, first_name, last_name,
               address_street, address_city, address_state, address_zip_code, address_country, roles
        FROM users WHERE id = $1`, id)
	if err == sql.ErrNoRows {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("error querying user by ID: %w", err)
	}

	userResp := convertToUserResponse(u)
	return &userResp, nil
}

// GetUserByUsername retrieves a user by their username (used for login)
func (repo *PostgresUserRepository) GetUserByUsername(username string) (*User, error) {
	var u User
	err := repo.db.Get(&u, `
        SELECT id, username, email, password_hash, first_name, last_name,
               address_street, address_city, address_state, address_zip_code, address_country, roles
        FROM users WHERE username = $1`, username)
	if err == sql.ErrNoRows {
		return nil, nil // User not found
	}
	if err != nil {
		return nil, fmt.Errorf("error querying user by username: %w", err)
	}
	return &u, nil
}

// CreateUser inserts a new user into the database
func (repo *PostgresUserRepository) CreateUser(user User) (*UserResponse, error) {
	if user.Username == "" || user.Email == "" {
		return nil, errors.New("username and email are required")
	}

	user.ID = uuid.New().String()

	var street, city, state, zipCode, country sql.NullString
	if user.Address != nil {
		street = sql.NullString{String: user.Address.Street, Valid: user.Address.Street != ""}
		city = sql.NullString{String: user.Address.City, Valid: user.Address.City != ""}
		state = sql.NullString{String: user.Address.State, Valid: user.Address.State != ""}
		zipCode = sql.NullString{String: user.Address.ZipCode, Valid: user.Address.ZipCode != ""}
		country = sql.NullString{String: user.Address.Country, Valid: user.Address.Country != ""}
	}

	_, err := repo.db.Exec(`
        INSERT INTO users (id, username, email, password_hash, first_name, last_name,
                          address_street, address_city, address_state, address_zip_code, address_country, roles)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		user.ID, user.Username, user.Email, user.PasswordHash,
		user.FirstName, user.LastName, street, city, state, zipCode, country, pq.Array(user.Roles))
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code.Name() == "unique_violation" {
			return nil, fmt.Errorf("user with this username or email already exists: %w", err)
		}
		return nil, fmt.Errorf("error creating user: %w", err)
	}

	userResp := convertToUserResponse(user)
	return &userResp, nil
}

// UpdateUser updates an existing user's details
func (repo *PostgresUserRepository) UpdateUser(id string, update UserUpdate) (*UserResponse, error) {
	var user User
	err := repo.db.Get(&user, "SELECT * FROM users WHERE id = $1", id)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("error retrieving user for update: %w", err)
	}

	// Build the update query dynamically
	updates := []string{}
	args := []interface{}{}
	argCounter := 1

	if update.Username != nil {
		updates = append(updates, fmt.Sprintf("username = $%d", argCounter))
		args = append(args, *update.Username)
		argCounter++
	}
	if update.Email != nil {
		updates = append(updates, fmt.Sprintf("email = $%d", argCounter))
		args = append(args, *update.Email)
		argCounter++
	}
	if update.FirstName != nil {
		updates = append(updates, fmt.Sprintf("first_name = $%d", argCounter))
		args = append(args, *update.FirstName)
		argCounter++
	}
	if update.LastName != nil {
		updates = append(updates, fmt.Sprintf("last_name = $%d", argCounter))
		args = append(args, *update.LastName)
		argCounter++
	}
	if update.Roles != nil {
		updates = append(updates, fmt.Sprintf("roles = $%d", argCounter))
		args = append(args, pq.Array(update.Roles))
		argCounter++
	}

	// Handle address fields
	if update.Address != nil {
		updates = append(updates, fmt.Sprintf("address_street = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.Street, Valid: update.Address.Street != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_city = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.City, Valid: update.Address.City != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_state = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.State, Valid: update.Address.State != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_zip_code = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.ZipCode, Valid: update.Address.ZipCode != ""})
		argCounter++

		updates = append(updates, fmt.Sprintf("address_country = $%d", argCounter))
		args = append(args, sql.NullString{String: update.Address.Country, Valid: update.Address.Country != ""})
		argCounter++
	}

	if len(updates) == 0 {
		return nil, errors.New("no fields to update")
	}

	updateQuery := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d RETURNING *", strings.Join(updates, ", "), argCounter)
	args = append(args, id)

	var updatedUser User
	err = repo.db.Get(&updatedUser, updateQuery, args...)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code.Name() == "unique_violation" {
			return nil, fmt.Errorf("a user with this username or email already exists")
		}
		return nil, fmt.Errorf("error updating user: %w", err)
	}

	resp := convertToUserResponse(updatedUser)
	return &resp, nil
}

// DeleteUser removes a user from the database
func (repo *PostgresUserRepository) DeleteUser(id string) error {
	result, err := repo.db.Exec(`DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("error deleting user: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("error checking rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return errors.New("user not found")
	}
	return nil
}

// CheckUsernameExists checks for a duplicate username, excluding a specific user
func (repo *PostgresUserRepository) CheckUsernameExists(username string, excludeUserID string) (bool, error) {
	var count int
	err := repo.db.Get(&count, "SELECT COUNT(*) FROM users WHERE username = $1 AND id != $2", username, excludeUserID)
	if err != nil {
		return false, fmt.Errorf("error checking username existence: %w", err)
	}
	return count > 0, nil
}

// CheckEmailExists checks for a duplicate email, excluding a specific user
func (repo *PostgresUserRepository) CheckEmailExists(email string, excludeUserID string) (bool, error) {
	var count int
	err := repo.db.Get(&count, "SELECT COUNT(*) FROM users WHERE email = $1 AND id != $2", email, excludeUserID)
	if err != nil {
		return false, fmt.Errorf("error checking email existence: %w", err)
	}
	return count > 0, nil
}

// PostgresRefreshTokenRepository implements RefreshTokenRepository for PostgreSQL
type PostgresRefreshTokenRepository struct {
	db *sqlx.DB
}

// NewPostgresRefreshTokenRepository creates a new instance of PostgresRefreshTokenRepository
func NewPostgresRefreshTokenRepository(db *sqlx.DB) *PostgresRefreshTokenRepository {
	return &PostgresRefreshTokenRepository{db: db}
}

// CreateToken inserts a new refresh token into the database
func (repo *PostgresRefreshTokenRepository) CreateToken(token RefreshToken) error {
	_, err := repo.db.Exec(`
        INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)`,
		token.Token, token.UserID, token.ExpiresAt)
	if err != nil {
		return fmt.Errorf("error creating refresh token: %w", err)
	}
	return nil
}

// GetToken retrieves a refresh token from the database
func (repo *PostgresRefreshTokenRepository) GetToken(tokenString string) (*RefreshToken, error) {
	var rt RefreshToken
	err := repo.db.Get(&rt, `
        SELECT token, user_id, expires_at, is_revoked FROM refresh_tokens WHERE token = $1`, tokenString)
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
	_, err := repo.db.Exec(`UPDATE refresh_tokens SET is_revoked = TRUE WHERE token = $1`, tokenString)
	if err != nil {
		return fmt.Errorf("error revoking refresh token: %w", err)
	}
	return nil
}

// RevokeAllUserTokens revokes all tokens for a specific user
func (repo *PostgresRefreshTokenRepository) RevokeAllUserTokens(userID string) error {
	_, err := repo.db.Exec(`UPDATE refresh_tokens SET is_revoked = TRUE WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("error revoking all user refresh tokens: %w", err)
	}
	return nil
}

// --- Utility Functions ---

// convertToUserResponse converts a User to UserResponse, omitting sensitive fields
func convertToUserResponse(user User) UserResponse {
	resp := UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Roles:     []string(user.Roles), // Convert pq.StringArray to []string
	}

	if user.AddressStreet.Valid || user.AddressCity.Valid || user.AddressState.Valid || user.AddressZipCode.Valid || user.AddressCountry.Valid {
		resp.Address = &Address{
			Street:  user.AddressStreet.String,
			City:    user.AddressCity.String,
			State:   user.AddressState.String,
			ZipCode: user.AddressZipCode.String,
			Country: user.AddressCountry.String,
		}
	}
	return resp
}

// getDBCredentials now directly reads from environment variables
func getDBCredentials() (string, string, error) {
	dbUser := os.Getenv("POSTGRES_USER")
	if dbUser == "" {
		return "", "", errors.New("POSTGRES_USER environment variable is required")
	}

	dbPassword := os.Getenv("POSTGRES_PASSWORD")
	if dbPassword == "" {
		return "", "", errors.New("POSTGRES_PASSWORD environment variable is required")
	}

	return dbUser, dbPassword, nil
}

// connectDB attempts to connect to the database with retries
func connectDB(dbURL string) (*sqlx.DB, error) {
	var db *sqlx.DB
	var err error
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		db, err = sqlx.Connect("postgres", dbURL)
		if err == nil {
			log.Println("Successfully connected to database")
			return db, nil
		}
		log.Printf("Failed to connect to database (attempt %d/%d): %v", i+1, maxRetries, err)
		time.Sleep(5 * time.Second) // Wait before retrying
	}
	return nil, fmt.Errorf("failed to connect to database after %d retries: %w", maxRetries, err)
}

// generateAccessToken generates a new JWT access token
func generateAccessToken(user *User, jwtSecret []byte) (string, error) {
	// Access token with a short lifespan (e.g., 15 minutes)
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Roles:    user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// generateRefreshToken generates a new refresh token and stores it in the database
func generateRefreshToken(user *User, repo RefreshTokenRepository) (string, error) {
	// Refresh token with a long lifespan (e.g., 7 days)
	tokenString := uuid.New().String()
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	refreshToken := RefreshToken{
		Token:     tokenString,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	}

	err := repo.CreateToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to save refresh token: %w", err)
	}

	return tokenString, nil
}

// --- Middleware ---

// jwtAuthMiddleware validates JWTs from the Authorization header
func jwtAuthMiddleware(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be in format 'Bearer <token>'"})
			return
		}

		tokenString := parts[1]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		if err != nil {
			log.Printf("JWT parsing error: %v", err)
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			}
			return
		}

		if !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Store claims in context for subsequent handlers
		c.Set("userID", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)
		c.Next() // Continue to the next handler
	}
}

// hasRole is a helper function to check if the user has a specific role
func hasRole(c *gin.Context, requiredRole string) bool {
	roles, exists := c.Get("roles")
	if !exists {
		return false
	}
	userRoles, ok := roles.([]string)
	if !ok {
		return false
	}
	for _, role := range userRoles {
		if role == requiredRole {
			return true
		}
	}
	return false
}

// RBAC middleware to check for a specific role
func requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !hasRole(c, role) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "You do not have the required permissions"})
			return
		}
		c.Next()
	}
}

// Create a simple in-memory map for rate limiting
var requestCounts = make(map[string]int)
var lastRequestTimes = make(map[string]time.Time)
var rateLimitInterval = time.Minute
var rateLimitMaxRequests = 5

// RateLimiting middleware protects an endpoint from abuse
func rateLimitMiddleware(c *gin.Context) {
	clientIP := c.ClientIP()
	currentTime := time.Now()

	// Reset the counter if the interval has passed
	if currentTime.Sub(lastRequestTimes[clientIP]) > rateLimitInterval {
		requestCounts[clientIP] = 0
		lastRequestTimes[clientIP] = currentTime
	}

	// Increment the counter and check if it's over the limit
	requestCounts[clientIP]++
	if requestCounts[clientIP] > rateLimitMaxRequests {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests. Please try again later."})
		return
	}

	c.Next()
}

// --- Main application logic ---

func main() {
	// Get database credentials
	dbUser, dbPassword, err := getDBCredentials()
	if err != nil {
		log.Fatalf("Failed to get database credentials: %v", err)
	}

	// Get other database connection parameters
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "postgres" // Default to service name in Docker Compose/Kubernetes
	}

	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "5432" // Default PostgreSQL port
	}

	dbName := os.Getenv("POSTGRES_DB")
	if dbName == "" {
		dbName = "user_service" // Default database name
	}

	// Get JWT Secret Key from environment variable
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET_KEY environment variable is required")
	}

	// Construct database URL
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	// Connect to PostgreSQL with retries
	db, err := connectDB(dbURL)
	if err != nil {
		log.Fatalf("Failed to establish database connection: %v", err)
	}
	defer db.Close()

	// Initialize the user and refresh token repositories
	userRepo := NewPostgresUserRepository(db)
	refreshTokenRepo := NewPostgresRefreshTokenRepository(db)

	router := gin.Default()

	// Add health and readiness endpoints for Kubernetes probes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "UP"})
	})

	router.GET("/ready", func(c *gin.Context) {
		if err := db.Ping(); err != nil {
			log.Printf("Readiness probe failed: database connection error: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "DOWN", "reason": "database not ready"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "READY"})
	})

	// Public route for user creation with rate limiting
	router.POST("/users", rateLimitMiddleware, func(c *gin.Context) {
		var newUser User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Custom validation for password strength
		if len(newUser.PasswordHash) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Password must be at least 8 characters long"})
			return
		}
		// Custom validation for unique username/email
		if exists, _ := userRepo.CheckUsernameExists(newUser.Username, ""); exists {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Username already exists"})
			return
		}
		if exists, _ := userRepo.CheckEmailExists(newUser.Email, ""); exists {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Email already exists"})
			return
		}

		// A newly created user should have a default role, e.g., "customer"
		if len(newUser.Roles) == 0 {
			newUser.Roles = []string{"customer"}
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.PasswordHash), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		newUser.PasswordHash = string(hashedPassword)

		userResp, err := userRepo.CreateUser(newUser)
		if err != nil {
			log.Printf("Error creating user: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, userResp)
	})

	// New login endpoint with refresh token
	router.POST("/login", rateLimitMiddleware, func(c *gin.Context) {
		var req LoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		user, err := userRepo.GetUserByUsername(req.Username)
		if err != nil {
			log.Printf("Error retrieving user for login: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Compare the provided password with the hashed password
		err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Generate Access Token
		accessToken, err := generateAccessToken(user, []byte(jwtSecret))
		if err != nil {
			log.Printf("Error generating access token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		// Generate and store Refresh Token
		refreshToken, err := generateRefreshToken(user, refreshTokenRepo)
		if err != nil {
			log.Printf("Error generating refresh token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
			return
		}

		c.JSON(http.StatusOK, TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		})
	})

	// New endpoint to refresh an access token
	router.POST("/refresh", rateLimitMiddleware, func(c *gin.Context) {
		var req RefreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token is required"})
			return
		}

		// Look up the refresh token in the database
		rt, err := refreshTokenRepo.GetToken(req.RefreshToken)
		if err != nil {
			log.Printf("Error retrieving refresh token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}
		if rt == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			return
		}

		// Check if the token is revoked or expired
		if rt.IsRevoked || rt.ExpiresAt.Before(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token is expired or revoked"})
			return
		}

		// Get the user associated with the token
		userResp, err := userRepo.GetUserByID(rt.UserID)
		if err != nil || userResp == nil {
			log.Printf("User not found for refresh token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token (user not found)"})
			return
		}

		// We need the full User struct to get the password hash
		user, err := userRepo.GetUserByUsername(userResp.Username)
		if err != nil || user == nil {
			log.Printf("User not found for refresh token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token (user not found)"})
			return
		}

		// Generate a new access token
		newAccessToken, err := generateAccessToken(user, []byte(jwtSecret))
		if err != nil {
			log.Printf("Error generating new access token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new access token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"accessToken": newAccessToken})
	})

	// Apply JWT authentication middleware to protected routes
	protected := router.Group("/")
	protected.Use(jwtAuthMiddleware([]byte(jwtSecret)))
	{
		// GET /users: Only accessible by "admin" role
		protected.GET("/users", requireRole("admin"), func(c *gin.Context) {
			// Extract query parameters with default values
			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
			sortBy := c.DefaultQuery("sortBy", "username")
			roleFilter := c.DefaultQuery("role", "")
			sortOrder := c.DefaultQuery("sortOrder", "asc")

			if page <= 0 {
				page = 1
			}
			if limit <= 0 {
				limit = 10
			}

			// Validate sort columns
			validSortColumns := map[string]bool{
				"username":  true,
				"email":     true,
				"firstName": true,
				"lastName":  true,
			}
			if !validSortColumns[sortBy] {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sort column"})
				return
			}
			if sortOrder != "asc" && sortOrder != "desc" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sort order. Must be 'asc' or 'desc'"})
				return
			}

			offset := (page - 1) * limit
			users, err := userRepo.GetAllUsers(limit, offset, sortBy, sortOrder, roleFilter)
			if err != nil {
				log.Printf("Error getting all users: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
				return
			}

			totalUsers, err := userRepo.GetUsersCount(roleFilter)
			if err != nil {
				log.Printf("Error getting user count: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user count"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"users":      users,
				"total":      totalUsers,
				"page":       page,
				"limit":      limit,
				"totalPages": (totalUsers + limit - 1) / limit,
			})
		})

		// GET /users/:id: Accessible by "admin" or the user themselves
		protected.GET("/users/:id", func(c *gin.Context) {
			id := c.Param("id")
			// Check if the authenticated user is the one being requested
			authenticatedUserID, _ := c.Get("userID")
			if authenticatedUserID != id && !hasRole(c, "admin") {
				c.JSON(http.StatusForbidden, gin.H{"error": "You can only view your own user profile unless you are an admin"})
				return
			}

			user, err := userRepo.GetUserByID(id)
			if err != nil {
				log.Printf("Error getting user by ID %s: %v", id, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
				return
			}
			if user == nil {
				c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
				return
			}
			c.JSON(http.StatusOK, user)
		})

		// PUT /users/:id: Accessible by "admin" or the user themselves
		protected.PUT("/users/:id", func(c *gin.Context) {
			id := c.Param("id")
			authenticatedUserID, _ := c.Get("userID")

			// Only allow admins to update other users. Regular users can only update their own profile.
			if authenticatedUserID != id && !hasRole(c, "admin") {
				c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to update this user"})
				return
			}

			var update UserUpdate
			if err := c.ShouldBindJSON(&update); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// Prevent regular users from changing their roles
			if !hasRole(c, "admin") && update.Roles != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to change your roles"})
				return
			}

			// Validate for unique username/email before updating
			if update.Username != nil {
				if exists, _ := userRepo.CheckUsernameExists(*update.Username, id); exists {
					c.JSON(http.StatusBadRequest, gin.H{"message": "Username already exists"})
					return
				}
			}
			if update.Email != nil {
				if exists, _ := userRepo.CheckEmailExists(*update.Email, id); exists {
					c.JSON(http.StatusBadRequest, gin.H{"message": "Email already exists"})
					return
				}
			}

			userResp, err := userRepo.UpdateUser(id, update)
			if err != nil {
				if err.Error() == "user not found" {
					c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
					return
				}
				log.Printf("Error updating user %s: %v", id, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
				return
			}
			c.JSON(http.StatusOK, userResp)
		})

		// DELETE /users/:id: Only accessible by "admin" role
		protected.DELETE("/users/:id", requireRole("admin"), func(c *gin.Context) {
			id := c.Param("id")

			err := userRepo.DeleteUser(id)
			if err != nil {
				if err.Error() == "user not found" {
					c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
					return
				}
				log.Printf("Error deleting user by ID %s: %v", id, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
		})
	}

	// Run the server
	port := "8080"
	log.Printf("User Service starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
