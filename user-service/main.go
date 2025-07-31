package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

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

// Claims defines the JWT claims structure
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
	jwt.RegisteredClaims
}

// UserRepository defines the interface for user data operations
type UserRepository interface {
	GetAllUsers() ([]UserResponse, error)
	GetUserByID(id string) (*UserResponse, error)
	GetUserByUsername(username string) (*User, error)
	CreateUser(user User) (*UserResponse, error)
	// New method for deleting a user
	DeleteUser(id string) error
}

// PostgresUserRepository implements UserRepository for PostgreSQL
type PostgresUserRepository struct {
	db *sqlx.DB
}

// NewPostgresUserRepository creates a new instance of PostgresUserRepository
func NewPostgresUserRepository(db *sqlx.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

// GetAllUsers retrieves all users from the database
func (repo *PostgresUserRepository) GetAllUsers() ([]UserResponse, error) {
	var users []User
	err := repo.db.Select(&users, `
		SELECT id, username, email, password_hash, first_name, last_name,
			   address_street, address_city, address_state, address_zip_code, address_country, roles
		FROM users`)
	if err != nil {
		return nil, fmt.Errorf("error querying users: %w", err)
	}

	var userResponses []UserResponse
	for _, u := range users {
		userResponses = append(userResponses, convertToUserResponse(u))
	}
	return userResponses, nil
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

	// Initialize the user repository
	userRepo := NewPostgresUserRepository(db)

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

	// Public route for user creation
	router.POST("/users", func(c *gin.Context) {
		var newUser User
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if newUser.PasswordHash == "" {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Password is required"})
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

	// New login endpoint
	router.POST("/login", func(c *gin.Context) {
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

		// Generate JWT
		expirationTime := time.Now().Add(24 * time.Hour) // Token valid for 24 hours
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
		tokenString, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			log.Printf("Error signing token: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Apply JWT authentication middleware to protected routes
	protected := router.Group("/")
	protected.Use(jwtAuthMiddleware([]byte(jwtSecret)))
	{
		// GET /users: Only accessible by "admin" role
		protected.GET("/users", requireRole("admin"), func(c *gin.Context) {
			users, err := userRepo.GetAllUsers()
			if err != nil {
				log.Printf("Error getting all users: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve users"})
				return
			}
			c.JSON(http.StatusOK, users)
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
