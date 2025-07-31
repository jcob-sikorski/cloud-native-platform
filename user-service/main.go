package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	// Keep strings import for potential future use, though not strictly needed for this change
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Address represents a user's address details
type Address struct {
	Street  string `json:"street"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zipCode"`
	Country string `json:"country"`
}

// User represents a user model for the e-commerce platform
type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username" binding:"required"`
	Email        string   `json:"email" binding:"required,email"`
	PasswordHash string   `json:"passwordHash" binding:"required"` // Expect raw password in JSON
	FirstName    string   `json:"firstName,omitempty"`
	LastName     string   `json:"lastName,omitempty"`
	Address      *Address `json:"address,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// UserResponse is a simplified struct for API responses
type UserResponse struct {
	ID        string   `json:"id"`
	Username  string   `json:"username"`
	Email     string   `json:"email"`
	FirstName string   `json:"firstName,omitempty"`
	LastName  string   `json:"lastName,omitempty"`
	Address   *Address `json:"address,omitempty"`
	Roles     []string `json:"roles,omitempty"`
}

// Request types for channel communication
type getUsersRequest struct {
	response chan []UserResponse
}

type getUserByIDRequest struct {
	id       string
	response chan *UserResponse
}

type createUserRequest struct {
	user     User
	response chan struct {
		user *UserResponse
		err  error
	}
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

func main() {
	// Get database credentials
	dbUser, dbPassword, err := getDBCredentials()
	if err != nil {
		log.Fatalf("Failed to get database credentials: %v", err)
	}

	// Get other database connection parameters
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "postgres" // Default to service name in Docker Compose
	}

	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "5432" // Default PostgreSQL port
	}

	dbName := os.Getenv("POSTGRES_DB") // Changed from DB_NAME to POSTGRES_DB
	if dbName == "" {
		dbName = "user_service" // Default database name
	}

	// Construct database URL
	dbURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Successfully connected to database")

	// Create channels for communication with the user manager
	getUsersChan := make(chan getUsersRequest)
	getUserByIDChan := make(chan getUserByIDRequest)
	createUserChan := make(chan createUserRequest)

	// Start the user manager goroutine
	go userManager(db, getUsersChan, getUserByIDChan, createUserChan)

	router := gin.Default()

	// Define routes
	router.GET("/users", func(c *gin.Context) {
		respChan := make(chan []UserResponse)
		getUsersChan <- getUsersRequest{response: respChan}
		users := <-respChan
		c.JSON(http.StatusOK, users)
	})

	router.GET("/users/:id", func(c *gin.Context) {
		respChan := make(chan *UserResponse)
		getUserByIDChan <- getUserByIDRequest{id: c.Param("id"), response: respChan}
		user := <-respChan
		if user == nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
			return
		}
		c.JSON(http.StatusOK, user)
	})

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

		// Hash the password using bcrypt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.PasswordHash), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		newUser.PasswordHash = string(hashedPassword)

		// Send the user creation request to the userManager
		respChan := make(chan struct {
			user *UserResponse
			err  error
		})
		createUserChan <- createUserRequest{user: newUser, response: respChan}
		resp := <-respChan
		if resp.err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": resp.err.Error()})
			return
		}
		c.JSON(http.StatusCreated, resp.user)
	})

	// Run the server
	port := "8080"
	log.Printf("User Service starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

// userManager handles all database operations in a single goroutine
func userManager(db *sql.DB, getUsersChan <-chan getUsersRequest, getUserByIDChan <-chan getUserByIDRequest, createUserChan <-chan createUserRequest) {
	for {
		select {
		case req := <-getUsersChan:
			go func(req getUsersRequest) {
				rows, err := db.Query(`
					SELECT id, username, email, first_name, last_name,
						   address_street, address_city, address_state, address_zip_code, address_country, roles
					FROM users`)
				if err != nil {
					log.Printf("Error querying users: %v", err)
					req.response <- nil
					return
				}
				defer rows.Close()

				var userResponses []UserResponse
				for rows.Next() {
					var u User
					var street, city, state, zipCode, country sql.NullString
					var dbRoles pq.StringArray

					if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
						&street, &city, &state, &zipCode, &country, &dbRoles); err != nil {
						log.Printf("Error scanning user: %v", err)
						continue
					}
					u.Roles = []string(dbRoles)

					if street.Valid || city.Valid || state.Valid || zipCode.Valid || country.Valid {
						u.Address = &Address{
							Street:  street.String,
							City:    city.String,
							State:   state.String,
							ZipCode: zipCode.String,
							Country: country.String,
						}
					}
					userResponses = append(userResponses, convertToUserResponse(u))
				}
				req.response <- userResponses
			}(req)

		case req := <-getUserByIDChan:
			go func(req getUserByIDRequest) {
				var u User
				var street, city, state, zipCode, country sql.NullString
				var dbRoles pq.StringArray

				err := db.QueryRow(`
					SELECT id, username, email, first_name, last_name,
						   address_street, address_city, address_state, address_zip_code, address_country, roles
					FROM users WHERE id = $1`, req.id).
					Scan(&u.ID, &u.Username, &u.Email, &u.FirstName, &u.LastName,
						&street, &city, &state, &zipCode, &country, &dbRoles)
				if err == sql.ErrNoRows {
					req.response <- nil
					return
				}
				if err != nil {
					log.Printf("Error querying user by ID: %v", err)
					req.response <- nil
					return
				}
				u.Roles = []string(dbRoles)

				if street.Valid || city.Valid || state.Valid || zipCode.Valid || country.Valid {
					u.Address = &Address{
						Street:  street.String,
						City:    city.String,
						State:   state.String,
						ZipCode: zipCode.String,
						Country: country.String,
					}
				}
				userResp := convertToUserResponse(u)
				req.response <- &userResp
			}(req)

		case req := <-createUserChan:
			go func(req createUserRequest) {
				if req.user.Username == "" || req.user.Email == "" {
					req.response <- struct {
						user *UserResponse
						err  error
					}{nil, errors.New("username and email are required")}
					return
				}

				newUser := req.user
				newUser.ID = uuid.New().String()

				var street, city, state, zipCode, country string
				if newUser.Address != nil {
					street = newUser.Address.Street
					city = newUser.Address.City
					state = newUser.Address.State
					zipCode = newUser.Address.ZipCode
					country = newUser.Address.Country
				}

				_, err := db.Exec(`
					INSERT INTO users (id, username, email, password_hash, first_name, last_name,
									  address_street, address_city, address_state, address_zip_code, address_country, roles)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
					newUser.ID, newUser.Username, newUser.Email, newUser.PasswordHash,
					newUser.FirstName, newUser.LastName, street, city, state, zipCode, country, pq.Array(newUser.Roles))
				if err != nil {
					log.Printf("Error creating user: %v", err)
					req.response <- struct {
						user *UserResponse
						err  error
					}{nil, err}
					return
				}

				userResp := convertToUserResponse(newUser)
				req.response <- struct {
					user *UserResponse
					err  error
				}{user: &userResp, err: nil}
			}(req)
		}
	}
}

// convertToUserResponse converts a User to UserResponse, omitting sensitive fields
func convertToUserResponse(user User) UserResponse {
	return UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Address:   user.Address,
		Roles:     user.Roles,
	}
}
