package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Address represents a user's address details
type Address struct {
	Street  string `json:"street"`
	City    string `json:"city"`
	State   string `json:"state"`
	ZipCode string `json:"zipCode"`
	Country string `json:"country"`
}

// User represents a more detailed user model for an e-commerce platform
type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username" binding:"required"`
	Email        string   `json:"email" binding:"required,email"`
	PasswordHash string   `json:"-"` // Prevent marshaling/unmarshaling
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

// In-memory "database"
var users = []User{
	{
		ID:           "1",
		Username:     "john.doe",
		Email:        "john.doe@example.com",
		PasswordHash: "hashedpassword1",
		FirstName:    "John",
		LastName:     "Doe",
		Address: &Address{
			Street:  "123 Main St",
			City:    "Anytown",
			State:   "Anystate",
			ZipCode: "12345",
			Country: "USA",
		},
		Roles: []string{"customer"},
	},
	{
		ID:           "2",
		Username:     "jane.smith",
		Email:        "jane.smith@example.com",
		PasswordHash: "hashedpassword2",
		FirstName:    "Jane",
		LastName:     "Smith",
		Address: &Address{
			Street:  "456 Oak Ave",
			City:    "Otherville",
			State:   "Otherstate",
			ZipCode: "67890",
			Country: "USA",
		},
		Roles: []string{"customer", "admin"},
	},
}

func main() {
	// Create channels for communication with the user manager goroutine
	getUsersChan := make(chan getUsersRequest)
	getUserByIDChan := make(chan getUserByIDRequest)
	createUserChan := make(chan createUserRequest)

	// Start the user manager goroutine
	go userManager(getUsersChan, getUserByIDChan, createUserChan)

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

// userManager handles all operations on the users slice in a single goroutine
func userManager(getUsersChan <-chan getUsersRequest, getUserByIDChan <-chan getUserByIDRequest, createUserChan <-chan createUserRequest) {
	for {
		select {
		case req := <-getUsersChan:
			var userResponses []UserResponse
			for _, user := range users {
				userResponses = append(userResponses, convertToUserResponse(user))
			}
			req.response <- userResponses

		case req := <-getUserByIDChan:
			var found bool
			for _, user := range users {
				if user.ID == req.id {
					userResp := convertToUserResponse(user)
					req.response <- &userResp
					found = true
					break
				}
			}
			if !found {
				req.response <- nil // User not found
			}

		case req := <-createUserChan:
			// Validate user (additional validation could be added here)
			if req.user.Username == "" || req.user.Email == "" {
				req.response <- struct {
					user *UserResponse
					err  error
				}{nil, errors.New("username and email are required")}
				continue
			}

			// Generate unique ID
			newUser := req.user
			newUser.ID = fmt.Sprintf("user-%d", len(users)+1)
			users = append(users, newUser)
			userResp := convertToUserResponse(newUser)
			req.response <- struct {
				user *UserResponse
				err  error
			}{user: &userResp, err: nil}
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
