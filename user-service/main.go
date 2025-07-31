package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// User represents a simplified user model
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// In-memory "database" for demonstration purposes
var users = []User{
	{ID: "1", Username: "john.doe", Email: "john.doe@example.com"},
	{ID: "2", Username: "jane.smith", Email: "jane.smith@example.com"},
}

func main() {
	// Set Gin to release mode for production, or comment out for debug mode
	// gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	// Define routes
	router.GET("/users", getUsers)
	router.GET("/users/:id", getUserByID)
	router.POST("/users", createUser)

	// Run the server on port 8080
	port := "8080"
	log.Printf("User Service starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

// getUsers handles GET requests to /users
func getUsers(c *gin.Context) {
	c.JSON(http.StatusOK, users)
}

// getUserByID handles GET requests to /users/:id
func getUserByID(c *gin.Context) {
	id := c.Param("id")
	for _, user := range users {
		if user.ID == id {
			c.JSON(http.StatusOK, user)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
}

// createUser handles POST requests to /users
func createUser(c *gin.Context) {
	var newUser User
	// Bind the incoming JSON to the newUser struct
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Simple validation (can be enhanced)
	if newUser.Username == "" || newUser.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Username and Email are required"})
		return
	}

	// Assign a new ID (in a real app, this would be handled by a database)
	newUser.ID = "new-" + newUser.Username // Placeholder for unique ID
	users = append(users, newUser)
	c.JSON(http.StatusCreated, newUser)
}
