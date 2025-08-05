package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings" // Added for strings.ToLower

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"github.com/jcob-sikorski/cloud-native-platform/internal/auth"
	"github.com/jcob-sikorski/cloud-native-platform/internal/config"
	"github.com/jcob-sikorski/cloud-native-platform/internal/database"
	"github.com/jcob-sikorski/cloud-native-platform/internal/handlers"
	"github.com/jcob-sikorski/cloud-native-platform/internal/repositories"
	"github.com/jcob-sikorski/cloud-native-platform/internal/services"
	"github.com/jcob-sikorski/cloud-native-platform/pkg/utils"
)

// This init function will be called automatically when the package is initialized.
// It's a good place for global setup like logger configuration.
func init() {
	// Set Logrus output to stdout (this is usually the default, but explicit is good)
	logrus.SetOutput(os.Stdout)

	// Set Logrus formatter for better readability (optional, but recommended)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true, // Add timestamps to logs
		// You can add more options here, like DisableColors: true for non-TTY environments
	})

	// Read log level from environment variable, default to Info if not set or invalid
	logLevelStr := os.Getenv("LOG_LEVEL")
	if logLevelStr == "" {
		logLevelStr = "info" // Default to info if not specified
	}

	logLevel, err := logrus.ParseLevel(strings.ToLower(logLevelStr))
	if err != nil {
		// If parsing fails, log a warning and default to Info
		logrus.Warnf("Invalid LOG_LEVEL environment variable '%s', defaulting to Info", logLevelStr)
		logLevel = logrus.InfoLevel
	}
	// Set the global logrus level
	logrus.SetLevel(logLevel)

	// A test debug log to confirm that debug logging is now enabled
	logrus.Debug("Logrus global logger initialized. Debug level enabled.")
}

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found, assuming environment variables are set.")
	}

	// Initialize configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database connection
	db, err := database.ConnectDB(cfg.Database)
	if err != nil {
		logrus.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize repositories
	userRepo := repositories.NewPostgresUserRepository(db)
	tokenRepo := repositories.NewPostgresRefreshTokenRepository(db)

	// Initialize services
	userService := services.NewUserService(userRepo)
	authService := services.NewAuthService(userRepo, tokenRepo, cfg.JWTSecret)

	// Initialize handlers
	healthHandler := handlers.NewHealthHandler()
	userHandler := handlers.NewUserHandler(userService)
	authHandler := handlers.NewAuthHandler(authService)

	// Set Gin to ReleaseMode in production
	if os.Getenv("GIN_MODE") == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Global Middleware
	router.Use(utils.RateLimitMiddleware()) // Apply rate limiting to all requests

	// Health check route
	router.GET("/health", healthHandler.HealthCheck)

	// Public routes (authentication)
	authRoutes := router.Group("/auth")
	{
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/refresh", authHandler.RefreshToken)
		authRoutes.POST("/logout", authHandler.Logout) // Requires refresh token in body
	}

	// Protected routes (require JWT authentication)
	protected := router.Group("/")
	protected.Use(auth.JwtAuthMiddleware(cfg.JWTSecret))
	{
		// User-specific routes (accessible to authenticated users)
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.GetString("userID")
			user, err := userService.GetUserByID(userID)
			if err != nil {
				utils.SendErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve user profile")
				return
			}
			utils.SendSuccessResponse(c, http.StatusOK, "User profile", user)
		})

		// User self-update route - must be OUTSIDE admin group
		// This allows users to update their own profiles
		protected.PUT("/users/:id", userHandler.UpdateUser)

		// Admin-only routes - separate group with admin middleware
		adminRoutes := protected.Group("/admin")
		adminRoutes.Use(auth.RequireRole("admin"))
		{
			adminRoutes.POST("/users", userHandler.CreateUser)       // POST /admin/users
			adminRoutes.GET("/users", userHandler.GetAllUsers)       // GET /admin/users
			adminRoutes.GET("/users/:id", userHandler.GetUserByID)   // GET /admin/users/:id
			adminRoutes.DELETE("/users/:id", userHandler.DeleteUser) // DELETE /admin/users/:id
			// Note: No PUT route here since it's handled above for self-updates
		}
	}

	logrus.Infof("Server starting on port %s", cfg.AppPort)
	log.Fatal(router.Run(fmt.Sprintf(":%s", cfg.AppPort)))
}
