package handlers

import (
	"github.com/gin-gonic/gin"
)

// This file can be used for general HTTP handler-level middleware.
// For example, request logging, common header setting, or other cross-cutting concerns
// that are specific to the handlers package, rather than authentication or utility functions.

// Example of a simple logging middleware (optional, for demonstration)
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Log the request before processing
		// logrus.Infof("Incoming request: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next() // Process the request
		// Log the response after processing
		// logrus.Infof("Outgoing response: %s %s, Status: %d", c.Request.Method, c.Request.URL.Path, c.Writer.Status())
	}
}

// Example of a custom header setting middleware (optional, for demonstration)
func SetCustomHeaderMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Service-Name", "User-Service-Structured")
		c.Next()
	}
}

// Note: Specific middlewares like JWT authentication and rate limiting
// are located in:
// - `internal/auth/middleware.go`
// - `pkg/utils/middleware.go`
// respectively, for better separation of concerns.
