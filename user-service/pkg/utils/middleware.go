package utils

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Create a simple in-memory map for rate limiting
var requestCounts = make(map[string]int)
var lastRequestTimes = make(map[string]time.Time)
var RateLimitInterval = time.Minute // Exported
var RateLimitMaxRequests = 5        // Exported

// RateLimitMiddleware protects an endpoint from abuse
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		currentTime := time.Now()

		// Reset the counter if the interval has passed
		if currentTime.Sub(lastRequestTimes[clientIP]) > RateLimitInterval {
			requestCounts[clientIP] = 0
			lastRequestTimes[clientIP] = currentTime
		}

		// Increment the counter and check if it's over the limit
		requestCounts[clientIP]++
		if requestCounts[clientIP] > RateLimitMaxRequests {
			// Use SendErrorResponse for consistent error formatting
			SendErrorResponse(c, http.StatusTooManyRequests, "Too many requests. Please try again later.")
			c.Abort() // Abort the request after sending the error
			return
		}

		c.Next()
	}
}
