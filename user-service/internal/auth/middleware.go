package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jcob-sikorski/cloud-native-platform/pkg/utils"
	"github.com/sirupsen/logrus" // Import logrus for debug logging
)

// JwtAuthMiddleware validates JWT tokens and sets user context
func JwtAuthMiddleware(secretKey []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Authorization header required")
			c.Abort()
			return
		}

		// Check for Bearer prefix
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Bearer token required")
			c.Abort()
			return
		}

		// Parse and validate token using the custom Claims struct
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(*Claims)
		if !ok {
			utils.SendErrorResponse(c, http.StatusUnauthorized, "Invalid token claims")
			c.Abort()
			return
		}

		// Set context values - FIXED: Use consistent key names
		c.Set("userID", claims.UserID)
		c.Set("roles", claims.Roles)     // Used by HasRole helper
		c.Set("userRoles", claims.Roles) // Used by RequireRole middleware

		// For backward compatibility, also set the primary role
		primaryRole := "user"
		if len(claims.Roles) > 0 {
			primaryRole = claims.Roles[0]
		}
		c.Set("role", primaryRole)

		c.Next()
	}
}

// hasRole is a helper function to check if the user has a specific role
func HasRole(c *gin.Context, requiredRole string) bool {
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

// RequireRole is a middleware to check for a specific role
func RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user roles from context (set by JwtAuthMiddleware)
		userRoles, exists := c.Get("userRoles") // This matches what we set above
		if !exists {
			logrus.Error("RequireRole: User roles not found in context")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User roles not found"})
			c.Abort()
			return
		}

		// Type assertion to []string
		roles, ok := userRoles.([]string)
		if !ok {
			logrus.Errorf("RequireRole: Invalid roles type: %T", userRoles)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user roles format"})
			c.Abort()
			return
		}

		// Check if user has the required role
		hasRole := false
		for _, role := range roles {
			if role == requiredRole {
				hasRole = true
				break
			}
		}

		if !hasRole {
			userID := c.GetString("userID")
			logrus.Warnf("RequireRole: User %s does not have required role '%s'. User roles: %v", userID, requiredRole, roles)
			c.JSON(http.StatusForbidden, gin.H{"error": "You do not have the required permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}
