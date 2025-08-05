package utils

import (
	"github.com/gin-gonic/gin"
)

// JSONResponse represents a standard JSON response format.
type JSONResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// SendSuccessResponse sends a successful JSON response using gin.Context.
func SendSuccessResponse(c *gin.Context, statusCode int, message string, data interface{}) {
	c.JSON(statusCode, JSONResponse{
		Status:  "success",
		Message: message,
		Data:    data,
	})
}

// SendErrorResponse sends an error JSON response using gin.Context.
func SendErrorResponse(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, JSONResponse{
		Status:  "error",
		Message: message,
		Error:   message, // For simplicity, error message is same as general message
	})
}
