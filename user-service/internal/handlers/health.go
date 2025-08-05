package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jcob-sikorski/cloud-native-platform/pkg/utils"
)

// HealthHandler handles health check requests.
type HealthHandler struct{}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// HealthCheck responds with a simple health status.
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	utils.SendSuccessResponse(c, http.StatusOK, "Service is healthy", nil)
}
