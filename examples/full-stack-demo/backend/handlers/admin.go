// Package handlers provides Gin HTTP handlers for the demo API.
package handlers

import (
	"net/http"

	"github.com/anthropics/hearth/sdks/go/hearth"
	"github.com/anthropics/hearth/examples/full-stack-demo/backend/middleware"
	"github.com/gin-gonic/gin"
)

// ListUsers calls the Hearth admin API and returns the paginated user list.
func ListUsers(client *hearth.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		admin := client.Admin(middleware.RawToken(c))
		page, err := admin.ListUsers(c.Request.Context(), 50)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, page)
	}
}
